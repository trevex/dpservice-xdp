use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_xdp_adjust_tail, bpf_xdp_load_bytes, bpf_xdp_store_bytes},
    programs::XdpContext,
};
use xdp_dp_common::PortMeta;

use crate::arp_nd::GW_MAC;
use crate::parse::{write16, write6, ETH_LEN, ETH_P_IP, ETH_P_IPV6, IPPROTO_UDP};

const DHCP_MAGIC: u32 = 0x6382_5363;
const OPT_PAD: u8 = 0;
const OPT_END: u8 = 255;
const OPT_MESSAGE_TYPE: u8 = 53;
const OPT_LEASE_TIME: u8 = 51;
const OPT_SERVER_ID: u8 = 54;
const OPT_CLASSLESS_ROUTE: u8 = 121;
const OPT_SUBNET_MASK: u8 = 1;
const OPT_DNS: u8 = 6;
const OPT_HOSTNAME: u8 = 12;
const OPT_MTU: u8 = 26;
const DHCP_MSG_DISCOVER: u8 = 1;
const DHCP_MSG_REQUEST: u8 = 3;
const DHCP_MSG_OFFER: u8 = 2;
const DHCP_MSG_ACK: u8 = 5;

const F_BOOTP: usize = ETH_LEN + 20 + 8;
const BOOTP_MAGIC_OFF: usize = 236;
const BOOTP_OPTIONS_OFF: usize = 240;
const F_OPTS: usize = F_BOOTP + BOOTP_OPTIONS_OFF;
const MIN_DHCP_LEN: usize = F_OPTS;

// Byte-by-byte scan: scan at most this many bytes (fixed stride of 1, verifier-safe)
const OPTS_SCAN_BYTES: usize = 128;

const O_MSGTYPE: usize = 0;
const O_LEASE: usize = 3;
const O_SERVERID: usize = 9;
const O_CLASSLESS: usize = 15;
const O_SUBNET: usize = 29;
const O_MTU: usize = 35;
const O_ROUTER: usize = 39;
const O_DNS: usize = 45;
const O_HOSTNAME: usize = 79;
const OPT_BLOCK_MAX: usize = 146;
const REPLY_LEN: usize = F_OPTS + OPT_BLOCK_MAX;

/// In-datapath DHCPv4 responder.
///
/// Uses a byte-by-byte state machine (i always += 1) to parse options.
/// This gives the BPF verifier a simple fixed-stride loop it can analyze correctly.
#[inline(always)]
pub fn try_dhcpv4_reply(ctx: &XdpContext, meta: &PortMeta) -> Option<u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + MIN_DHCP_LEN > data_end {
        return None;
    }
    let p = data as *const u8;

    let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(12) as *const u16) });
    if ethertype != ETH_P_IP {
        return None;
    }
    if unsafe { *p.add(ETH_LEN) } & 0x0f != 5 {
        return None;
    }
    if unsafe { *p.add(ETH_LEN + 9) } != IPPROTO_UDP {
        return None;
    }
    let udp_dst =
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 22) as *const u16) });
    if udp_dst != 67 {
        return None;
    }
    let magic = u32::from_be(unsafe {
        core::ptr::read_unaligned(p.add(F_BOOTP + BOOTP_MAGIC_OFF) as *const u32)
    });
    if magic != DHCP_MAGIC {
        return None;
    }

    // Byte-by-byte option state machine.
    // sm_state: 0 = expect code, 1 = expect length, 2 = reading value bytes (counting down sm_remain)
    // i always increments by 1 (fixed stride = verifier-friendly loop).
    let mut msg_type: u8 = 0;
    let mut sm_state: u8 = 0;
    let mut _sm_code: u8 = 0;
    let mut sm_remain: usize = 0;
    let mut sm_is_msgtype: bool = false;

    let mut i: usize = 0;
    while i < OPTS_SCAN_BYTES {
        let boff = data + F_OPTS + i;
        if boff >= data_end {
            break;
        }
        let b = unsafe { *(boff as *const u8) };
        i += 1;

        if sm_state == 0 {
            // Expecting option code
            if b == OPT_PAD {
                // no-op
            } else if b == OPT_END {
                break;
            } else {
                _sm_code = b;
                sm_is_msgtype = b == OPT_MESSAGE_TYPE;
                sm_state = 1;
            }
        } else if sm_state == 1 {
            // Expecting option length
            sm_remain = b as usize;
            if sm_remain == 0 {
                sm_state = 0;
            } else {
                sm_state = 2;
            }
        } else {
            // sm_state == 2: reading value bytes. MESSAGE_TYPE always has len=1, so the single
            // value byte (sm_remain==1, before the decrement below) is the message type.
            if sm_is_msgtype && sm_remain == 1 {
                msg_type = b;
            }
            sm_remain -= 1;
            if sm_remain == 0 {
                sm_state = 0;
            }
        }
    }

    if msg_type != DHCP_MSG_DISCOVER && msg_type != DHCP_MSG_REQUEST {
        return None;
    }
    let reply_type = if msg_type == DHCP_MSG_DISCOVER {
        DHCP_MSG_OFFER
    } else {
        DHCP_MSG_ACK
    };

    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    // MAC learning: use the Ethernet source (bytes 6-11), not BOOTP chaddr.
    // The test suite sends REQUEST with a different Ethernet src than chaddr to verify
    // that the datapath learns the actual L2 source address used by the VM.
    let eth_src = unsafe { core::ptr::read_unaligned(p.add(6) as *const [u8; 6]) };
    if eth_src != meta.guest_mac {
        let mut updated = *meta;
        updated.guest_mac = eth_src;
        let _ = crate::maps::PORT_META.insert(&ifindex, &updated, 0);
        // Also update UNDERLAY (keyed by underlay IPv6) and INTERFACES (keyed by vni+ipv4)
        // so the local fast path and ingress delivery use the new MAC immediately.
        if let Some(u) = unsafe { crate::maps::UNDERLAY.get(&meta.underlay_ipv6) } {
            let mut u2 = *u;
            u2.guest_mac = eth_src;
            let _ = crate::maps::UNDERLAY.insert(&meta.underlay_ipv6, &u2, 0);
        }
        let ikey = xdp_dp_common::IfaceKey::new(meta.vni, meta.guest_ipv4);
        if let Some(iv) = unsafe { crate::maps::INTERFACES.get(&ikey) } {
            let mut iv2 = *iv;
            iv2.guest_mac = eth_src;
            let _ = crate::maps::INTERFACES.insert(&ikey, &iv2, 0);
        }
    }

    let dhcp_cfg = crate::maps::DHCP_CONFIG.get(0);
    let dhcp_meta = unsafe { crate::maps::DHCP_META.get(&ifindex) };

    let cur_len = data_end - data;
    if cur_len != REPLY_LEN {
        let delta: i32 = REPLY_LEN as i32 - cur_len as i32;
        if unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) } != 0 {
            return None;
        }
    }
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + REPLY_LEN > data_end {
        return None;
    }
    let p = data as *mut u8;

    // BOOTP header. Mirror dpservice's dhcp_node.c byte-for-byte: op=BOOTREPLY(2), yiaddr=assigned
    // IP, siaddr+giaddr=the virtual gateway (server identity), chaddr=the client's L2 address (the
    // original Ethernet source, still intact here — adjust_tail preserves the existing bytes and the
    // Ethernet header is not rewritten until below). sname/file/options (from +44) are zeroed.
    let client_mac = unsafe { core::ptr::read_unaligned(p.add(6) as *const [u8; 6]) };
    let gw4 = meta.gateway_ipv4;
    unsafe {
        *p.add(F_BOOTP) = 2;
        core::ptr::write_unaligned(p.add(F_BOOTP + 16) as *mut [u8; 4], meta.guest_ipv4); // yiaddr
        core::ptr::write_unaligned(p.add(F_BOOTP + 20) as *mut [u8; 4], gw4); // siaddr
        core::ptr::write_unaligned(p.add(F_BOOTP + 24) as *mut [u8; 4], gw4); // giaddr
        write6(p.add(F_BOOTP + 28), &client_mac); // chaddr
        core::ptr::write_bytes(p.add(F_BOOTP + 44), 0, 192);
    }

    let gw = meta.gateway_ipv4;
    unsafe {
        *p.add(F_OPTS + O_MSGTYPE) = OPT_MESSAGE_TYPE;
        *p.add(F_OPTS + O_MSGTYPE + 1) = 1;
        *p.add(F_OPTS + O_MSGTYPE + 2) = reply_type;
        *p.add(F_OPTS + O_LEASE) = OPT_LEASE_TIME;
        *p.add(F_OPTS + O_LEASE + 1) = 4;
        *p.add(F_OPTS + O_LEASE + 2) = 0xff;
        *p.add(F_OPTS + O_LEASE + 3) = 0xff;
        *p.add(F_OPTS + O_LEASE + 4) = 0xff;
        *p.add(F_OPTS + O_LEASE + 5) = 0xff;
        *p.add(F_OPTS + O_SERVERID) = OPT_SERVER_ID;
        *p.add(F_OPTS + O_SERVERID + 1) = 4;
        *p.add(F_OPTS + O_SERVERID + 2) = gw[0];
        *p.add(F_OPTS + O_SERVERID + 3) = gw[1];
        *p.add(F_OPTS + O_SERVERID + 4) = gw[2];
        *p.add(F_OPTS + O_SERVERID + 5) = gw[3];
        *p.add(F_OPTS + O_CLASSLESS) = OPT_CLASSLESS_ROUTE;
        *p.add(F_OPTS + O_CLASSLESS + 1) = 12;
        *p.add(F_OPTS + O_CLASSLESS + 2) = 16;
        *p.add(F_OPTS + O_CLASSLESS + 3) = 169;
        *p.add(F_OPTS + O_CLASSLESS + 4) = 254;
        *p.add(F_OPTS + O_CLASSLESS + 5) = 0;
        *p.add(F_OPTS + O_CLASSLESS + 6) = 0;
        *p.add(F_OPTS + O_CLASSLESS + 7) = 0;
        *p.add(F_OPTS + O_CLASSLESS + 8) = 0;
        *p.add(F_OPTS + O_CLASSLESS + 9) = 0;
        *p.add(F_OPTS + O_CLASSLESS + 10) = gw[0];
        *p.add(F_OPTS + O_CLASSLESS + 11) = gw[1];
        *p.add(F_OPTS + O_CLASSLESS + 12) = gw[2];
        *p.add(F_OPTS + O_CLASSLESS + 13) = gw[3];
        *p.add(F_OPTS + O_SUBNET) = OPT_SUBNET_MASK;
        *p.add(F_OPTS + O_SUBNET + 1) = 4;
        *p.add(F_OPTS + O_SUBNET + 2) = 0xff;
        *p.add(F_OPTS + O_SUBNET + 3) = 0xff;
        *p.add(F_OPTS + O_SUBNET + 4) = 0xff;
        *p.add(F_OPTS + O_SUBNET + 5) = 0xff;
    }

    let mtu: u16 = if let Some(cfg) = dhcp_cfg {
        cfg.mtu
    } else {
        1500
    };
    unsafe {
        *p.add(F_OPTS + O_MTU) = OPT_MTU;
        *p.add(F_OPTS + O_MTU + 1) = 2;
        core::ptr::write_unaligned(p.add(F_OPTS + O_MTU + 2) as *mut u16, mtu.to_be());
        // dpservice emits the ROUTER(3) option only in PXE setups; the v4 path here has no PXE
        // support (unlike the v6 path), so this slot is intentionally left as PAD. Reserved for a
        // future v4-PXE branch.
        core::ptr::write_bytes(p.add(F_OPTS + O_ROUTER), OPT_PAD, 6);
    }

    unsafe {
        core::ptr::write_bytes(p.add(F_OPTS + O_DNS), OPT_PAD, 34);
    }
    if let Some(cfg) = dhcp_cfg {
        let dns_len = (cfg.dns4_len as usize).min(xdp_dp_common::DHCP_MAX_DNS);
        if dns_len > 0 {
            unsafe {
                *p.add(F_OPTS + O_DNS) = OPT_DNS;
                *p.add(F_OPTS + O_DNS + 1) = (dns_len * 4) as u8;
            }
            let mut j = 0usize;
            while j < dns_len {
                let off = F_OPTS + O_DNS + 2 + j * 4;
                unsafe {
                    *p.add(off) = cfg.dns4[j][0];
                    *p.add(off + 1) = cfg.dns4[j][1];
                    *p.add(off + 2) = cfg.dns4[j][2];
                    *p.add(off + 3) = cfg.dns4[j][3];
                }
                j += 1;
            }
        }
    }

    unsafe {
        core::ptr::write_bytes(p.add(F_OPTS + O_HOSTNAME), OPT_PAD, 66);
    }
    if let Some(dm) = dhcp_meta {
        let hn_len = (dm.hostname_len as usize).min(64);
        if hn_len > 0 {
            unsafe {
                *p.add(F_OPTS + O_HOSTNAME) = OPT_HOSTNAME;
                *p.add(F_OPTS + O_HOSTNAME + 1) = hn_len as u8;
            }
            let mut k = 0usize;
            while k < hn_len {
                unsafe {
                    *p.add(F_OPTS + O_HOSTNAME + 2 + k) = dm.hostname[k];
                }
                k += 1;
            }
        }
    }
    unsafe {
        *p.add(F_OPTS + OPT_BLOCK_MAX - 1) = OPT_END;
    }

    // Ethernet: dst = requester, src = the virtual gateway MAC. dpservice uses the port's own_mac
    // here; this reimplementation deliberately uses the single synthetic GW_MAC that the ARP/ND
    // responders also advertise, so the guest's neighbor table for the gateway stays coherent.
    let req_eth_src = unsafe { core::ptr::read_unaligned(p.add(6) as *const [u8; 6]) };
    unsafe {
        write6(p, &req_eth_src);
        write6(p.add(6), &GW_MAC);
    }

    let ip_total = (REPLY_LEN - ETH_LEN) as u16;
    let vihl = unsafe { *p.add(ETH_LEN) };
    let tos = unsafe { *p.add(ETH_LEN + 1) };
    let ip_hdr: [u8; 20] = [
        vihl,
        tos,
        (ip_total >> 8) as u8,
        (ip_total & 0xff) as u8,
        0,
        0,
        0,
        0,
        64,
        IPPROTO_UDP,
        0,
        0,
        meta.gateway_ipv4[0],
        meta.gateway_ipv4[1],
        meta.gateway_ipv4[2],
        meta.gateway_ipv4[3],
        255,
        255,
        255,
        255,
    ];
    let mut s: u32 = 0;
    s = s.wrapping_add(((ip_hdr[0] as u32) << 8) | ip_hdr[1] as u32);
    s = s.wrapping_add(((ip_hdr[2] as u32) << 8) | ip_hdr[3] as u32);
    s = s.wrapping_add(((ip_hdr[4] as u32) << 8) | ip_hdr[5] as u32);
    s = s.wrapping_add(((ip_hdr[6] as u32) << 8) | ip_hdr[7] as u32);
    s = s.wrapping_add(((ip_hdr[8] as u32) << 8) | ip_hdr[9] as u32);
    s = s.wrapping_add(((ip_hdr[12] as u32) << 8) | ip_hdr[13] as u32);
    s = s.wrapping_add(((ip_hdr[14] as u32) << 8) | ip_hdr[15] as u32);
    s = s.wrapping_add(((ip_hdr[16] as u32) << 8) | ip_hdr[17] as u32);
    s = s.wrapping_add(((ip_hdr[18] as u32) << 8) | ip_hdr[19] as u32);
    s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    let ip_csum = !(s as u16);
    unsafe {
        core::ptr::copy_nonoverlapping(ip_hdr.as_ptr(), p.add(ETH_LEN), 20);
        core::ptr::write_unaligned(p.add(ETH_LEN + 10) as *mut u16, ip_csum.to_be());
    }

    let udp_len = (REPLY_LEN - ETH_LEN - 20) as u16;
    unsafe {
        core::ptr::write_unaligned(p.add(ETH_LEN + 20) as *mut u16, 67u16.to_be());
        core::ptr::write_unaligned(p.add(ETH_LEN + 22) as *mut u16, 68u16.to_be());
        core::ptr::write_unaligned(p.add(ETH_LEN + 24) as *mut u16, udp_len.to_be());
        core::ptr::write_unaligned(p.add(ETH_LEN + 26) as *mut u16, 0u16);
    }

    Some(xdp_action::XDP_TX)
}

// ──────────────────────── DHCPv6 responder ────────────────────────

// DHCPv6 message types (RFC 8415)
const D6_SOLICIT: u8 = 1;
const D6_ADVERTISE: u8 = 2;
const D6_REQUEST: u8 = 3;
const D6_CONFIRM: u8 = 4;
const D6_REPLY: u8 = 7;

// DHCPv6 option codes
const D6_OPT_CLIENTID: u16 = 1;
const D6_OPT_SERVERID: u16 = 2;
const D6_OPT_IA_NA: u16 = 3;
const D6_OPT_IAADDR: u16 = 5;
const D6_OPT_STATUS_CODE: u16 = 13;
const D6_OPT_RAPID_COMMIT: u16 = 14;
const D6_OPT_USER_CLASS: u16 = 15;
const D6_OPT_VENDOR_CLASS: u16 = 16;
const D6_OPT_DNS: u16 = 23;
const D6_OPT_BOOT_FILE: u16 = 59;

// DUID type for server DUID-LL (DP_DHCPV6_HW_ID = 0xabcd)
const DUID_LL_TYPE: u16 = 3;
const DP_DHCPV6_HW_ID: u16 = 0xabcd;

// DHCPv6 packet starts at ETH+IPv6+UDP = 14+40+8 = 62
const F6_DHCP: usize = ETH_LEN + 40 + 8;
// Options start 4 bytes in (msg_type(1)+tid(3))
const F6_OPTS: usize = F6_DHCP + 4;
// Minimum packet we need to peek at: ETH + IPv6 + UDP + DHCPv6 header
const MIN_D6_LEN: usize = F6_OPTS;

// Vendor class enterprise number for PXE (343)
const PXE_ENTERPRISE: u32 = 343;

// PXE mode discriminator
const PXE_NONE: u8 = 0;
const PXE_TFTP: u8 = 1;
const PXE_HTTP: u8 = 2;

// TFTP path constant (mirrors dpservice DP_PXE_TFTP_PATH)
const TFTP_PATH: &[u8] = b"ipxe/x86_64/ipxe.new";

// Maximum DNS entries to include
const D6_MAX_DNS: usize = xdp_dp_common::DHCP_MAX_DNS; // 8 entries

// Cap DUID to 10 bytes: minimum for DUID-LL with MAC (type(2)+hwtype(2)+mac(6)=10)
const D6_MAX_DUID: usize = 10;

// Maximum boot file URL length: scheme(7) + "[" + host(46) + "]/" + path(64) = 120
const D6_MAX_URL: usize = 120;

// Maximum DHCPv6 options total size
const D6_MAX_OPTS: usize = 14 // ServerId: op(2)+len(2)+DUID_LL(10)=14
    + (4 + D6_MAX_DUID) // ClientId: op(2)+len(2)+duid_cap(10)=14
    + 4  // RapidCommit: op(2)+len(2)=4
    + 50 // IA_NA full with nested IAADDR+STATUS_CODE
    + (4 + D6_MAX_DNS * 16) // DNS: 4+128=132
    + (4 + D6_MAX_URL); // BootFileUrl: 4+120=124

/// Compute the URL length for PXE without building it in a buffer.
/// Returns 0 if PXE is not configured.
#[inline(always)]
fn d6_url_len(pxe_mode: u8, dm: &xdp_dp_common::DhcpMeta) -> usize {
    if pxe_mode == PXE_NONE {
        return 0;
    }
    let host_len = dm.pxe_host_len as usize;
    if host_len == 0 || host_len > 46 {
        return 0;
    }
    let path_len = if pxe_mode == PXE_TFTP {
        TFTP_PATH.len()
    } else {
        dm.boot_filename_len as usize
    };
    // scheme(7) + "[" + host + "]/" + path
    7 + 1 + host_len + 2 + path_len
}

/// Copy `len` bytes from `buf` into the packet at byte `offset` via bpf_xdp_store_bytes.
///
/// The helper performs its own bounds check against the (post-adjust_tail) packet length,
/// so `offset`/`len` may be runtime values — this is what lets us emit DHCPv6 options at a
/// running `off` offset without the verifier rejecting variable-offset direct packet writes.
#[inline(always)]
unsafe fn store(ctx: &XdpContext, offset: usize, buf: *const u8, len: usize) -> bool {
    bpf_xdp_store_bytes(
        ctx.ctx,
        offset as u32,
        buf as *mut core::ffi::c_void,
        len as u32,
    ) == 0
}

/// Emit the PXE boot file URL into the packet starting at byte `base`, one small piece at a
/// time via bpf_xdp_store_bytes. Returns the number of bytes written (0 on bad host length).
///
/// Pieces (scheme / "[" / host / "]/" / path) are stored separately so no large URL staging
/// buffer is needed on the stack; the constant pieces come straight from `.rodata` and the
/// helper bounds-checks each store against the packet.
#[inline(always)]
unsafe fn d6_store_url(
    ctx: &XdpContext,
    base: usize,
    pxe_mode: u8,
    dm: &xdp_dp_common::DhcpMeta,
) -> usize {
    let host_len = dm.pxe_host_len as usize;
    if host_len == 0 || host_len > 46 {
        return 0;
    }
    // scheme (7 bytes) from .rodata
    let scheme_ptr = if pxe_mode == PXE_TFTP {
        TFTP_SCHEME.as_ptr()
    } else {
        HTTP_SCHEME.as_ptr()
    };
    let mut up = 0usize;
    store(ctx, base + up, scheme_ptr, 7);
    up += 7;
    // "["
    store(ctx, base + up, URL_LBRACKET.as_ptr(), 1);
    up += 1;
    // host (from map memory)
    store(ctx, base + up, dm.pxe_host.as_ptr(), host_len);
    up += host_len;
    // "]/"
    store(ctx, base + up, URL_RBRACKET.as_ptr(), 2);
    up += 2;
    // path
    if pxe_mode == PXE_TFTP {
        let path_len = TFTP_PATH.len();
        store(ctx, base + up, TFTP_PATH.as_ptr(), path_len);
        up += path_len;
    } else {
        let file_len = (dm.boot_filename_len as usize).min(64);
        // store_bytes rejects a zero length ("invalid zero-sized read"), so only emit a path
        // when there actually is a boot filename. An empty path (http://[host]/) is valid.
        if file_len > 0 {
            store(ctx, base + up, dm.boot_filename.as_ptr(), file_len);
            up += file_len;
        }
    }
    up
}

// Scan window for the option parser: copied from the packet into a stack buffer so the parse
// loop iterates a fixed-size array (no per-iteration packet-bound branch, which is what made the
// inlined parser explode the verifier's state count). 192 bytes covers any realistic SOLICIT.
const D6_SCAN: usize = 128;

const D6_MAX_TOTAL: usize = F6_OPTS + D6_MAX_OPTS;

/// Parsed request fields plus the values `try_dhcpv6_reply` computes before emitting the reply.
/// Passed by reference across the BPF-to-BPF call boundary so parse / emit verify independently.
#[derive(Clone, Copy)]
struct D6Reply {
    // Filled by `d6_parse`:
    got_clientid: bool,
    duid: [u8; D6_MAX_DUID],
    duid_len: u16,
    got_iana: bool,
    iaid: u32,
    rapid_commit: bool,
    pxe_mode: u8,
    // Filled by `try_dhcpv6_reply`:
    reply_type: u8,
    tid: [u8; 3],
    dns6_count: u16,
    url_len: u16,
    real_reply_len: u16,
    req_src6: [u8; 16],
    req_eth_src: [u8; 6],
}

/// Parse DHCPv6 options into `r` (out-param). Marked `#[inline(never)]` so it compiles to a
/// separate BPF subprogram: its loop state is verified once, instead of being multiplied by the
/// emit path's branch combinations (which is what inlining everything into one function did).
///
/// The packet has ALREADY been tail-grown to D6_MAX_TOTAL (>= F6_OPTS + D6_SCAN) by the caller, so
/// a single constant-size bounds check lets every option read below use a constant offset — no
/// per-iteration `ptr >= data_end` branch, and no stack scratch buffer (the memset of which got
/// `mark_precise`-walked once per loop state and exploded the verifier's instruction count).
/// `n` is the real option-byte count (original packet length) so we stop before the zero/garbage
/// tail the grow added.
///
/// Returns the parsed `pxe_mode` as a scalar. A BPF subprogram may not leave a stack pointer in
/// R0 at return, and LLVM otherwise leaves `&r.duid[i]` (from the loop) there. Returning a runtime
/// scalar that the caller actually stores forces R0 to a scalar at the exit and isn't DCE'd (a
/// constant `0` return was — the caller discarded it, so R0 was never materialised).
///
/// Reads go through bpf_xdp_load_bytes rather than direct packet access: a variable option offset
/// added to a packet pointer resets the verifier's range to 0, and LLVM reassociates/decomposes
/// multi-byte loads so per-read `ptr + size <= data_end` checks don't stick. load_bytes does its
/// own in-kernel bounds check on a runtime (offset, len), sidestepping all of that. The option-skip
/// loop keeps the call count tiny (~one per option) and the staging buffers are only a few bytes,
/// so neither the loads nor a scratch-buffer memset blow up the verifier's state count.
#[inline(never)]
fn d6_parse(ctx: &XdpContext, r: &mut D6Reply, n: usize) -> u32 {
    let mut i: usize = 0;
    let mut guard: u32 = 0;
    // A DHCPv6 SOLICIT/REQUEST carries well under a dozen options; cap the loop tightly so the
    // verifier explores few symbolic iterations (each option-skip iteration with its load_bytes
    // calls is expensive, and a loose cap pushed total instructions over the 1M limit).
    while i + 4 <= n && i + 4 <= D6_SCAN && guard < 12 {
        guard += 1;
        // Option header: code(2) + len(2).
        let mut hb = [0u8; 4];
        if unsafe {
            bpf_xdp_load_bytes(
                ctx.ctx,
                (F6_OPTS + i) as u32,
                hb.as_mut_ptr() as *mut core::ffi::c_void,
                4,
            )
        } != 0
        {
            break;
        }
        let code = ((hb[0] as u16) << 8) | hb[1] as u16;
        // Clamp the option length to the scan window: it advances `i`, and an unclamped 0..65535
        // from the packet made the verifier track `i = v + olen` with an exploding range (the
        // option-skip loop's instruction count blew past 1M). Valid options are far smaller than
        // the scan window, and the loop stops at `n` anyway, so the clamp is correctness-neutral.
        let olen = (((hb[2] as u16) << 8) | hb[3] as u16).min(D6_SCAN as u16);
        let v = i + 4; // value start

        match code {
            D6_OPT_RAPID_COMMIT => r.rapid_commit = true,
            D6_OPT_USER_CLASS => {
                // dpservice carries "iPXE" in a User Class option to request HTTP boot; treat the
                // option's presence as that signal (avoids a per-byte string matcher).
                if r.pxe_mode == PXE_NONE {
                    r.pxe_mode = PXE_HTTP;
                }
            }
            D6_OPT_IA_NA => {
                // IAID = first 4 value bytes (big-endian).
                let mut vb = [0u8; 4];
                if unsafe {
                    bpf_xdp_load_bytes(
                        ctx.ctx,
                        (F6_OPTS + v) as u32,
                        vb.as_mut_ptr() as *mut core::ffi::c_void,
                        4,
                    )
                } == 0
                {
                    r.iaid = u32::from_be_bytes(vb);
                    r.got_iana = true;
                }
            }
            D6_OPT_VENDOR_CLASS => {
                // Enterprise number = first 4 value bytes (big-endian); 343 → TFTP boot.
                let mut vb = [0u8; 4];
                if unsafe {
                    bpf_xdp_load_bytes(
                        ctx.ctx,
                        (F6_OPTS + v) as u32,
                        vb.as_mut_ptr() as *mut core::ffi::c_void,
                        4,
                    )
                } == 0
                    && u32::from_be_bytes(vb) == PXE_ENTERPRISE
                    && r.pxe_mode == PXE_NONE
                {
                    r.pxe_mode = PXE_TFTP;
                }
            }
            D6_OPT_CLIENTID => {
                r.got_clientid = true;
                let dl = (olen as usize).min(D6_MAX_DUID);
                r.duid_len = dl as u16;
                // Load up to D6_MAX_DUID DUID bytes straight into `r.duid`; emit echoes `duid_len`
                // of them. Loading the full 10 is harmless (the frame was grown) and never echoed.
                let _ = unsafe {
                    bpf_xdp_load_bytes(
                        ctx.ctx,
                        (F6_OPTS + v) as u32,
                        r.duid.as_mut_ptr() as *mut core::ffi::c_void,
                        D6_MAX_DUID as u32,
                    )
                };
            }
            _ => {}
        }
        // Advance to the next option. A zero-length option still advances by the 4-byte header,
        // and `guard` bounds the loop regardless, so this always terminates for the verifier.
        i = v + olen as usize;
    }
    r.pxe_mode as u32
}

// Constant option bytes live in `.rodata` so `d6_emit` doesn't stage them on its stack — the
// combined stack of `guest_tx` + `d6_emit` must stay under the BPF 512-byte limit, and a 50-byte
// IA_NA stack buffer pushed it to 592. store_bytes copies straight from these read-only sources.
//
// IA_NA template: opt(3)+len(46) | iaid(0) | t1=∞ | t2=∞ | IAADDR opt(5)+len(30) | addr(0) |
//   preferred=∞ | valid=∞ | STATUS opt(13)+len(2)+code(0=SUCCESS). The iaid (offset 4) and the
//   IPv6 address (offset 20) are overwritten with two further small store_bytes from runtime data.
#[rustfmt::skip]
static IA_TEMPLATE: [u8; 50] = [
    0, 3,  0, 46,
    0, 0, 0, 0,
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
    0, 5,  0, 30,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
    0, 13, 0, 2, 0, 0,
];
// RapidCommit option (opt 14, len 0).
static RC_OPT: [u8; 4] = [0, 14, 0, 0];
// One zero byte, used to null the odd-length checksum pad byte.
static ZERO1: [u8; 1] = [0];
// Boot file URL pieces.
static TFTP_SCHEME: [u8; 7] = *b"tftp://";
static HTTP_SCHEME: [u8; 7] = *b"http://";
static URL_LBRACKET: [u8; 1] = [b'['];
static URL_RBRACKET: [u8; 2] = [b']', b'/'];

/// Emit the DHCPv6 reply into the (already tail-adjusted) packet. Marked `#[inline(never)]` so it
/// is a separate BPF subprogram — its option-branch combinations are verified on their own rather
/// than multiplied against the parse loop's states.
#[inline(never)]
fn d6_emit(ctx: &XdpContext, data: usize, data_end: usize, meta: &PortMeta, r: &D6Reply) {
    // Constant-size check: after this the verifier proves any constant offset < D6_MAX_TOTAL is
    // in-bounds for direct packet access. (adjust_tail already grew the frame, so this holds.)
    // data/data_end are passed in rather than re-derived from `ctx` inside the subprogram — see
    // d6_parse for why (`ctx.data_end()` in a subprogram trips "pointer arithmetic on pkt_end").
    if data + D6_MAX_TOTAL > data_end {
        return;
    }
    let p = data as *mut u8;
    let real_reply_len = r.real_reply_len as usize;

    // NOTE: we deliberately do NOT zero-fill the option region. A constant-length `write_bytes`
    // memset here became a byte loop that the verifier `mark_precise`-walked once per downstream
    // store_bytes state — tens of thousands of times — blowing the 1M instruction limit. Instead
    // the checksum below sums only the real bytes (gated by length) and zeroes the lone odd-pad
    // byte, so the uninitialised grown tail never affects the result.

    // ─── Ethernet ───
    unsafe {
        write6(p, &r.req_eth_src);
        write6(p.add(6), &GW_MAC);
        core::ptr::write_unaligned(p.add(12) as *mut u16, ETH_P_IPV6.to_be());
    }

    // ─── IPv6 ───
    let ipv6_payload_len = (real_reply_len - ETH_LEN - 40) as u16;
    unsafe {
        core::ptr::write_unaligned(p.add(ETH_LEN + 4) as *mut u16, ipv6_payload_len.to_be());
        *p.add(ETH_LEN + 6) = IPPROTO_UDP;
        *p.add(ETH_LEN + 7) = 64; // hop limit
        write16(p.add(ETH_LEN + 8), &meta.gateway_ipv6);
        write16(p.add(ETH_LEN + 24), &r.req_src6);
    }

    // ─── UDP ───
    let udp_len = ipv6_payload_len;
    unsafe {
        core::ptr::write_unaligned(p.add(ETH_LEN + 40) as *mut u16, 547u16.to_be());
        core::ptr::write_unaligned(p.add(ETH_LEN + 42) as *mut u16, 546u16.to_be());
        core::ptr::write_unaligned(p.add(ETH_LEN + 44) as *mut u16, udp_len.to_be());
        core::ptr::write_unaligned(p.add(ETH_LEN + 46) as *mut u16, 0u16); // cksum filled later
    }

    // ─── DHCPv6 message header ───
    unsafe {
        *p.add(F6_DHCP) = r.reply_type;
        *p.add(F6_DHCP + 1) = r.tid[0];
        *p.add(F6_DHCP + 2) = r.tid[1];
        *p.add(F6_DHCP + 3) = r.tid[2];
    }

    let dhcp_cfg = crate::maps::DHCP_CONFIG.get(0);
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let dhcp_meta = unsafe { crate::maps::DHCP_META.get(&ifindex) };
    let duid_len_usize = (r.duid_len as usize).min(D6_MAX_DUID);

    let mut off: usize = 0;

    // ServerId: DUID-LL (always present) — constant offset, direct packet write.
    unsafe {
        core::ptr::write_unaligned(p.add(F6_OPTS + off) as *mut u16, D6_OPT_SERVERID.to_be());
        core::ptr::write_unaligned(p.add(F6_OPTS + off + 2) as *mut u16, 10u16.to_be());
        core::ptr::write_unaligned(p.add(F6_OPTS + off + 4) as *mut u16, DUID_LL_TYPE.to_be());
        core::ptr::write_unaligned(
            p.add(F6_OPTS + off + 6) as *mut u16,
            DP_DHCPV6_HW_ID.to_be(),
        );
        write6(p.add(F6_OPTS + off + 8), &meta.guest_mac);
    }
    off += 14;

    // ClientId: echo the client's DUID (off is still constant 14 here).
    if r.got_clientid && duid_len_usize > 0 {
        unsafe {
            core::ptr::write_unaligned(p.add(F6_OPTS + off) as *mut u16, D6_OPT_CLIENTID.to_be());
            core::ptr::write_unaligned(
                p.add(F6_OPTS + off + 2) as *mut u16,
                (duid_len_usize as u16).to_be(),
            );
        }
        let duid_ptr = r.duid.as_ptr();
        let mut di = 0usize;
        while di < duid_len_usize && di < D6_MAX_DUID {
            unsafe {
                *p.add(F6_OPTS + off + 4 + di) = *duid_ptr.add(di);
            }
            di += 1;
        }
        off += 4 + duid_len_usize;
    }

    // From here `off` is runtime-variable. Adding a variable to a packet pointer yields range=0
    // (the verifier won't combine it with the static data range), so these options are written
    // with bpf_xdp_store_bytes, which bounds-checks each store internally.

    // One small reused stack buffer for the option headers that carry a runtime length.
    let mut hdr = [0u8; 4];

    // IA_NA: store the constant template from .rodata, then overlay the runtime iaid (offset 4)
    // and the assigned IPv6 address (offset 20, straight from map memory).
    if r.got_iana {
        let iaid_be = r.iaid.to_be_bytes();
        unsafe {
            store(ctx, F6_OPTS + off, IA_TEMPLATE.as_ptr(), 50);
            store(ctx, F6_OPTS + off + 4, iaid_be.as_ptr(), 4);
            store(ctx, F6_OPTS + off + 20, meta.guest_ipv6.as_ptr(), 16);
        }
        off += 50;
    }

    // RapidCommit (only if client sent it) — constant option from .rodata.
    if r.rapid_commit {
        unsafe {
            store(ctx, F6_OPTS + off, RC_OPT.as_ptr(), 4);
        }
        off += 4;
    }

    // DNS servers: 4-byte header then each 16-byte address stored straight from map memory.
    let dns6_count = (r.dns6_count as usize).min(D6_MAX_DNS);
    if dns6_count > 0 {
        if let Some(cfg) = dhcp_cfg {
            let dns_data_len = (dns6_count as u16) * 16;
            hdr[0..2].copy_from_slice(&D6_OPT_DNS.to_be_bytes());
            hdr[2..4].copy_from_slice(&dns_data_len.to_be_bytes());
            unsafe {
                store(ctx, F6_OPTS + off, hdr.as_ptr(), 4);
            }
            let dns6_ptr = cfg.dns6.as_ptr();
            let mut di = 0usize;
            while di < dns6_count {
                unsafe {
                    store(
                        ctx,
                        F6_OPTS + off + 4 + di * 16,
                        dns6_ptr.add(di) as *const u8,
                        16,
                    );
                }
                di += 1;
            }
            off += 4 + dns6_count * 16;
        }
    }

    // Boot File URL: 4-byte header then the URL pieces, all via store_bytes.
    if r.url_len as usize > 0 {
        if let Some(dm) = dhcp_meta {
            hdr[0..2].copy_from_slice(&D6_OPT_BOOT_FILE.to_be_bytes());
            hdr[2..4].copy_from_slice(&r.url_len.to_be_bytes());
            unsafe {
                store(ctx, F6_OPTS + off, hdr.as_ptr(), 4);
                let written = d6_store_url(ctx, F6_OPTS + off + 4, r.pxe_mode, dm);
                off += 4 + written;
            }
        }
    }
    let _ = off;

    // Zero the single odd-length pad byte: when udp_len is odd, the last checksummed 16-bit word
    // straddles the last real byte and the first (uninitialised) pad byte — zeroing that pad byte
    // makes the word = real_byte<<8, which is the RFC's "pad the final odd byte with zero" rule.
    // (The maximum-size reply has an even udp_len, so real_reply_len < D6_MAX_TOTAL whenever this
    // matters and the 1-byte store stays in-bounds.) The UDP checksum itself is computed by the
    // separate `d6_checksum` subprogram so its locals don't add to this frame.
    unsafe {
        store(ctx, real_reply_len, ZERO1.as_ptr(), 1);
    }
}

/// Compute and write the DHCPv6 reply's UDP checksum. A separate BPF subprogram (not nested under
/// `d6_emit`) so its locals form their own short call chain with the large `guest_tx` frame rather
/// than adding to `guest_tx + d6_emit` (the combined-stack 512-byte limit is the binding one here).
///
/// `data`/`data_end` are passed in (re-deriving via `ctx` in a subprogram trips the verifier — see
/// `d6_parse`). Sums the IPv6 pseudo-header + UDP datagram over a CONSTANT number of words, folding
/// in only words within `udp_len` so the uninitialised pad past the real reply is read-but-ignored.
#[inline(never)]
fn d6_checksum(data: usize, data_end: usize, udp_len: u16) -> u32 {
    if data + D6_MAX_TOTAL > data_end {
        return 0;
    }
    let p = data as *const u8;
    const D6_UDP_CKSUM_LEN: usize = D6_MAX_TOTAL - ETH_LEN - 40;
    // Clamp to the constant scan length so the verifier knows the gate `j < udp_len_usize` is
    // bounded (an unbounded u16 param forked the loop state past the 1M instruction limit).
    let udp_len_usize = (udp_len as usize).min(D6_UDP_CKSUM_LEN);
    let mut cs: u32 = 0;
    let mut k: usize = 0;
    while k < 16 {
        cs = cs.wrapping_add(u16::from_be(unsafe {
            core::ptr::read_unaligned(p.add(ETH_LEN + 8 + k) as *const u16)
        }) as u32);
        cs = cs.wrapping_add(u16::from_be(unsafe {
            core::ptr::read_unaligned(p.add(ETH_LEN + 24 + k) as *const u16)
        }) as u32);
        k += 2;
    }
    cs = cs.wrapping_add(udp_len as u32);
    cs = cs.wrapping_add(IPPROTO_UDP as u32);
    let mut j: usize = 0;
    while j < D6_UDP_CKSUM_LEN {
        if j < udp_len_usize {
            cs = cs.wrapping_add(u16::from_be(unsafe {
                core::ptr::read_unaligned(p.add(ETH_LEN + 40 + j) as *const u16)
            }) as u32);
        }
        j += 2;
    }
    cs = (cs & 0xffff) + (cs >> 16);
    cs = (cs & 0xffff) + (cs >> 16);
    let cksum = !(cs as u16);
    unsafe {
        core::ptr::write_unaligned((data + ETH_LEN + 46) as *mut u16, cksum.to_be());
    }
    cksum as u32
}

/// In-datapath DHCPv6 responder.
///
/// Detects DHCPv6 SOLICIT/REQUEST/CONFIRM on UDP dst port 547, then delegates option parsing to
/// `d6_parse` and reply construction to `d6_emit` (both separate BPF subprograms — see their docs
/// for why splitting keeps the verifier's state count in check). Returns `Some(XDP_TX)` on reply.
#[inline(always)]
pub fn try_dhcpv6_reply(ctx: &XdpContext, meta: &PortMeta) -> Option<u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + MIN_D6_LEN > data_end {
        return None;
    }
    let p = data as *const u8;

    // Detect: ETH_P_IPV6 / next-header UDP / UDP dst port 547.
    let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(12) as *const u16) });
    if ethertype != ETH_P_IPV6 {
        return None;
    }
    if unsafe { *p.add(ETH_LEN + 6) } != IPPROTO_UDP {
        return None;
    }
    let udp_dst =
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 40 + 2) as *const u16) });
    if udp_dst != 547 {
        return None;
    }

    let msg_type = unsafe { *p.add(F6_DHCP) };
    if msg_type != D6_SOLICIT && msg_type != D6_REQUEST && msg_type != D6_CONFIRM {
        return None;
    }

    let mut r = D6Reply {
        got_clientid: false,
        duid: [0u8; D6_MAX_DUID],
        duid_len: 0,
        got_iana: false,
        iaid: 0,
        rapid_commit: false,
        pxe_mode: PXE_NONE,
        reply_type: D6_REPLY,
        tid: [
            unsafe { *p.add(F6_DHCP + 1) },
            unsafe { *p.add(F6_DHCP + 2) },
            unsafe { *p.add(F6_DHCP + 3) },
        ],
        dns6_count: 0,
        url_len: 0,
        real_reply_len: 0,
        req_src6: unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 8) as *const [u8; 16]) },
        req_eth_src: unsafe { core::ptr::read_unaligned(p.add(6) as *const [u8; 6]) },
    };

    // Real option-byte count in the *original* frame, captured before we grow it (the grown tail
    // is garbage and must not be parsed). Clamp to the scan window.
    let cur_len = data_end - data;
    let opts_avail = if cur_len > F6_OPTS {
        cur_len - F6_OPTS
    } else {
        0
    };
    let n = if opts_avail < D6_SCAN {
        opts_avail
    } else {
        D6_SCAN
    };

    // Grow the frame to the MAXIMUM possible reply size FIRST, so both parse and emit can use a
    // single constant-size bounds check for all their direct packet accesses (the UDP/IPv6 length
    // fields carry the REAL payload length; trailing pad is zeroed and checksum-neutral).
    let delta: i32 = D6_MAX_TOTAL as i32 - cur_len as i32;
    if unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) } != 0 {
        return None;
    }
    // Re-fetch packet bounds after the grow (adjust_tail invalidates the old pointers) and pass
    // them explicitly to the subprograms.
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Parse options (separate subprogram). Store the returned pxe_mode back into `r` — using the
    // return value keeps it live so the subprogram materialises a scalar in R0 (see d6_parse).
    r.pxe_mode = d6_parse(ctx, &mut r, n) as u8;

    // Reply type: SOLICIT+RapidCommit → REPLY, plain SOLICIT → ADVERTISE, REQUEST/CONFIRM → REPLY.
    r.reply_type = if msg_type == D6_SOLICIT && !r.rapid_commit {
        D6_ADVERTISE
    } else {
        D6_REPLY
    };

    // Config-derived option sizes (DNS, PXE boot file URL).
    let dhcp_cfg = crate::maps::DHCP_CONFIG.get(0);
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let dhcp_meta = unsafe { crate::maps::DHCP_META.get(&ifindex) };

    let dns6_count = if let Some(cfg) = dhcp_cfg {
        (cfg.dns6_len as usize).min(D6_MAX_DNS)
    } else {
        0
    };
    r.dns6_count = dns6_count as u16;

    let url_len = if r.pxe_mode != PXE_NONE {
        if let Some(dm) = dhcp_meta {
            d6_url_len(r.pxe_mode, dm).min(D6_MAX_URL)
        } else {
            0
        }
    } else {
        0
    };
    r.url_len = url_len as u16;

    // Size the reply. The sum is ≤ D6_MAX_OPTS by construction, but the `.min` makes that explicit
    // to the verifier so it does NOT keep an (unreachable) "too big → return None" branch: such a
    // None after the tail-grow would fall through to guest_tx's forwarding path, and the verifier
    // explored that whole map-heavy path once per parse state — tens of thousands of times, blowing
    // the 1M instruction limit. We have already grown the frame, so from here we ALWAYS emit.
    let duid_len_usize = (r.duid_len as usize).min(D6_MAX_DUID);
    let real_opts_len: usize =
        (14 + if r.got_clientid && duid_len_usize > 0 {
            4 + duid_len_usize
        } else {
            0
        } + if r.got_iana { 50 } else { 0 }
            + if r.rapid_commit { 4 } else { 0 }
            + if dns6_count > 0 {
                4 + dns6_count * 16
            } else {
                0
            }
            + if url_len > 0 { 4 + url_len } else { 0 })
        .min(D6_MAX_OPTS);
    r.real_reply_len = (F6_OPTS + real_opts_len) as u16;

    // Emit the reply, then compute its UDP checksum (two separate subprograms, each a short call
    // chain off the large guest_tx frame — see d6_checksum for why the checksum is split out).
    d6_emit(ctx, data, data_end, meta, &r);
    let udp_len = (real_opts_len + F6_OPTS - ETH_LEN - 40) as u16;
    let _ = d6_checksum(data, data_end, udp_len);

    Some(xdp_action::XDP_TX)
}
