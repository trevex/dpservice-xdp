use aya_ebpf::{bindings::xdp_action, helpers::bpf_xdp_adjust_tail, programs::XdpContext};
use xdp_dp_common::PortMeta;

use crate::arp_nd::{csum16, GW_MAC};
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
            // sm_state == 2: reading value bytes
            if sm_is_msgtype && sm_remain == 1 {
                // This is the last byte of MESSAGE_TYPE option (and the only value byte)
                // Note: sm_remain counts DOWN from len. sm_remain=1 means we're on the FIRST
                // (and for len=1, only) value byte.
                // Wait: we decrement sm_remain AFTER this block, so sm_remain is still the
                // original count (not yet decremented). For len=1: sm_remain starts at 1,
                // this block executes once (boff is valid), we set msg_type = b, then
                // sm_remain becomes 0 and we go back to state 0.
                // Actually we need to check if this IS the first byte for msg_type (len=1 case).
                // Since MESSAGE_TYPE always has len=1 in valid DHCP, we can just capture any
                // byte while sm_is_msgtype is true (they'll all be the same byte for len=1).
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

    unsafe {
        *p.add(F_BOOTP) = 2;
        core::ptr::write_unaligned(p.add(F_BOOTP + 16) as *mut [u8; 4], meta.guest_ipv4);
        core::ptr::write_unaligned(p.add(F_BOOTP + 20) as *mut [u8; 4], [0u8; 4]);
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

/// Write the PXE boot file URL directly to `dst` (already bounds-checked by caller).
/// Returns the number of bytes written.
///
/// All array accesses use raw pointer arithmetic (no Rust bounds checks) so the
/// function compiles to a single basic block with no panic edges even in debug builds.
#[inline(always)]
unsafe fn d6_write_url(dst: *mut u8, pxe_mode: u8, dm: &xdp_dp_common::DhcpMeta) -> usize {
    let host_len = dm.pxe_host_len as usize;
    if host_len == 0 || host_len > 46 {
        return 0;
    }
    let mut up = 0usize;
    // scheme: use raw pointer to avoid bounds-check calls in debug builds
    let scheme_ptr: *const u8 = if pxe_mode == PXE_TFTP {
        b"tftp://".as_ptr()
    } else {
        b"http://".as_ptr()
    };
    let mut si = 0usize;
    while si < 7 {
        *dst.add(up) = *scheme_ptr.add(si);
        up += 1;
        si += 1;
    }
    // [host]/
    *dst.add(up) = b'[';
    up += 1;
    let host_ptr = dm.pxe_host.as_ptr();
    let mut hi = 0usize;
    while hi < host_len {
        *dst.add(up) = *host_ptr.add(hi);
        up += 1;
        hi += 1;
    }
    *dst.add(up) = b']';
    up += 1;
    *dst.add(up) = b'/';
    up += 1;
    // path
    if pxe_mode == PXE_TFTP {
        let path_ptr = TFTP_PATH.as_ptr();
        let path_len = TFTP_PATH.len();
        let mut pi = 0usize;
        while pi < path_len {
            *dst.add(up) = *path_ptr.add(pi);
            up += 1;
            pi += 1;
        }
    } else {
        let file_len = dm.boot_filename_len as usize;
        let file_ptr = dm.boot_filename.as_ptr();
        let mut fi = 0usize;
        while fi < file_len {
            *dst.add(up) = *file_ptr.add(fi);
            up += 1;
            fi += 1;
        }
    }
    up
}

/// In-datapath DHCPv6 responder.
///
/// Detects DHCPv6 SOLICIT/REQUEST/CONFIRM on UDP dst port 547, builds a reply
/// with IA_NA/ClientId/ServerId/DNS/BootFileUrl/RapidCommit, and returns XDP_TX.
///
/// Stack usage is minimised: no URL buffer (written directly to packet), DUID
/// capped at 10 bytes. Uses a single byte-by-byte bounded parse loop (stride=1).
///
/// NOTE: NOT marked #[inline(never)] — BPF does not support true out-of-line subprograms
/// within the same ELF section. Inlining is required; stack usage is kept low by writing
/// the boot-file URL directly to the packet and capping the DUID capture buffer.
#[inline(always)]
pub fn try_dhcpv6_reply(ctx: &XdpContext, meta: &PortMeta) -> Option<u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + MIN_D6_LEN > data_end {
        return None;
    }
    let p = data as *const u8;

    // Detect: ETH_P_IPV6
    let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(12) as *const u16) });
    if ethertype != ETH_P_IPV6 {
        return None;
    }
    // IPv6 next-header = UDP (17) at offset ETH_LEN+6
    if unsafe { *p.add(ETH_LEN + 6) } != IPPROTO_UDP {
        return None;
    }
    // UDP dst port = 547 (DHCPv6 server)
    let udp_dst =
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 40 + 2) as *const u16) });
    if udp_dst != 547 {
        return None;
    }

    // DHCPv6 message type and transaction ID
    let msg_type = unsafe { *p.add(F6_DHCP) };
    if msg_type != D6_SOLICIT && msg_type != D6_REQUEST && msg_type != D6_CONFIRM {
        return None;
    }
    let tid0 = unsafe { *p.add(F6_DHCP + 1) };
    let tid1 = unsafe { *p.add(F6_DHCP + 2) };
    let tid2 = unsafe { *p.add(F6_DHCP + 3) };

    // IPv6 source (link-local) and Ethernet source of requester
    let req_src6 = unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 8) as *const [u8; 16]) };
    let req_eth_src = unsafe { core::ptr::read_unaligned(p.add(6) as *const [u8; 6]) };

    // ─── Parse options — single byte-by-byte loop (stride=1, max 256, verifier-safe) ───
    // State: 0=op_hi 1=op_lo 2=len_hi 3=len_lo 4+=value. sm_phase tracks where we are.
    let mut sm_phase: u8 = 0;
    let mut sm_op: u16 = 0;
    let mut sm_len: u16 = 0;
    let mut sm_remain: u16 = 0;
    let mut sm_idx: u16 = 0; // index within current option value

    let mut got_clientid = false;
    let mut duid_buf = [0u8; D6_MAX_DUID];
    let mut duid_len: u16 = 0;

    let mut got_iana = false;
    let mut iaid: u32 = 0;

    let mut rapid_commit = false;

    // pxe_mode: PXE_NONE=0, PXE_TFTP=1, PXE_HTTP=2
    // During parsing we also use 3 = "saw 'i'" and 4 = "saw iPX" to detect "iPXE"
    let mut pxe_mode: u8 = PXE_NONE;
    // Track enterprise number bytes for VENDOR_CLASS
    let mut ent_acc: u32 = 0;

    let mut i: usize = 0;
    while i < 256 {
        let boff = data + F6_OPTS + i;
        if boff >= data_end {
            break;
        }
        let b = unsafe { *(boff as *const u8) };
        i += 1;

        if sm_phase == 0 {
            sm_op = (b as u16) << 8;
            sm_phase = 1;
        } else if sm_phase == 1 {
            sm_op |= b as u16;
            sm_phase = 2;
        } else if sm_phase == 2 {
            sm_len = (b as u16) << 8;
            sm_phase = 3;
        } else if sm_phase == 3 {
            sm_len |= b as u16;
            sm_remain = sm_len;
            sm_idx = 0;
            if sm_remain == 0 {
                if sm_op == D6_OPT_RAPID_COMMIT {
                    rapid_commit = true;
                }
                sm_phase = 0;
            } else {
                sm_phase = 4;
                ent_acc = 0; // reset for each new option
            }
        } else {
            // sm_phase == 4: reading value bytes
            match sm_op {
                D6_OPT_CLIENTID => {
                    if sm_idx == 0 {
                        got_clientid = true;
                        duid_len = sm_len.min(D6_MAX_DUID as u16);
                    }
                    // Use raw pointer write to avoid debug-mode bounds-check panic edges.
                    if (sm_idx as usize) < D6_MAX_DUID {
                        unsafe {
                            *duid_buf.as_mut_ptr().add(sm_idx as usize) = b;
                        }
                    }
                }
                D6_OPT_IA_NA => {
                    if sm_idx == 0 {
                        iaid = (b as u32) << 24;
                    } else if sm_idx == 1 {
                        iaid |= (b as u32) << 16;
                    } else if sm_idx == 2 {
                        iaid |= (b as u32) << 8;
                    } else if sm_idx == 3 {
                        iaid |= b as u32;
                        got_iana = true;
                    }
                }
                D6_OPT_VENDOR_CLASS => {
                    // Enterprise number is bytes 0-3 (big-endian)
                    if sm_idx == 0 {
                        ent_acc = (b as u32) << 24;
                    } else if sm_idx == 1 {
                        ent_acc |= (b as u32) << 16;
                    } else if sm_idx == 2 {
                        ent_acc |= (b as u32) << 8;
                    } else if sm_idx == 3 {
                        ent_acc |= b as u32;
                        if ent_acc == PXE_ENTERPRISE && pxe_mode == PXE_NONE {
                            pxe_mode = PXE_TFTP;
                        }
                    }
                }
                D6_OPT_USER_CLASS => {
                    // Structure: sub_opt_len(2) then data. Look for "iPXE" in data.
                    // sm_idx 0,1 = sub_opt_len; sm_idx 2+ = data bytes.
                    // We detect "iPXE" using pxe_mode states: 3=saw i, 4=saw iP, 5=saw iPX
                    if sm_idx >= 2 && pxe_mode != PXE_HTTP && pxe_mode != PXE_TFTP {
                        let ci = sm_idx - 2; // index within data
                        if ci == 0 {
                            pxe_mode = if b == b'i' { 3 } else { PXE_NONE };
                        } else if ci == 1 {
                            pxe_mode = if b == b'P' && pxe_mode == 3 {
                                4
                            } else {
                                PXE_NONE
                            };
                        } else if ci == 2 {
                            pxe_mode = if b == b'X' && pxe_mode == 4 {
                                5
                            } else {
                                PXE_NONE
                            };
                        } else if ci == 3 {
                            pxe_mode = if b == b'E' && pxe_mode == 5 {
                                PXE_HTTP
                            } else {
                                PXE_NONE
                            };
                        }
                    }
                }
                _ => {}
            }
            sm_idx += 1;
            sm_remain -= 1;
            if sm_remain == 0 {
                sm_phase = 0;
            }
        }
    }

    // Determine reply type
    let reply_type = if msg_type == D6_SOLICIT && rapid_commit {
        D6_REPLY
    } else if msg_type == D6_SOLICIT {
        D6_ADVERTISE
    } else {
        D6_REPLY // REQUEST or CONFIRM
    };

    // Look up DHCP config for DNS and PXE
    let dhcp_cfg = crate::maps::DHCP_CONFIG.get(0);
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let dhcp_meta = unsafe { crate::maps::DHCP_META.get(&ifindex) };

    let dns6_count = if let Some(cfg) = dhcp_cfg {
        (cfg.dns6_len as usize).min(D6_MAX_DNS)
    } else {
        0
    };

    // Compute URL length (no buffer — will write directly to packet)
    let url_len = if pxe_mode != PXE_NONE {
        if let Some(dm) = dhcp_meta {
            let l = d6_url_len(pxe_mode, dm);
            l.min(D6_MAX_URL)
        } else {
            0
        }
    } else {
        0
    };

    // ─── Size the reply ───
    let duid_len_usize = duid_len as usize;
    let real_opts_len: usize = 14  // ServerId (always)
        + if got_clientid && duid_len_usize > 0 { 4 + duid_len_usize } else { 0 }
        + if got_iana { 50 } else { 0 }
        + if rapid_commit { 4 } else { 0 }
        + if dns6_count > 0 { 4 + dns6_count * 16 } else { 0 }
        + if url_len > 0 { 4 + url_len } else { 0 };

    if real_opts_len > D6_MAX_OPTS {
        return None;
    }
    let real_reply_len = F6_OPTS + real_opts_len;

    // Always adjust the frame to the MAXIMUM possible reply size (F6_OPTS + D6_MAX_OPTS).
    // This lets us use a single compile-time constant bounds check after the tail adjust,
    // which is the only way to convince the BPF verifier that all subsequent packet writes
    // at variable offsets are safe (the verifier cannot propagate data_end-data >= runtime_var).
    // The UDP/IPv6 length fields carry the ACTUAL payload length so the DHCPv6 client knows
    // where the valid options end; bytes beyond real_reply_len are zero-padded (harmless).
    const D6_MAX_TOTAL: usize = F6_OPTS + D6_MAX_OPTS;
    let cur_len = data_end - data;
    {
        let delta: i32 = D6_MAX_TOTAL as i32 - cur_len as i32;
        if unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) } != 0 {
            return None;
        }
    }
    let data = ctx.data();
    let data_end = ctx.data_end();
    // Single constant-size check: the verifier can now prove any offset < D6_MAX_TOTAL is valid.
    if data + D6_MAX_TOTAL > data_end {
        return None;
    }
    let p = data as *mut u8;

    // ─── Rewrite Ethernet header ───
    unsafe {
        write6(p, &req_eth_src);
        write6(p.add(6), &GW_MAC);
        // ETH_P_IPV6 ethertype stays (0x86DD)
        core::ptr::write_unaligned(p.add(12) as *mut u16, ETH_P_IPV6.to_be());
    }

    // ─── Rewrite IPv6 header ───
    let ipv6_payload_len = (real_reply_len - ETH_LEN - 40) as u16;
    unsafe {
        // Version+TC+Flow already present; rewrite payload_len + next_hdr + hop_limit + addrs
        core::ptr::write_unaligned(p.add(ETH_LEN + 4) as *mut u16, ipv6_payload_len.to_be());
        *p.add(ETH_LEN + 6) = IPPROTO_UDP;
        *p.add(ETH_LEN + 7) = 64; // hop limit
        write16(p.add(ETH_LEN + 8), &meta.gateway_ipv6);
        write16(p.add(ETH_LEN + 24), &req_src6);
    }

    // ─── Rewrite UDP header ───
    let udp_len = ipv6_payload_len;
    unsafe {
        core::ptr::write_unaligned(p.add(ETH_LEN + 40) as *mut u16, 547u16.to_be()); // src port
        core::ptr::write_unaligned(p.add(ETH_LEN + 42) as *mut u16, 546u16.to_be()); // dst port
        core::ptr::write_unaligned(p.add(ETH_LEN + 44) as *mut u16, udp_len.to_be()); // length
        core::ptr::write_unaligned(p.add(ETH_LEN + 46) as *mut u16, 0u16); // cksum (fill later)
    }

    // ─── Rewrite DHCPv6 message header ───
    unsafe {
        *p.add(F6_DHCP) = reply_type;
        *p.add(F6_DHCP + 1) = tid0;
        *p.add(F6_DHCP + 2) = tid1;
        *p.add(F6_DHCP + 3) = tid2;
    }

    // ─── Write DHCPv6 options sequentially ───
    let mut off: usize = 0;

    // ServerId: DUID-LL (always present)
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

    // ClientId: echo the client's DUID
    if got_clientid && duid_len_usize > 0 {
        unsafe {
            core::ptr::write_unaligned(p.add(F6_OPTS + off) as *mut u16, D6_OPT_CLIENTID.to_be());
            core::ptr::write_unaligned(p.add(F6_OPTS + off + 2) as *mut u16, duid_len.to_be());
        }
        let duid_ptr = duid_buf.as_ptr();
        let mut di = 0usize;
        while di < duid_len_usize && di < D6_MAX_DUID {
            unsafe {
                *p.add(F6_OPTS + off + 4 + di) = *duid_ptr.add(di);
            }
            di += 1;
        }
        off += 4 + duid_len_usize;
    }

    // IA_NA with nested IAADDR + STATUS_CODE
    if got_iana {
        unsafe {
            // IA_NA header: op_len = iaid(4)+t1(4)+t2(4)+IAADDR_opt(4+30) = 46
            core::ptr::write_unaligned(p.add(F6_OPTS + off) as *mut u16, D6_OPT_IA_NA.to_be());
            core::ptr::write_unaligned(p.add(F6_OPTS + off + 2) as *mut u16, 46u16.to_be());
            core::ptr::write_unaligned(p.add(F6_OPTS + off + 4) as *mut u32, iaid.to_be());
            core::ptr::write_unaligned(
                p.add(F6_OPTS + off + 8) as *mut u32,
                0xffff_ffffu32.to_be(),
            ); // t1
            core::ptr::write_unaligned(
                p.add(F6_OPTS + off + 12) as *mut u32,
                0xffff_ffffu32.to_be(),
            ); // t2
               // IAADDR: op_len = ipv6(16)+preferred(4)+valid(4)+STATUS_CODE_opt(4+2)=30
            core::ptr::write_unaligned(
                p.add(F6_OPTS + off + 16) as *mut u16,
                D6_OPT_IAADDR.to_be(),
            );
            core::ptr::write_unaligned(p.add(F6_OPTS + off + 18) as *mut u16, 30u16.to_be());
            write16(p.add(F6_OPTS + off + 20), &meta.guest_ipv6);
            core::ptr::write_unaligned(
                p.add(F6_OPTS + off + 36) as *mut u32,
                0xffff_ffffu32.to_be(),
            ); // preferred
            core::ptr::write_unaligned(
                p.add(F6_OPTS + off + 40) as *mut u32,
                0xffff_ffffu32.to_be(),
            ); // valid
               // STATUS_CODE nested in IAADDR: op_len = 2, status = SUCCESS (0)
            core::ptr::write_unaligned(
                p.add(F6_OPTS + off + 44) as *mut u16,
                D6_OPT_STATUS_CODE.to_be(),
            );
            core::ptr::write_unaligned(p.add(F6_OPTS + off + 46) as *mut u16, 2u16.to_be());
            core::ptr::write_unaligned(p.add(F6_OPTS + off + 48) as *mut u16, 0u16.to_be());
            // SUCCESS
        }
        off += 50;
    }

    // RapidCommit (only if client sent it)
    if rapid_commit {
        unsafe {
            core::ptr::write_unaligned(
                p.add(F6_OPTS + off) as *mut u16,
                D6_OPT_RAPID_COMMIT.to_be(),
            );
            core::ptr::write_unaligned(p.add(F6_OPTS + off + 2) as *mut u16, 0u16.to_be());
        }
        off += 4;
    }

    // DNS servers
    if dns6_count > 0 {
        if let Some(cfg) = dhcp_cfg {
            let dns_data_len = (dns6_count as u16) * 16;
            unsafe {
                core::ptr::write_unaligned(p.add(F6_OPTS + off) as *mut u16, D6_OPT_DNS.to_be());
                core::ptr::write_unaligned(
                    p.add(F6_OPTS + off + 2) as *mut u16,
                    dns_data_len.to_be(),
                );
            }
            let dns6_ptr = cfg.dns6.as_ptr();
            let mut di = 0usize;
            while di < dns6_count {
                unsafe {
                    write16(p.add(F6_OPTS + off + 4 + di * 16), &*dns6_ptr.add(di));
                }
                di += 1;
            }
            off += 4 + dns6_count * 16;
        }
    }

    // Boot File URL (written directly to packet, no intermediate buffer)
    if url_len > 0 {
        unsafe {
            core::ptr::write_unaligned(p.add(F6_OPTS + off) as *mut u16, D6_OPT_BOOT_FILE.to_be());
            core::ptr::write_unaligned(
                p.add(F6_OPTS + off + 2) as *mut u16,
                (url_len as u16).to_be(),
            );
            if let Some(dm) = dhcp_meta {
                let written = d6_write_url(p.add(F6_OPTS + off + 4), pxe_mode, dm);
                off += 4 + written;
            }
        }
    }
    let _ = off; // silence "never read" warning

    // ─── UDP checksum over IPv6 pseudo-header ───
    // pseudo-header: src(16) + dst(16) + length(4 BE) + zeros(3) + next(1=17)
    let udp_payload_len = udp_len as usize;
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
    cs = cs.wrapping_add((udp_payload_len >> 16) as u32);
    cs = cs.wrapping_add((udp_payload_len & 0xffff) as u32);
    cs = cs.wrapping_add(IPPROTO_UDP as u32);
    let cksum = unsafe { csum16(cs, p.add(ETH_LEN + 40) as *const u8, udp_payload_len) };
    unsafe {
        core::ptr::write_unaligned(p.add(ETH_LEN + 46) as *mut u16, cksum.to_be());
    }

    Some(xdp_action::XDP_TX)
}
