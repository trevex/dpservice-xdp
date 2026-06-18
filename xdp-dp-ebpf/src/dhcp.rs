use aya_ebpf::{bindings::xdp_action, helpers::bpf_xdp_adjust_tail, programs::XdpContext};
use xdp_dp_common::PortMeta;

use crate::arp_nd::GW_MAC;
use crate::parse::{write6, ETH_LEN, ETH_P_IP, IPPROTO_UDP};

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
    let mut sm_code: u8 = 0;
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
                sm_code = b;
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
