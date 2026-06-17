use aya_ebpf::{helpers::bpf_ktime_get_ns, programs::XdpContext};
use xdp_dp_common::{
    CtEntry, CtKey, CT_REWRITE_SRC, TCP_ESTABLISHED, TCP_FINWAIT, TCP_NEW_SYN, TCP_NEW_SYNACK,
    TCP_RST_FIN,
};

use crate::csum::csum_replace4;
use crate::parse::l4_ports;

/// Fold a 16-bit field change (network-order) into an L4/ICMP checksum via csum_replace4.
#[inline(always)]
pub fn csum_replace2(check: u16, old: u16, new: u16) -> u16 {
    let o = old.to_be_bytes();
    let n = new.to_be_bytes();
    csum_replace4(check, &[o[0], o[1], 0, 0], &[n[0], n[1], 0, 0])
}

/// Current kernel monotonic time (ns).
#[inline(always)]
pub fn now() -> u64 {
    unsafe { bpf_ktime_get_ns() }
}

/// Build the VNI-keyed 5-tuple key for the packet at `ip_off` (host-order ports; ICMP id in both ports).
#[inline(always)]
pub fn ct_key(data: usize, data_end: usize, ip_off: usize, vni: u32) -> Option<CtKey> {
    let p = data as *const u8;
    if data + ip_off + 20 > data_end {
        return None;
    }
    let src = unsafe { core::ptr::read_unaligned(p.add(ip_off + 12) as *const [u8; 4]) };
    let dst = unsafe { core::ptr::read_unaligned(p.add(ip_off + 16) as *const [u8; 4]) };
    let (proto, sport, dport) = l4_ports(data, data_end, ip_off)?;
    Some(CtKey {
        vni,
        src_ip: src,
        dst_ip: dst,
        src_port: sport,
        dst_port: dport,
        proto,
        _pad: [0; 3],
    })
}

/// Apply a conntrack entry's translation to the packet at `ip_off`.
///
/// Rewrites the src address (CT_REWRITE_SRC) or dst address (otherwise) to `xlate_ip` and
/// updates the corresponding L4 port / ICMP id to `xlate_port` (when non-zero), fixing IP and
/// L4/ICMP checksums.
///
/// Only handles packets with a standard 20-byte IPv4 header (IHL == 5 / no options), which
/// covers all conntrack-tracked flows in this datapath (options are dropped at ingress).
///
/// All reads happen before any writes so the verifier's pkt-range tracking is not invalidated
/// mid-function. All L4 offsets are constants (ip_off + 20 = ETH_LEN + 20 = 34 is fixed), so
/// the verifier can check every access against known bounds without variable-offset pkt pointers.
#[inline(always)]
pub fn ct_apply(ctx: &XdpContext, ip_off: usize, e: &CtEntry) {
    // DEFAULT (flag-less) entries carry no translation — never rewrite, or we'd null the address.
    if e.flags & (xdp_dp_common::CT_REWRITE_SRC | xdp_dp_common::CT_REWRITE_DST) == 0 {
        return;
    }
    // Re-fetch bounds: after CONNTRACK.get() (a helper call) the verifier resets pkt-range
    // tracking, so we must re-establish it here.
    let data = ctx.data();
    let data_end = ctx.data_end();
    let p = data as *mut u8;

    // Only handle standard 20-byte IP headers (IHL == 5).
    // This covers all conntrack-tracked flows; packets with options were dropped at ingress.
    if data + ip_off + 20 > data_end {
        return;
    }
    let ihl_byte = unsafe { *p.add(ip_off) };
    if ihl_byte & 0x0f != 5 {
        return;
    }
    // From here: l4 = ip_off + 20 is a constant (no variable-offset pkt access).
    let l4 = ip_off + 20;

    let proto = unsafe { *p.add(ip_off + 9) };
    let rewrite_src = e.flags & CT_REWRITE_SRC != 0;
    let addr_off = ip_off + if rewrite_src { 12 } else { 16 };

    // --- Phase 1: read all packet fields before any write ---
    let old_addr = unsafe { core::ptr::read_unaligned(p.add(addr_off) as *const [u8; 4]) };
    let new_addr = e.xlate_ip;
    let old_ip_csum =
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(ip_off + 10) as *const u16) });

    // Bounds checks at fixed offsets: all l4+N are compile-time constants.
    let tcp_ok = proto == 6 && data + l4 + 18 <= data_end;
    let udp_ok = proto == 17 && data + l4 + 8 <= data_end;
    let icmp_ok = proto == 1 && data + l4 + 8 <= data_end;

    let tcp_csum = if tcp_ok {
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(l4 + 16) as *const u16) })
    } else {
        0
    };
    let udp_csum = if udp_ok {
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(l4 + 6) as *const u16) })
    } else {
        0
    };
    let icmp_csum = if icmp_ok {
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(l4 + 2) as *const u16) })
    } else {
        0
    };
    let icmp_id = if icmp_ok {
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(l4 + 4) as *const u16) })
    } else {
        0
    };

    // Port offsets: src port at l4+0, dst port at l4+2. All constants.
    let src_port_off = l4;
    let dst_port_off = l4 + 2;
    let port_off = if rewrite_src {
        src_port_off
    } else {
        dst_port_off
    };

    let old_port = if (tcp_ok || udp_ok) && e.xlate_port != 0 {
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(port_off) as *const u16) })
    } else {
        0
    };

    // --- Phase 2: compute new checksums (pure arithmetic, no packet access) ---
    let new_ip_csum = csum_replace4(old_ip_csum, &old_addr, &new_addr);

    let new_tcp_csum = if tcp_ok {
        let c1 = csum_replace4(tcp_csum, &old_addr, &new_addr);
        if e.xlate_port != 0 {
            csum_replace2(c1, old_port, e.xlate_port)
        } else {
            c1
        }
    } else {
        0
    };

    let new_udp_csum = if udp_ok && udp_csum != 0 {
        let c1 = csum_replace4(udp_csum, &old_addr, &new_addr);
        if e.xlate_port != 0 {
            csum_replace2(c1, old_port, e.xlate_port)
        } else {
            c1
        }
    } else {
        0
    };

    let new_icmp_csum = if icmp_ok && e.xlate_port != 0 {
        csum_replace2(icmp_csum, icmp_id, e.xlate_port)
    } else {
        0
    };

    // --- Phase 3: write all modified fields ---
    unsafe {
        // IP address + checksum
        core::ptr::write_unaligned(p.add(addr_off) as *mut [u8; 4], new_addr);
        core::ptr::write_unaligned(p.add(ip_off + 10) as *mut u16, new_ip_csum.to_be());

        if tcp_ok {
            core::ptr::write_unaligned(p.add(l4 + 16) as *mut u16, new_tcp_csum.to_be());
            if e.xlate_port != 0 {
                core::ptr::write_unaligned(p.add(port_off) as *mut u16, e.xlate_port.to_be());
            }
        } else if udp_ok {
            if udp_csum != 0 {
                core::ptr::write_unaligned(p.add(l4 + 6) as *mut u16, new_udp_csum.to_be());
            }
            if e.xlate_port != 0 {
                core::ptr::write_unaligned(p.add(port_off) as *mut u16, e.xlate_port.to_be());
            }
        } else if icmp_ok && e.xlate_port != 0 {
            core::ptr::write_unaligned(p.add(l4 + 2) as *mut u16, new_icmp_csum.to_be());
            core::ptr::write_unaligned(p.add(l4 + 4) as *mut u16, e.xlate_port.to_be());
        }
    }
}

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// Advance the TCP state for a flow given a packet's TCP flags (functional parity with dpservice's
/// NONE->NEW_SYN->NEW_SYNACK->ESTABLISHED->FINWAIT->RST_FIN progression).
#[inline(always)]
pub fn tcp_advance(state: u8, flags: u8) -> u8 {
    if flags & TCP_RST != 0 {
        return TCP_RST_FIN;
    }
    if flags & TCP_FIN != 0 {
        return TCP_FINWAIT;
    }
    if flags & TCP_SYN != 0 {
        if flags & TCP_ACK != 0 {
            return TCP_NEW_SYNACK;
        }
        return TCP_NEW_SYN;
    }
    if flags & TCP_ACK != 0
        && (state == TCP_NEW_SYNACK || state == TCP_NEW_SYN || state == TCP_ESTABLISHED)
    {
        return TCP_ESTABLISHED;
    }
    state
}

/// Refresh last_seen (and TCP state for TCP) on a matched entry, writing it back.
#[inline(always)]
pub fn ct_touch(ctx: &XdpContext, ip_off: usize, key: &CtKey, e: &mut CtEntry) {
    e.last_seen = now();
    if let Some(fl) = crate::parse::tcp_flags(ctx.data(), ctx.data_end(), ip_off) {
        e.tcp_state = tcp_advance(e.tcp_state, fl);
    }
    let _ = crate::maps::CONNTRACK.insert(key, e, 0);
}

/// Invert a 5-tuple key (swap src/dst addr + port) — the expected reverse-direction key.
#[inline(always)]
pub fn invert_key(k: &CtKey) -> CtKey {
    CtKey {
        vni: k.vni,
        src_ip: k.dst_ip,
        dst_ip: k.src_ip,
        src_port: k.dst_port,
        dst_port: k.src_port,
        proto: k.proto,
        _pad: [0; 3],
    }
}

/// Insert a no-translation DEFAULT conntrack entry for a flow on conntrack-miss, so every flow is
/// tracked (firewall + aging see it). Records last_seen + initial TCP state. Also pre-seeds the
/// reverse-direction entry so return traffic is immediately recognised as established.
#[inline(always)]
pub fn ct_ensure_default(ctx: &XdpContext, ip_off: usize, key: &CtKey) {
    let tcp = crate::parse::tcp_flags(ctx.data(), ctx.data_end(), ip_off)
        .map(|fl| tcp_advance(0, fl))
        .unwrap_or(0);
    let e = CtEntry {
        last_seen: now(),
        xlate_ip: [0; 4],
        xlate_port: 0,
        flags: xdp_dp_common::CT_F_DEFAULT,
        tcp_state: tcp,
        fwall_action: 0,
        _pad: [0; 7],
    };
    let _ = crate::maps::CONNTRACK.insert(key, &e, 0);
    // Pre-seed the reverse direction so return traffic is immediately recognised as established,
    // but only if no entry already exists (NAT reverse entries must not be overwritten).
    let rev = invert_key(key);
    if unsafe { crate::maps::CONNTRACK.get(&rev) }.is_none() {
        let _ = crate::maps::CONNTRACK.insert(&rev, &e, 0);
    }
}
