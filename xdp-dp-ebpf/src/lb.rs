use aya_ebpf::programs::XdpContext;
use xdp_dp_common::{CtKey, LbKey, MaglevKey};

use crate::csum::csum_replace4;
use crate::maps::{CONNTRACK, LB, MAGLEV};
use crate::parse::{hash5, l4_ports};

/// If the packet's inner IPv4 dst+port is an LB, Maglev-select a backend, DNAT to it (+csum),
/// insert reverse conntrack, and return Some(backend_ipv4). Else None.
#[inline(always)]
pub fn lb_select_dnat(ctx: &XdpContext, ip_off: usize, vni: u32) -> Option<[u8; 4]> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ip_off + 20 > data_end {
        return None;
    }
    let p = data as *mut u8;
    let dst = unsafe { core::ptr::read_unaligned(p.add(ip_off + 16) as *const [u8; 4]) };
    let src = unsafe { core::ptr::read_unaligned(p.add(ip_off + 12) as *const [u8; 4]) };
    let (proto, sport, dport) = l4_ports(data, data_end, ip_off)?;
    // For ICMP the L4 "port" is the echo id (varies per client process); LB services are keyed
    // with port=0 for ICMP so one service matches all ids. TCP/UDP key on the real dport. The
    // Maglev hash below still uses the real id, giving per-flow stickiness + cross-flow spread.
    let lookup_port = if proto == 1 { 0 } else { dport };
    let lb = unsafe {
        LB.get(&LbKey {
            vni,
            ipv4: dst,
            port: lookup_port,
            proto,
            _pad: 0,
        })
    }?;
    if lb.size == 0 {
        return None;
    }
    let slot = hash5(&src, &dst, sport, dport, proto) % lb.size;
    let backend = unsafe {
        MAGLEV.get(&MaglevKey {
            table_id: lb.table_id,
            slot,
        })
    }?;
    let backend = *backend;
    // DNAT dst: LB -> backend
    let ihl = (unsafe { *p.add(ip_off) } & 0x0f) as usize * 4;
    unsafe {
        core::ptr::write_unaligned(p.add(ip_off + 16) as *mut [u8; 4], backend);
        let ipc = u16::from_be(core::ptr::read_unaligned(p.add(ip_off + 10) as *const u16));
        core::ptr::write_unaligned(
            p.add(ip_off + 10) as *mut u16,
            csum_replace4(ipc, &dst, &backend).to_be(),
        );
        let l4 = ip_off + ihl;
        if proto == 6 && data + l4 + 18 <= data_end {
            let c = u16::from_be(core::ptr::read_unaligned(p.add(l4 + 16) as *const u16));
            core::ptr::write_unaligned(
                p.add(l4 + 16) as *mut u16,
                csum_replace4(c, &dst, &backend).to_be(),
            );
        } else if proto == 17 && data + l4 + 8 <= data_end {
            let c = u16::from_be(core::ptr::read_unaligned(p.add(l4 + 6) as *const u16));
            if c != 0 {
                core::ptr::write_unaligned(
                    p.add(l4 + 6) as *mut u16,
                    csum_replace4(c, &dst, &backend).to_be(),
                );
            }
        }
    }
    // reverse conntrack: backend->client expected on the return; restore lb (= dst) on egress.
    let key = CtKey {
        vni,
        src_ip: backend,
        dst_ip: src,
        src_port: dport, // backend replies from the LB port
        dst_port: sport,
        proto,
        _pad: [0; 3],
    };
    let _ = CONNTRACK.insert(
        &key,
        &xdp_dp_common::CtEntry {
            last_seen: crate::conntrack::now(),
            xlate_ip: dst,
            xlate_port: 0,
            flags: xdp_dp_common::CT_REWRITE_SRC | xdp_dp_common::CT_F_DST_LB,
            tcp_state: 0,
            fwall_action: 0,
            _pad: [0; 7],
        },
        0,
    );
    Some(backend)
}
