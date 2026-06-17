use aya_ebpf::programs::XdpContext;
use xdp_dp_common::{LbKey, MaglevKey};

use crate::maps::{LB, MAGLEV};
use crate::parse::{hash5, l4_ports};

/// If the inner IPv4 dst+port is an LB service, Maglev-select a backend and return its underlay
/// /128. No DNAT, no conntrack — the backend VF owns the LB IP (anycast) and replies from it.
#[inline(always)]
pub fn lb_select_forward(ctx: &XdpContext, ip_off: usize, vni: u32) -> Option<[u8; 16]> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ip_off + 20 > data_end {
        return None;
    }
    let p = data as *const u8;
    let dst = unsafe { core::ptr::read_unaligned(p.add(ip_off + 16) as *const [u8; 4]) };
    let src = unsafe { core::ptr::read_unaligned(p.add(ip_off + 12) as *const [u8; 4]) };
    let (proto, sport, dport) = l4_ports(data, data_end, ip_off)?;
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
    Some(*backend)
}
