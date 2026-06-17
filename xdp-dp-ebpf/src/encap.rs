use aya_ebpf::{
    helpers::{bpf_redirect, bpf_xdp_adjust_head},
    programs::XdpContext,
};
use xdp_dp_common::{Local, RouteValue};

use crate::parse::{write16, write6, ETH_LEN, ETH_P_IPV6, IPPROTO_IPIP, IPV6_LEN};

/// Encapsulate the current inner IPv4 frame into Eth+IPv6 toward `route.nexthop_ipv6` and
/// redirect out the local uplink. `inner_len` = (frame len - inner ETH_LEN), captured BEFORE
/// adjust_head.
#[inline(always)]
pub fn encap_and_redirect(
    ctx: &XdpContext,
    local: &Local,
    route: &RouteValue,
    inner_len: u16,
) -> Result<u32, ()> {
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -(IPV6_LEN as i32)) } != 0 {
        return Err(());
    }
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + IPV6_LEN > data_end {
        return Err(());
    }
    let p = data as *mut u8;
    unsafe {
        // Outer Ethernet: dst = underlay gateway MAC, src = our uplink MAC, ethertype IPv6.
        write6(p, &local.gateway_mac);
        write6(p.add(6), &local.uplink_mac);
        core::ptr::write_unaligned(p.add(12) as *mut u16, ETH_P_IPV6.to_be());
        // Outer IPv6.
        let ip = p.add(ETH_LEN);
        *ip.add(0) = 0x60;
        *ip.add(1) = 0;
        *ip.add(2) = 0;
        *ip.add(3) = 0;
        core::ptr::write_unaligned(ip.add(4) as *mut u16, inner_len.to_be());
        *ip.add(6) = IPPROTO_IPIP;
        *ip.add(7) = 64;
        write16(ip.add(8), &local.underlay_ipv6);
        write16(ip.add(24), &route.nexthop_ipv6);
    }
    Ok(unsafe { bpf_redirect(local.uplink_ifindex, 0) } as u32)
}
