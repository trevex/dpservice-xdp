use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_redirect, bpf_xdp_adjust_head},
    programs::XdpContext,
};
use xdp_dp_common::{PortMeta, RouteLpmData6};

use crate::arp_nd::GW_MAC;
use crate::encap::encap_and_redirect;
use crate::maps::{LOCAL, ROUTES6, UNDERLAY};
use crate::parse::{write6, ETH_LEN, ETH_P_IPV6, IPPROTO_IPV6, IPV6_LEN};

/// Egress for an inner IPv6 frame: route the inner v6 dst via ROUTES6 and encap (inner-proto 41).
#[inline(always)]
pub fn v6_guest_tx(ctx: &XdpContext, meta: &PortMeta) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + IPV6_LEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let p = data as *const u8;
    let dst = unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 24) as *const [u8; 16]) };
    let route = ROUTES6
        .get(&aya_ebpf::maps::lpm_trie::Key::new(
            160,
            RouteLpmData6 {
                vni: meta.vni.to_be_bytes(),
                ipv6: dst,
            },
        ))
        .ok_or(())?;
    let inner_len = (data_end - data - ETH_LEN) as u16;
    let local = LOCAL.get(0).ok_or(())?;
    encap_and_redirect(
        ctx,
        local,
        &meta.underlay_ipv6,
        route,
        inner_len,
        IPPROTO_IPV6,
    )
}

/// Ingress for an inner IPv6 frame (outer next-header 41): deliver by outer IPv6 dst, decap, write
/// the inner Ethernet (Ethertype IPv6), redirect to the tap.
#[inline(always)]
pub fn v6_uplink_rx(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + IPV6_LEN + 40 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let p = data as *const u8;
    let outer_dst = unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 24) as *const [u8; 16]) };
    let u = match unsafe { UNDERLAY.get(&outer_dst) } {
        Some(u) => *u,
        None => return Ok(xdp_action::XDP_PASS),
    };
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, IPV6_LEN as i32) } != 0 {
        return Err(());
    }
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN > data_end {
        return Err(());
    }
    let q = data as *mut u8;
    unsafe {
        write6(q, &u.guest_mac);
        write6(q.add(6), &GW_MAC);
        core::ptr::write_unaligned(q.add(12) as *mut u16, ETH_P_IPV6.to_be());
    }
    Ok(unsafe { bpf_redirect(u.tap_ifindex, 0) } as u32)
}
