use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use xdp_dp_common::RouteKey;

use crate::arp_nd::try_arp_reply;
use crate::encap::encap_and_redirect;
use crate::maps::{LOCAL, PORT_META, ROUTES};
use crate::parse::{ETH_LEN, ETH_P_IP};

pub fn try_guest_tx(ctx: &XdpContext) -> Result<u32, ()> {
    // Identify the port by its ingress ifindex.
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let meta = unsafe { PORT_META.get(&ifindex) }.ok_or(())?;

    // Answer ARP for the gateway in-datapath.
    if let Some(act) = try_arp_reply(ctx, meta) {
        return Ok(act);
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + 20 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let p = data as *const u8;
    let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(12) as *const u16) });
    if ethertype != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }
    // Conntrack: apply any established translation (LB reverse; later NAT/DEFAULT) before SNAT/route.
    if let Some(key) = crate::conntrack::ct_key(data, data_end, ETH_LEN) {
        if let Some(e) = unsafe { crate::maps::CONNTRACK.get(&key) } {
            let mut e = *e;
            crate::conntrack::ct_apply(ctx, ETH_LEN, &e);
            crate::conntrack::ct_touch(ctx, ETH_LEN, &key, &mut e);
        }
    }
    // SNAT: rewrite inner IPv4 source if a VIP mapping exists (G->V).
    crate::vip::snat_egress(ctx, ETH_LEN, meta.vni);
    // inner IPv4 dst at ETH_LEN + 16
    let dst = unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 16) as *const [u8; 4]) };
    let route = unsafe {
        ROUTES.get(&RouteKey {
            vni: meta.vni,
            prefix_len: 32,
            ipv4: dst,
        })
    }
    .ok_or(())?;
    // Network NAT: SNAT guest -> nat_ip:port when the dst route is external and the guest has a
    // NAT config. Rewrites the packet in place; the route (dst unchanged) still encaps correctly.
    let is_ext = route.is_external != 0;
    crate::nat::nat_snat_egress(ctx, ETH_LEN, meta.vni, is_ext);
    // Track every flow: if no conntrack entry exists for this (post-NAT) 5-tuple, insert DEFAULT.
    if let Some(key) = crate::conntrack::ct_key(ctx.data(), ctx.data_end(), ETH_LEN) {
        if unsafe { crate::maps::CONNTRACK.get(&key) }.is_none() {
            crate::conntrack::ct_ensure_default(ctx, ETH_LEN, &key);
        }
    }
    let inner_len = (data_end - data - ETH_LEN) as u16;
    let local = LOCAL.get(0).ok_or(())?;
    encap_and_redirect(ctx, local, route, inner_len)
}
