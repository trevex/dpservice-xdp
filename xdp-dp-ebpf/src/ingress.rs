use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_redirect, bpf_xdp_adjust_head},
    programs::XdpContext,
};
use xdp_dp_common::{IfaceKey, CT_REWRITE_DST};

use crate::arp_nd::GW_MAC;
use crate::maps::INTERFACES;
use crate::parse::{write6, ETH_LEN, ETH_P_IP, ETH_P_IPV6, IPPROTO_IPIP, IPV6_LEN};

pub fn try_uplink_rx(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    // Need outer Eth(14) + IPv6(40) + at least the inner IPv4 dst (ends at +20).
    if data + ETH_LEN + IPV6_LEN + 20 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let p = data as *const u8;
    let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(12) as *const u16) });
    if ethertype != ETH_P_IPV6 {
        return Ok(xdp_action::XDP_PASS);
    }
    if unsafe { *p.add(ETH_LEN + 6) } != IPPROTO_IPIP {
        return Ok(xdp_action::XDP_PASS);
    }
    // Resolve the destination interface from the OUTER IPv6 dst (uniquely identifies the iface and
    // its VNI). This disambiguates overlapping overlay IPv4 across VNIs.
    let outer_dst = unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 24) as *const [u8; 16]) };
    let u = match unsafe { crate::maps::UNDERLAY.get(&outer_dst) } {
        Some(u) => *u,
        None => return Ok(xdp_action::XDP_PASS),
    };
    let vni = u.vni;
    // LB takes precedence: Maglev-select a backend (vni-scoped) and DNAT the inner header in place.
    let lb_backend = crate::lb::lb_select_dnat(ctx, ETH_LEN + IPV6_LEN, vni);
    // NAT reverse (and other CT_REWRITE_DST established returns): apply the stored translation.
    let nat_guest = if lb_backend.is_none() {
        let d = ctx.data();
        let de = ctx.data_end();
        match crate::conntrack::ct_key(d, de, ETH_LEN + IPV6_LEN, vni) {
            Some(key) => match unsafe { crate::maps::CONNTRACK.get(&key) } {
                Some(e) if e.flags & CT_REWRITE_DST != 0 => {
                    let mut e = *e;
                    crate::conntrack::ct_apply(ctx, ETH_LEN + IPV6_LEN, &e);
                    crate::conntrack::ct_touch(ctx, ETH_LEN + IPV6_LEN, &key, &mut e);
                    Some(e.xlate_ip)
                }
                _ => None,
            },
            None => None,
        }
    } else {
        None
    };
    // Delivery interface: LB backend's iface (vni-scoped) if LB matched, else the underlay-resolved
    // interface. (VIP DNAT of the inner header still happens post-adjust_head below.)
    let (tap_ifindex, guest_mac) = match lb_backend {
        Some(backend) => {
            let bi = unsafe { INTERFACES.get(&IfaceKey { vni, ipv4: backend }) }.ok_or(())?;
            if bi.is_local == 0 {
                return Ok(xdp_action::XDP_PASS);
            }
            (bi.tap_ifindex, bi.guest_mac)
        }
        None => (u.tap_ifindex, u.guest_mac),
    };

    // Ingress firewall: enforce the DESTINATION interface's INGRESS rules on NEW inbound flows
    // (established flows — including seeded returns — already have a conntrack entry, so they are
    // allowed without re-evaluation). Runs on the post-LB/NAT-DNAT inner 5-tuple.
    if let Some(key) = crate::conntrack::ct_key(ctx.data(), ctx.data_end(), ETH_LEN + IPV6_LEN, vni)
    {
        if unsafe { crate::maps::CONNTRACK.get(&key) }.is_none()
            && crate::firewall::fw_eval_dir(
                ctx.data(),
                ctx.data_end(),
                ETH_LEN + IPV6_LEN,
                tap_ifindex,
                xdp_dp_common::FW_DIR_INGRESS,
            ) == xdp_dp_common::FW_ACTION_DROP
            && crate::firewall::fw_enforcing()
        {
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // Track every flow: refresh an existing inbound DEFAULT entry, or create one on miss.
    // Only for non-LB/non-NAT flows; the inner IPv4 is at ETH_LEN + IPV6_LEN pre-adjust_head.
    if lb_backend.is_none() && nat_guest.is_none() {
        if let Some(key) =
            crate::conntrack::ct_key(ctx.data(), ctx.data_end(), ETH_LEN + IPV6_LEN, vni)
        {
            match unsafe { crate::maps::CONNTRACK.get(&key) } {
                Some(e) => {
                    let mut e = *e;
                    crate::conntrack::ct_touch(ctx, ETH_LEN + IPV6_LEN, &key, &mut e);
                }
                None => crate::conntrack::ct_ensure_default(ctx, ETH_LEN + IPV6_LEN, &key),
            }
        }
    }
    // Strip outer Eth+IPv6, leaving room to write the inner Ethernet.
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
        write6(q, &guest_mac);
        write6(q.add(6), &GW_MAC);
        core::ptr::write_unaligned(q.add(12) as *mut u16, ETH_P_IP.to_be());
    }
    // DNAT: rewrite inner IPv4 dest if inner_dst was a VIP (V->G). Skip for LB packets (already DNAT'd).
    if lb_backend.is_none() && nat_guest.is_none() {
        crate::vip::dnat_ingress(ctx, ETH_LEN, vni);
    }
    Ok(unsafe { bpf_redirect(tap_ifindex, 0) } as u32)
}
