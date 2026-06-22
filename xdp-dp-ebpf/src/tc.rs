//! tc (clsact ingress) glue for the guest edge. Mirrors the XDP guest_tx/guest_dhcp split but uses
//! skb primitives (pull_data/change_tail) and tc return codes, and replies to the guest by
//! redirecting back out the tap. The heavy logic lives in the shared pure core (xdp_dp_common::dhcp).

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    helpers::{bpf_redirect, bpf_skb_change_tail},
    macros::classifier,
    programs::TcContext,
};

use crate::dhcp::{gather_dhcpv4_reply, learn_mac};
use crate::maps::{GUEST_PROGS_TC, PORT_META};
use xdp_dp_common::dhcp::{
    looks_like_dhcpv4, parse_dhcpv4_request, write_dhcpv4_reply, MIN_DHCP_LEN, REPLY_LEN,
};

// `aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_SHOT}` are already `i32` (the verdict type a
// `#[classifier]` returns), so they're used directly below.

/// clsact-ingress on a guest tap: host receives = guest egress. ARP + IPv6 ND are answered
/// in place (redirect back to guest); DHCP is tail-called. Everything else → TC_ACT_OK passthrough.
#[classifier]
pub fn tc_guest_tx(ctx: TcContext) -> i32 {
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    let meta = match unsafe { PORT_META.get(&ifindex) } {
        Some(m) => *m,
        None => return TC_ACT_OK,
    };
    // Bounds-checked ethertype read (classification only).
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + 14 > data_end {
        return TC_ACT_OK;
    }
    let ethertype = u16::from_be(unsafe {
        core::ptr::read_unaligned((data as *const u8).add(12) as *const u16)
    });

    // ARP request for the gateway → reply in place, redirect back to the guest.
    if ethertype == xdp_dp_common::arp_nd::ETH_P_ARP {
        if ctx
            .pull_data((xdp_dp_common::arp_nd::ETH_LEN + xdp_dp_common::arp_nd::ARP_LEN) as u32)
            .is_ok()
            && unsafe {
                xdp_dp_common::arp_nd::try_write_arp_reply(
                    ctx.data(),
                    ctx.data_end(),
                    meta.gateway_ipv4,
                    meta.guest_mac,
                )
            }
        {
            return unsafe { bpf_redirect(ifindex, 0) as i32 };
        }
        return TC_ACT_OK;
    }

    // IPv6 → may be an ND Neighbor Solicitation for the gateway.
    if ethertype == xdp_dp_common::arp_nd::ETH_P_IPV6 {
        const ND_FRAME: usize =
            xdp_dp_common::arp_nd::ETH_LEN + xdp_dp_common::arp_nd::IPV6_LEN + 32;
        if ctx.pull_data(ND_FRAME as u32).is_ok()
            && unsafe {
                xdp_dp_common::arp_nd::try_write_nd_reply(
                    ctx.data(),
                    ctx.data_end(),
                    meta.gateway_ipv6,
                    meta.guest_mac,
                )
            }
        {
            return unsafe { bpf_redirect(ifindex, 0) as i32 };
        }
        // fall through (other IPv6, incl. DHCPv6 — handled in a later phase)
    }

    // DHCPv4 → tail-call the dedicated responder.
    if looks_like_dhcpv4(ctx.data(), ctx.data_end()) {
        let _ = unsafe { GUEST_PROGS_TC.tail_call(&ctx, xdp_dp_common::GUEST_PROG_DHCP) };
        return TC_ACT_OK;
    }
    TC_ACT_OK
}

/// tc DHCP responder: build the OFFER/ACK into the (resized) skb and redirect it back to the guest.
#[classifier]
pub fn tc_guest_dhcp(ctx: TcContext) -> i32 {
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    let meta = match unsafe { PORT_META.get(&ifindex) } {
        Some(m) => *m,
        None => return TC_ACT_OK,
    };
    // Make the request head writable/linear so the parse works on direct packet access. A DISCOVER
    // is typically SHORTER than REPLY_LEN (e.g. ~286B vs 428B), so pulling REPLY_LEN here fails
    // (bpf_skb_pull_data cannot pull past skb->len) and we'd bail before ever growing the skb.
    // Pull only the fixed DHCP header (MIN_DHCP_LEN), which every valid request carries; the skb is
    // grown to REPLY_LEN and re-pulled below, before the reply is written.
    if ctx.pull_data(MIN_DHCP_LEN as u32).is_err() {
        return TC_ACT_OK;
    }
    let req = match parse_dhcpv4_request(ctx.data(), ctx.data_end()) {
        Some(r) => r,
        None => return TC_ACT_OK,
    };
    learn_mac(ifindex, &meta, req.client_mac);
    let r = gather_dhcpv4_reply(&req, &meta, ifindex);
    // Resize the skb to REPLY_LEN, then re-establish writability (change_tail invalidates bounds).
    let cur = (ctx.data_end() - ctx.data()) as u32;
    if cur != REPLY_LEN as u32
        && unsafe { bpf_skb_change_tail(ctx.skb.skb, REPLY_LEN as u32, 0) } != 0
    {
        return TC_ACT_OK;
    }
    if ctx.pull_data(REPLY_LEN as u32).is_err() {
        return TC_ACT_OK;
    }
    if unsafe { write_dhcpv4_reply(ctx.data(), ctx.data_end(), &r) }.is_none() {
        return TC_ACT_SHOT;
    }
    // Reply to the guest: redirect back out the tap we arrived on (egress = toward guest).
    // In tc, bpf_redirect returns TC_ACT_REDIRECT, which is the correct return value.
    unsafe { bpf_redirect(ifindex, 0) as i32 }
}
