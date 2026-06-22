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

/// clsact-ingress on a guest tap: host receives = guest egress. DHCP is tail-called to keep
/// verifier cost split, mirroring the XDP path. Phase 1 handles ONLY DHCP; forwarding/responders
/// land in later phases (everything else → TC_ACT_OK passthrough).
#[classifier]
pub fn tc_guest_tx(ctx: TcContext) -> i32 {
    // `__sk_buff.ifindex` is the receiving device on tc ingress (guest tap).
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    if unsafe { PORT_META.get(&ifindex) }.is_none() {
        return TC_ACT_OK;
    }
    if looks_like_dhcpv4(ctx.data(), ctx.data_end()) {
        let _ = unsafe { GUEST_PROGS_TC.tail_call(&ctx, xdp_dp_common::GUEST_PROG_DHCP) };
        return TC_ACT_OK; // tail-call miss → pass (mirrors XDP_PASS)
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
