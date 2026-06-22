#![no_std]
#![no_main]

mod arp_nd;
mod conntrack;
mod csum;
mod dbg;
mod dhcp;
mod egress;
mod encap;
mod firewall;
mod ingress;
mod inspect;
mod lb;
mod maps;
mod meter;
mod nat;
mod nat64;
mod parse;
mod v6;
mod verdict;
mod vip;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

/// Trivial pass program used as a redirect-target enabler: XDP redirect *into* a veth only
/// works if the veth's peer has an XDP program attached. Attach this on those receiving ends.
#[xdp]
pub fn xdp_pass(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

#[xdp]
pub fn guest_tx(ctx: XdpContext) -> u32 {
    dbg::dlog!(&ctx, "guest_tx: ingress_ifindex={}", unsafe {
        (*ctx.ctx).ingress_ifindex
    });
    match egress::try_guest_tx(&ctx) {
        Ok(act) => {
            dbg::dlog!(&ctx, "guest_tx: action={}", act);
            act
        }
        Err(()) => xdp_action::XDP_PASS,
    }
}

#[xdp]
pub fn guest_dhcp(ctx: XdpContext) -> u32 {
    dbg::dlog!(&ctx, "guest_dhcp: tail-call entered");
    let act = egress::dhcp_handle(&ctx);
    dbg::dlog!(&ctx, "guest_dhcp: action={}", act);
    act
}

#[xdp]
pub fn uplink_rx(ctx: XdpContext) -> u32 {
    dbg::dlog!(&ctx, "uplink_rx: ingress_ifindex={}", unsafe {
        (*ctx.ctx).ingress_ifindex
    });
    match ingress::try_uplink_rx(&ctx) {
        Ok(act) => act,
        Err(()) => xdp_action::XDP_PASS,
    }
}

#[xdp]
pub fn xdp_inspect(ctx: XdpContext) -> u32 {
    inspect::try_inspect(&ctx)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
