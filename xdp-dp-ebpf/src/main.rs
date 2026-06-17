#![no_std]
#![no_main]

mod arp_nd;
mod egress;
mod encap;
mod ingress;
mod inspect;
mod maps;
mod parse;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

/// Trivial pass program used as a redirect-target enabler: XDP redirect *into* a veth only
/// works if the veth's peer has an XDP program attached. Attach this on those receiving ends.
#[xdp]
pub fn xdp_pass(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

#[xdp]
pub fn guest_tx(ctx: XdpContext) -> u32 {
    match egress::try_guest_tx(&ctx) {
        Ok(act) => act,
        Err(()) => xdp_action::XDP_PASS,
    }
}

#[xdp]
pub fn uplink_rx(ctx: XdpContext) -> u32 {
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
