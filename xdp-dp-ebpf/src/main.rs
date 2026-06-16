#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

#[xdp]
pub fn uplink_rx(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

#[xdp]
pub fn guest_tx(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Declare a GPL-compatible license so GPL-only helpers (bpf_redirect, bpf_fib_lookup, used
// from Task 11 onward) are permitted by the verifier. edition-2021 attribute spelling.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
