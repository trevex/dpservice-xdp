#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use xdp_dp_common::{IfaceKey, IfaceValue, RouteKey, RouteValue};

/// Overlay (VNI, IPv4) -> local tap ifindex + owning hypervisor underlay endpoint.
/// Written by the userspace control plane; read by the XDP datapath (Task 11+).
#[map]
static INTERFACES: HashMap<IfaceKey, IfaceValue> = HashMap::with_max_entries(1024, 0);

/// Overlay (VNI, IPv4 prefix) -> underlay IPv6 nexthop (tunnel dst).
#[map]
static ROUTES: HashMap<RouteKey, RouteValue> = HashMap::with_max_entries(4096, 0);

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
