#![no_std]
#![no_main]

mod arp_nd;
mod encap;
mod maps;
mod parse;

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_redirect, bpf_xdp_adjust_head},
    macros::xdp,
    programs::XdpContext,
};
use maps::CONFIG;
use parse::{write16, write6, ETH_LEN, ETH_P_IP, ETH_P_IPV6, IPPROTO_IPIP, IPV6_LEN};

/// Trivial pass program used as a redirect-target enabler: XDP redirect *into* a veth only
/// works if the veth's peer has an XDP program attached. Attach this on those receiving ends.
#[xdp]
pub fn xdp_pass(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

#[xdp]
pub fn guest_tx(ctx: XdpContext) -> u32 {
    match try_guest_tx(&ctx) {
        Ok(act) => act,
        Err(()) => xdp_action::XDP_PASS,
    }
}

fn try_guest_tx(ctx: &XdpContext) -> Result<u32, ()> {
    let cfg = CONFIG.get(0).ok_or(())?;

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let p = data as *const u8;
    let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(12) as *const u16) });
    if ethertype != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }
    let inner_len = (data_end - data - ETH_LEN) as u16;

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
        write6(p, &cfg.peer_mac);
        write6(p.add(6), &cfg.local_mac);
        core::ptr::write_unaligned(p.add(12) as *mut u16, ETH_P_IPV6.to_be());
        let ip = p.add(ETH_LEN);
        *ip.add(0) = 0x60;
        *ip.add(1) = 0x00;
        *ip.add(2) = 0x00;
        *ip.add(3) = 0x00;
        core::ptr::write_unaligned(ip.add(4) as *mut u16, inner_len.to_be());
        *ip.add(6) = IPPROTO_IPIP;
        *ip.add(7) = 64;
        write16(ip.add(8), &cfg.local_underlay_ipv6);
        write16(ip.add(24), &cfg.peer_underlay_ipv6);
    }
    Ok(unsafe { bpf_redirect(cfg.uplink_ifindex, 0) } as u32)
}

#[xdp]
pub fn uplink_rx(ctx: XdpContext) -> u32 {
    match try_uplink_rx(&ctx) {
        Ok(act) => act,
        Err(()) => xdp_action::XDP_PASS,
    }
}

fn try_uplink_rx(ctx: &XdpContext) -> Result<u32, ()> {
    let cfg = CONFIG.get(0).ok_or(())?;

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + IPV6_LEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let p = data as *const u8;
    let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(12) as *const u16) });
    if ethertype != ETH_P_IPV6 {
        return Ok(xdp_action::XDP_PASS);
    }
    let next_hdr = unsafe { *p.add(ETH_LEN + 6) };
    if next_hdr != IPPROTO_IPIP {
        return Ok(xdp_action::XDP_PASS);
    }

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
        write6(q, &cfg.guest_mac);
        write6(q.add(6), &cfg.local_mac);
        core::ptr::write_unaligned(q.add(12) as *mut u16, ETH_P_IP.to_be());
    }
    Ok(unsafe { bpf_redirect(cfg.guest_ifindex, 0) } as u32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
