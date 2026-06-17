use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use xdp_dp_common::PortMeta;

use crate::parse::{write6, ETH_LEN, ETH_P_ARP};

/// Virtual gateway MAC the datapath answers ARP with (and uses as inner-eth src on delivery).
pub const GW_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

// ARP (Ethernet/IPv4) field offsets, relative to the ARP header start (= ETH_LEN):
//   opcode @ 6 (2B; 1=request, 2=reply)
//   sha    @ 8 (6B, sender hw addr)
//   spa    @ 14 (4B, sender proto addr)
//   tha    @ 18 (6B, target hw addr)
//   tpa    @ 24 (4B, target proto addr)
const ARP_LEN: usize = 28;

/// If the frame is an ARP request for `meta.gateway_ipv4`, rewrite it in place into an ARP
/// reply (from GW_MAC / gateway IP) and return `Some(XDP_TX)`. Otherwise return `None` and the
/// caller continues its pipeline.
#[inline(always)]
pub fn try_arp_reply(ctx: &XdpContext, meta: &PortMeta) -> Option<u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + ARP_LEN > data_end {
        return None;
    }
    let p = data as *mut u8;
    let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(12) as *const u16) });
    if ethertype != ETH_P_ARP {
        return None;
    }
    let arp = unsafe { p.add(ETH_LEN) };
    let opcode = u16::from_be(unsafe { core::ptr::read_unaligned(arp.add(6) as *const u16) });
    if opcode != 1 {
        return None;
    }
    let tpa = unsafe { core::ptr::read_unaligned(arp.add(24) as *const [u8; 4]) };
    if tpa != meta.gateway_ipv4 {
        return None;
    }
    // Capture requester fields before overwriting.
    let sender_mac = unsafe { core::ptr::read_unaligned(arp.add(8) as *const [u8; 6]) };
    let spa = unsafe { core::ptr::read_unaligned(arp.add(14) as *const [u8; 4]) };
    unsafe {
        // Ethernet: dst = requester MAC, src = gateway MAC.
        write6(p, &sender_mac);
        write6(p.add(6), &GW_MAC);
        // ARP: opcode = reply(2); sha = GW_MAC, spa = gateway IP; tha = requester MAC, tpa = requester IP.
        core::ptr::write_unaligned(arp.add(6) as *mut u16, 2u16.to_be());
        write6(arp.add(8), &GW_MAC);
        core::ptr::write_unaligned(arp.add(14) as *mut [u8; 4], meta.gateway_ipv4);
        write6(arp.add(18), &sender_mac);
        core::ptr::write_unaligned(arp.add(24) as *mut [u8; 4], spa);
    }
    Some(xdp_action::XDP_TX)
}
