use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use xdp_dp_common::PortMeta;

use crate::parse::{write16, write6, ETH_LEN, ETH_P_ARP, IPPROTO_ICMPV6, IPV6_LEN};

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
    // dpservice presents the virtual gateway to each VF using that VF's OWN MAC (point-to-point
    // L2), so the guest caches the gateway at its own MAC. Answer ARP with the guest's MAC.
    let gw_mac = meta.guest_mac;
    unsafe {
        // Ethernet: dst = requester MAC, src = gateway MAC (= guest's own MAC).
        write6(p, &sender_mac);
        write6(p.add(6), &gw_mac);
        // ARP: opcode = reply(2); sha = gw_mac, spa = gateway IP; tha = requester MAC, tpa = requester IP.
        core::ptr::write_unaligned(arp.add(6) as *mut u16, 2u16.to_be());
        write6(arp.add(8), &gw_mac);
        core::ptr::write_unaligned(arp.add(14) as *mut [u8; 4], meta.gateway_ipv4);
        write6(arp.add(18), &sender_mac);
        core::ptr::write_unaligned(arp.add(24) as *mut [u8; 4], spa);
    }
    Some(xdp_action::XDP_TX)
}

const ND_NS: u8 = 135;
const ND_NA: u8 = 136;

/// One's-complement checksum over `len` bytes at `ptr`, plus an initial `sum` (pseudo-header).
#[inline(always)]
unsafe fn csum16(mut sum: u32, ptr: *const u8, len: usize) -> u16 {
    let mut i = 0;
    while i + 1 < len {
        sum += u16::from_be(core::ptr::read_unaligned(ptr.add(i) as *const u16)) as u32;
        i += 2;
    }
    if i < len {
        sum += (*ptr.add(i) as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// If the frame is an ICMPv6 Neighbor Solicitation for `meta.gateway_ipv6`, rewrite it in place
/// into a solicited Neighbor Advertisement from GW_MAC and return Some(XDP_TX). NS/NA are a fixed
/// size here (40 IPv6 + 32 ICMPv6) so all accesses are constant-offset (verifier-friendly).
#[inline(always)]
pub fn try_nd_reply(ctx: &XdpContext, meta: &PortMeta) -> Option<u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + IPV6_LEN + 32 > data_end {
        return None;
    }
    let p = data as *mut u8;
    let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(12) as *const u16) });
    if ethertype != crate::parse::ETH_P_IPV6 {
        return None;
    }
    let ip = unsafe { p.add(ETH_LEN) };
    if unsafe { *ip.add(6) } != IPPROTO_ICMPV6 {
        return None;
    }
    let icmp = unsafe { p.add(ETH_LEN + IPV6_LEN) };
    if unsafe { *icmp } != ND_NS {
        return None;
    }
    let target = unsafe { core::ptr::read_unaligned(icmp.add(8) as *const [u8; 16]) };
    if target != meta.gateway_ipv6 {
        return None;
    }
    let req_mac = unsafe { core::ptr::read_unaligned(p as *const [u8; 6]) };
    let req_src = unsafe { core::ptr::read_unaligned(ip.add(8) as *const [u8; 16]) };
    // Like ARP, present the virtual v6 gateway to the VF using the guest's own MAC.
    let gw_mac = meta.guest_mac;
    unsafe {
        write6(p, &req_mac);
        write6(p.add(6), &gw_mac);
        write16(ip.add(8), &meta.gateway_ipv6);
        write16(ip.add(24), &req_src);
        *ip.add(7) = 255;
        core::ptr::write_unaligned(ip.add(4) as *mut u16, 32u16.to_be());
        *icmp = ND_NA;
        *icmp.add(1) = 0;
        core::ptr::write_unaligned(icmp.add(2) as *mut u16, 0);
        *icmp.add(4) = 0x60;
        *icmp.add(5) = 0;
        *icmp.add(6) = 0;
        *icmp.add(7) = 0;
        // target @ +8 stays = gateway. Option @ +24: type=2 (target LL addr), len=1, gw_mac.
        *icmp.add(24) = 2;
        *icmp.add(25) = 1;
        write6(icmp.add(26), &gw_mac);
        let mut sum: u32 = 0;
        let mut k = 0;
        while k < 16 {
            sum += u16::from_be(core::ptr::read_unaligned(ip.add(8 + k) as *const u16)) as u32;
            sum += u16::from_be(core::ptr::read_unaligned(ip.add(24 + k) as *const u16)) as u32;
            k += 2;
        }
        sum += 32u32;
        sum += IPPROTO_ICMPV6 as u32;
        let cks = csum16(sum, icmp as *const u8, 32);
        core::ptr::write_unaligned(icmp.add(2) as *mut u16, cks.to_be());
    }
    Some(xdp_action::XDP_TX)
}
