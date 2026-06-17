#![cfg_attr(not(feature = "user"), no_std)]

/// Manual incremental checksum updates (XDP has no bpf_l3/l4_csum_replace helpers).
pub mod csum {
    #[inline(always)]
    fn fold(mut sum: u32) -> u16 {
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16
    }

    /// RFC 1624 incremental update of a 16-bit ones-complement checksum `check` (host order, i.e.
    /// already `u16::from_be`) when a 32-bit field changes from `old` to `new` (big-endian bytes).
    /// Returns the new checksum (host order) to store back as big-endian.
    ///
    /// HC' = ~( ~HC + ~m + m' ), summed over the two 16-bit words of the changed field.
    #[inline(always)]
    pub fn csum_replace4(check: u16, old: &[u8; 4], new: &[u8; 4]) -> u16 {
        let mut sum: u32 = (!check) as u32;
        sum += (!u16::from_be_bytes([old[0], old[1]])) as u32;
        sum += (!u16::from_be_bytes([old[2], old[3]])) as u32;
        sum += u16::from_be_bytes([new[0], new[1]]) as u32;
        sum += u16::from_be_bytes([new[2], new[3]]) as u32;
        !fold(sum)
    }
}

/// Key for the `interfaces` map: an overlay (VNI, IPv4) tuple.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct IfaceKey {
    pub vni: u32,
    pub ipv4: [u8; 4],
}

/// Value for the `interfaces` map: how to reach/deliver to an overlay IP.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct IfaceValue {
    /// Host-side tap ifindex for local delivery (0 if remote).
    pub tap_ifindex: u32,
    /// 1 = interface is local to this hypervisor, 0 = remote.
    pub is_local: u32,
    /// Underlay IPv6 endpoint of the owning hypervisor (tunnel dst for remote).
    pub underlay_ipv6: [u8; 16],
    /// Guest MAC (inner eth dst for local delivery).
    pub guest_mac: [u8; 6],
    pub _pad: [u8; 2],
}

/// Per-port metadata, keyed by the guest tap's host-side ifindex.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct PortMeta {
    pub vni: u32,
    pub guest_ipv4: [u8; 4],
    pub gateway_ipv4: [u8; 4],
    pub guest_mac: [u8; 6],
    pub _pad: [u8; 2],
}

impl IfaceKey {
    pub fn new(vni: u32, ipv4: [u8; 4]) -> Self {
        Self { vni, ipv4 }
    }
}

/// Key for the `routes` map: (VNI, IPv4 prefix). Host-order length in `prefix_len`.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct RouteKey {
    pub vni: u32,
    pub prefix_len: u32,
    pub ipv4: [u8; 4],
}

/// Value for the `routes` map: the underlay IPv6 nexthop (tunnel dst). MAC-free — the outer
/// L2 next-hop is the single underlay gateway in `Local`, not per-route.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct RouteValue {
    pub nexthop_vni: u32,
    pub nexthop_ipv6: [u8; 16],
}

/// This hypervisor's uplink + underlay gateway, written once into LOCAL[0] by the control plane.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct Local {
    pub uplink_ifindex: u32,
    pub uplink_mac: [u8; 6],
    /// Underlay next-hop (gateway/ToR router) MAC — outer eth dst for ALL encapped traffic.
    pub gateway_mac: [u8; 6],
    pub underlay_ipv6: [u8; 16],
}

/// Debug-only type for the `INSPECT` map: records the first 32 bytes of the first packet an
/// XDP program sees, plus the total length and a per-packet counter.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct InspectEntry {
    pub len: u32,
    pub seen: u32,
    pub bytes: [u8; 32],
}

/// Key for the `vips` map: (VNI, IPv4). Value is the mapped IPv4 (the 1:1 counterpart).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct VipKey {
    pub vni: u32,
    pub ipv4: [u8; 4],
}

/// Single-entry `CONFIG` map: per-hypervisor datapath parameters for the PoC's
/// CONFIG-driven single-peer overlay (one guest + one peer hypervisor). The XDP programs
/// read entry 0; the control plane populates it. MACs/ifindexes are filled at e2e time.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct Config {
    /// Overlay VNI this hypervisor's guest belongs to.
    pub vni: u32,
    /// ifindex of the underlay-facing uplink (encap redirect target).
    pub uplink_ifindex: u32,
    /// ifindex of the guest-facing tap/veth (decap redirect target).
    pub guest_ifindex: u32,
    pub _pad: u32,
    /// This hypervisor's underlay IPv6 (outer src on encap).
    pub local_underlay_ipv6: [u8; 16],
    /// The peer hypervisor's underlay IPv6 (outer dst on encap).
    pub peer_underlay_ipv6: [u8; 16],
    /// Uplink source MAC (outer eth src on encap).
    pub local_mac: [u8; 6],
    /// Peer uplink MAC (outer eth dst on encap).
    pub peer_mac: [u8; 6],
    /// Guest MAC (inner eth dst on decap delivery).
    pub guest_mac: [u8; 6],
    pub _pad2: [u8; 2],
}

#[cfg(feature = "user")]
mod user_impls {
    use super::*;
    unsafe impl aya::Pod for IfaceKey {}
    unsafe impl aya::Pod for IfaceValue {}
    unsafe impl aya::Pod for PortMeta {}
    unsafe impl aya::Pod for RouteKey {}
    unsafe impl aya::Pod for RouteValue {}
    unsafe impl aya::Pod for Config {}
    unsafe impl aya::Pod for Local {}
    unsafe impl aya::Pod for InspectEntry {}
    unsafe impl aya::Pod for VipKey {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iface_key_is_word_packed() {
        // POD layout must be stable for sharing with eBPF: 4 (vni) + 4 (ipv4).
        assert_eq!(core::mem::size_of::<IfaceKey>(), 8);
        let k = IfaceKey::new(100, [10, 0, 0, 5]);
        assert_eq!(k.vni, 100);
        assert_eq!(k.ipv4, [10, 0, 0, 5]);
    }

    #[test]
    fn route_types_have_stable_layout() {
        // 4 (vni) + 4 (prefix_len) + 4 (ipv4) = 12.
        // 4 (nexthop_vni) + 16 (ipv6) = 20.
        assert_eq!(core::mem::size_of::<RouteKey>(), 12);
        assert_eq!(core::mem::size_of::<RouteValue>(), 20);
        // 4 (uplink_ifindex) + 6 (uplink_mac) + 6 (gateway_mac) + 16 (underlay_ipv6) = 32.
        assert_eq!(core::mem::size_of::<Local>(), 32);
    }

    #[test]
    fn port_meta_and_iface_layout() {
        assert_eq!(core::mem::size_of::<PortMeta>(), 20);
        assert_eq!(core::mem::size_of::<IfaceValue>(), 32);
        assert_eq!(core::mem::align_of::<PortMeta>(), 4);
    }

    #[test]
    fn config_has_stable_layout() {
        // 4*4 (u32s) + 16 + 16 (underlays) + 6+6+6+2 (macs+pad) = 16 + 32 + 20 = 68.
        assert_eq!(core::mem::size_of::<Config>(), 68);
        assert_eq!(core::mem::align_of::<Config>(), 4);
    }

    #[test]
    fn vip_key_layout() {
        assert_eq!(core::mem::size_of::<VipKey>(), 8);
    }
}

#[cfg(test)]
mod csum_tests {
    use super::csum::csum_replace4;

    /// Full ones-complement checksum over a byte slice (16-bit words, big-endian), folded.
    fn full_csum(bytes: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < bytes.len() {
            sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
            i += 2;
        }
        if i < bytes.len() {
            sum += (bytes[i] as u32) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Build a minimal 20-byte IPv4 header with a correct checksum, then verify that changing the
    /// destination address via csum_replace4 yields the same checksum as a full recompute.
    #[test]
    fn ipv4_dst_change_matches_full_recompute() {
        // ver/ihl=0x45, tos=0, total_len=0x0054, id=0, flags/frag=0x4000, ttl=64, proto=1(ICMP),
        // checksum=0 (placeholder), src=10.0.0.5, dst=10.0.0.6
        let mut hdr: [u8; 20] = [
            0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 10, 0, 0, 5,
            10, 0, 0, 6,
        ];
        // initial correct checksum
        let init = full_csum(&hdr);
        hdr[10] = (init >> 8) as u8;
        hdr[11] = (init & 0xff) as u8;

        let old_dst = [hdr[16], hdr[17], hdr[18], hdr[19]];
        let new_dst = [10u8, 0, 0, 7];

        // incremental
        let inc = csum_replace4(u16::from_be_bytes([hdr[10], hdr[11]]), &old_dst, &new_dst);

        // apply change + full recompute (zero the checksum field first)
        hdr[16..20].copy_from_slice(&new_dst);
        hdr[10] = 0;
        hdr[11] = 0;
        let full = full_csum(&hdr);

        assert_eq!(inc, full, "incremental checksum must equal full recompute");
    }

    /// Also verify the round-trip: changing A->B then B->A restores the original checksum.
    #[test]
    fn round_trip_restores_checksum() {
        let a = [10u8, 0, 0, 5];
        let b = [192u8, 168, 1, 1];
        let start = 0x1234u16;
        let once = csum_replace4(start, &a, &b);
        let back = csum_replace4(once, &b, &a);
        assert_eq!(back, start);
    }
}
