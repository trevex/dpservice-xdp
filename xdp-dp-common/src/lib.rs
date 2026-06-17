#![cfg_attr(not(feature = "user"), no_std)]

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

/// Value for the `routes` map: how to reach the overlay prefix's nexthop on the underlay.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct RouteValue {
    pub nexthop_vni: u32,
    pub nexthop_ipv6: [u8; 16],
    /// Underlay MAC of the nexthop hypervisor's uplink (outer eth dst on encap).
    pub nexthop_mac: [u8; 6],
    pub _pad: [u8; 2],
}

/// This hypervisor's uplink, written once by the control plane into `LOCAL[0]`.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct Local {
    pub uplink_ifindex: u32,
    pub uplink_mac: [u8; 6],
    pub _pad: [u8; 2],
    pub underlay_ipv6: [u8; 16],
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
        // 4 (nexthop_vni) + 16 (ipv6) + 6 (mac) + 2 (pad) = 28.
        assert_eq!(core::mem::size_of::<RouteKey>(), 12);
        assert_eq!(core::mem::size_of::<RouteValue>(), 28);
        // 4 (uplink_ifindex) + 6 (uplink_mac) + 2 (pad) + 16 (underlay_ipv6) = 28.
        assert_eq!(core::mem::size_of::<Local>(), 28);
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
}
