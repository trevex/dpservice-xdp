#![cfg_attr(not(feature = "user"), no_std)]

/// Key for the `interfaces` map: an overlay (VNI, IPv4) tuple.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct IfaceKey {
    pub vni: u32,
    pub ipv4: [u8; 4],
}

/// Value for the `interfaces` map: where to deliver/encap for this overlay IP.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct IfaceValue {
    /// Host-side tap ifindex for local delivery (0 if remote-only).
    pub tap_ifindex: u32,
    /// Underlay IPv6 endpoint of the owning hypervisor (the tunnel dst).
    pub underlay_ipv6: [u8; 16],
}

impl IfaceKey {
    pub fn new(vni: u32, ipv4: [u8; 4]) -> Self {
        Self { vni, ipv4 }
    }
}

#[cfg(feature = "user")]
mod user_impls {
    use super::*;
    unsafe impl aya::Pod for IfaceKey {}
    unsafe impl aya::Pod for IfaceValue {}
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
}
