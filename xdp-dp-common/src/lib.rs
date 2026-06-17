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

/// Ingress delivery entry: an interface's underlay IPv6 -> its VNI + local tap + guest MAC.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct UnderlayValue {
    pub vni: u32,
    pub tap_ifindex: u32,
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
    pub underlay_ipv6: [u8; 16],
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

/// LPM-trie key data for `ROUTES`: VNI (big-endian, matched MSB-first as a fixed 32-bit VRF
/// discriminator) followed by the IPv4 octets (network order, variable prefix).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct RouteLpmData {
    pub vni: [u8; 4],
    pub ipv4: [u8; 4],
}

/// Value for the `routes` map: the underlay IPv6 nexthop (tunnel dst). MAC-free — the outer
/// L2 next-hop is the single underlay gateway in `Local`, not per-route.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct RouteValue {
    pub nexthop_vni: u32,
    pub nexthop_ipv6: [u8; 16],
    /// 1 = the nexthop is the external/public network (NAT-eligible egress); 0 = overlay peer.
    pub is_external: u8,
    pub _pad: [u8; 3],
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

/// LB service key: (vni, balanced IPv4, L4 port, proto). proto: 6=TCP, 17=UDP, 1=ICMP.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct LbKey {
    pub vni: u32,
    pub ipv4: [u8; 4],
    pub port: u16,
    pub proto: u8,
    pub _pad: u8,
}

/// LB value: the Maglev table id + its size (number of slots).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct LbValue {
    pub table_id: u32,
    pub size: u32,
}

/// Maglev slot key: (table_id, slot). Value in the map is the backend IPv4 (`[u8;4]`).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct MaglevKey {
    pub table_id: u32,
    pub slot: u32,
}

/// Conntrack key: the VNI + 5-tuple (host-order ports; for ICMP the ports hold the id).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct CtKey {
    pub vni: u32,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
}

/// NAT-GW config key: (vni, local guest IPv4).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct NatKey {
    pub vni: u32,
    pub ipv4: [u8; 4],
}

/// NAT-GW config value: the public NAT IPv4 + the source-port range [port_min, port_max).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct NatValue {
    pub nat_ipv4: [u8; 4],
    pub port_min: u16,
    pub port_max: u16,
}

/// Unified conntrack entry value. Keyed by the 5-tuple (`CtKey`) of the packet that will be SEEN;
/// the datapath's `ct_apply` rewrites that packet's src or dst address (+L4 port) to
/// `xlate_ip`/`xlate_port`. Replaces the feature-private `CtVal`/`NatCtVal` (removed in M5 Task 3).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct CtEntry {
    pub last_seen: u64,
    pub xlate_ip: [u8; 4],
    pub xlate_port: u16,
    pub flags: u8,
    pub tcp_state: u8,
    pub fwall_action: u8,
    pub _pad: [u8; 7],
}

// CtEntry.flags bits
pub const CT_REWRITE_SRC: u8 = 0x01;
pub const CT_REWRITE_DST: u8 = 0x02;
pub const CT_F_SRC_NAT: u8 = 0x04;
pub const CT_F_DST_LB: u8 = 0x08;
pub const CT_F_DEFAULT: u8 = 0x10;
pub const CT_F_FIREWALL: u8 = 0x20;

// CtEntry.tcp_state values (mirror dpservice dp_flow_tcp_state)
pub const TCP_NONE: u8 = 0;
pub const TCP_NEW_SYN: u8 = 1;
pub const TCP_NEW_SYNACK: u8 = 2;
pub const TCP_ESTABLISHED: u8 = 3;
pub const TCP_FINWAIT: u8 = 4;
pub const TCP_RST_FIN: u8 = 5;

/// Max firewall rules scanned per interface per direction in the datapath (bounded loop).
pub const FW_MAX_RULES: u32 = 16;

/// Firewall rule slot key: (interface ifindex, slot index 0..FW_MAX_RULES).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct FwRuleKey {
    pub ifindex: u32,
    pub idx: u32,
}

/// A single firewall rule (fixed-size POD). Ports are inclusive ranges (0..=65535 = any);
/// icmp_type/icmp_code 0xffff = any; proto 0 = any; action 1=accept/0=drop; direction
/// 1=egress/0=ingress; enabled 1 = slot in use.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct FwRule {
    pub src_ip: [u8; 4],
    pub src_mask: [u8; 4],
    pub dst_ip: [u8; 4],
    pub dst_mask: [u8; 4],
    pub src_port_min: u16,
    pub src_port_max: u16,
    pub dst_port_min: u16,
    pub dst_port_max: u16,
    pub icmp_type: u16,
    pub icmp_code: u16,
    pub proto: u8,
    pub action: u8,
    pub direction: u8,
    pub enabled: u8,
}

/// Per-interface rule counts (so empty-direction => ACCEPT can be decided cheaply).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct FwMeta {
    pub ingress_count: u32,
    pub egress_count: u32,
}

pub const FW_DIR_INGRESS: u8 = 0;
pub const FW_DIR_EGRESS: u8 = 1;
pub const FW_ACTION_DROP: u8 = 0;
pub const FW_ACTION_ACCEPT: u8 = 1;

/// Maximum number of neighbor-NAT entries the datapath will scan.
pub const NB_MAX_ENTRIES: u32 = 64;

/// A neighbor-NAT entry: a remote node owns `(vni, nat_ip, [port_min, port_max))`; return traffic
/// to that nat_ip:port is re-forwarded to `underlay`. `enabled` 1 = slot in use.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct NeighborNatEntry {
    pub underlay: [u8; 16],
    pub nat_ip: [u8; 4],
    pub vni: u32,
    pub port_min: u16,
    pub port_max: u16,
    pub enabled: u8,
    pub _pad: [u8; 3],
}

/// Pure firewall match (no_std; used by the datapath and host-tested). Returns true if `r` matches
/// the packet selectors. `icmp_type`/`icmp_code` are ignored unless `proto == 1`.
#[inline]
pub fn fw_rule_matches(
    r: &FwRule,
    src: &[u8; 4],
    dst: &[u8; 4],
    proto: u8,
    sport: u16,
    dport: u16,
    icmp_type: u16,
    icmp_code: u16,
) -> bool {
    if r.enabled == 0 {
        return false;
    }
    if r.proto != 0 && r.proto != proto {
        return false;
    }
    for i in 0..4 {
        if src[i] & r.src_mask[i] != r.src_ip[i] & r.src_mask[i] {
            return false;
        }
        if dst[i] & r.dst_mask[i] != r.dst_ip[i] & r.dst_mask[i] {
            return false;
        }
    }
    match proto {
        6 | 17 => {
            sport >= r.src_port_min
                && sport <= r.src_port_max
                && dport >= r.dst_port_min
                && dport <= r.dst_port_max
        }
        1 => {
            (r.icmp_type == 0xffff || icmp_type == r.icmp_type)
                && (r.icmp_code == 0xffff || icmp_code == r.icmp_code)
        }
        _ => true,
    }
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
    unsafe impl aya::Pod for UnderlayValue {}
    unsafe impl aya::Pod for PortMeta {}
    unsafe impl aya::Pod for RouteKey {}
    unsafe impl aya::Pod for RouteLpmData {}
    unsafe impl aya::Pod for RouteValue {}
    unsafe impl aya::Pod for Config {}
    unsafe impl aya::Pod for Local {}
    unsafe impl aya::Pod for InspectEntry {}
    unsafe impl aya::Pod for VipKey {}
    unsafe impl aya::Pod for LbKey {}
    unsafe impl aya::Pod for LbValue {}
    unsafe impl aya::Pod for MaglevKey {}
    unsafe impl aya::Pod for CtKey {}
    unsafe impl aya::Pod for NatKey {}
    unsafe impl aya::Pod for NatValue {}
    unsafe impl aya::Pod for CtEntry {}
    unsafe impl aya::Pod for FwRuleKey {}
    unsafe impl aya::Pod for FwRule {}
    unsafe impl aya::Pod for FwMeta {}
    unsafe impl aya::Pod for NeighborNatEntry {}
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
        // 4 (nexthop_vni) + 16 (ipv6) + 1 (is_external) + 3 (_pad) = 24.
        assert_eq!(core::mem::size_of::<RouteKey>(), 12);
        assert_eq!(core::mem::size_of::<RouteValue>(), 24);
        // 4 (uplink_ifindex) + 6 (uplink_mac) + 6 (gateway_mac) + 16 (underlay_ipv6) = 32.
        assert_eq!(core::mem::size_of::<Local>(), 32);
        // LPM key data: 4 (vni be) + 4 (ipv4) = 8.
        assert_eq!(core::mem::size_of::<RouteLpmData>(), 8);
    }

    #[test]
    fn port_meta_and_iface_layout() {
        assert_eq!(core::mem::size_of::<PortMeta>(), 36);
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

    #[test]
    fn lb_ct_layouts() {
        assert_eq!(core::mem::size_of::<LbKey>(), 12);
        assert_eq!(core::mem::size_of::<LbValue>(), 8);
        assert_eq!(core::mem::size_of::<MaglevKey>(), 8);
        assert_eq!(core::mem::size_of::<CtKey>(), 20);
        assert_eq!(core::mem::size_of::<UnderlayValue>(), 16);
    }

    #[test]
    fn nat_layouts() {
        assert_eq!(core::mem::size_of::<NatKey>(), 8);
        assert_eq!(core::mem::size_of::<NatValue>(), 8);
    }

    #[test]
    fn ct_entry_layout() {
        // 8 (last_seen) + 4 (xlate_ip) + 2 (xlate_port) + 1 (flags) + 1 (tcp_state)
        // + 1 (fwall_action) + 7 (_pad) = 24, u64-aligned.
        assert_eq!(core::mem::size_of::<CtEntry>(), 24);
    }

    #[test]
    fn fw_types_layout() {
        // 4 (ifindex) + 4 (idx) = 8.
        assert_eq!(core::mem::size_of::<FwRuleKey>(), 8);
        // 4*4 (ip/mask pairs) + 4*2 (port ranges) + 2+2 (icmp) + 4 (proto/action/dir/enabled) = 32.
        assert_eq!(core::mem::size_of::<FwRule>(), 32);
        // 4 (ingress_count) + 4 (egress_count) = 8.
        assert_eq!(core::mem::size_of::<FwMeta>(), 8);
    }

    #[test]
    fn neighbor_nat_entry_layout() {
        // 16 (underlay) + 4 (nat_ip) + 4 (vni) + 2 (port_min) + 2 (port_max)
        // + 1 (enabled) + 3 (_pad) = 32.
        assert_eq!(core::mem::size_of::<NeighborNatEntry>(), 32);
        assert_eq!(core::mem::align_of::<NeighborNatEntry>(), 4);
    }

    #[test]
    fn fw_match_proto_and_ports() {
        let r = FwRule {
            src_ip: [0, 0, 0, 0],
            src_mask: [0, 0, 0, 0],
            dst_ip: [10, 0, 0, 5],
            dst_mask: [255, 255, 255, 255],
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: 80,
            dst_port_max: 80,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            proto: 6,
            action: FW_ACTION_ACCEPT,
            direction: FW_DIR_INGRESS,
            enabled: 1,
        };
        assert!(fw_rule_matches(
            &r,
            &[1, 2, 3, 4],
            &[10, 0, 0, 5],
            6,
            12345,
            80,
            0,
            0
        ));
        assert!(!fw_rule_matches(
            &r,
            &[1, 2, 3, 4],
            &[10, 0, 0, 5],
            6,
            12345,
            81,
            0,
            0
        ));
        assert!(!fw_rule_matches(
            &r,
            &[1, 2, 3, 4],
            &[10, 0, 0, 5],
            17,
            12345,
            80,
            0,
            0
        ));
        assert!(!fw_rule_matches(
            &r,
            &[1, 2, 3, 4],
            &[10, 0, 0, 6],
            6,
            12345,
            80,
            0,
            0
        ));
    }

    #[test]
    fn fw_match_icmp_and_any() {
        let r = FwRule {
            src_ip: [0; 4],
            src_mask: [0; 4],
            dst_ip: [0; 4],
            dst_mask: [0; 4],
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: 0,
            dst_port_max: 65535,
            icmp_type: 8,
            icmp_code: 0xffff,
            proto: 1,
            action: FW_ACTION_ACCEPT,
            direction: FW_DIR_INGRESS,
            enabled: 1,
        };
        assert!(fw_rule_matches(
            &r,
            &[1, 1, 1, 1],
            &[2, 2, 2, 2],
            1,
            0,
            0,
            8,
            0
        ));
        assert!(!fw_rule_matches(
            &r,
            &[1, 1, 1, 1],
            &[2, 2, 2, 2],
            1,
            0,
            0,
            0,
            0
        ));
        let mut d = r;
        d.enabled = 0;
        assert!(!fw_rule_matches(
            &d,
            &[1, 1, 1, 1],
            &[2, 2, 2, 2],
            1,
            0,
            0,
            8,
            0
        ));
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
