use anyhow::Context;
use aya::maps::{
    lpm_trie::{Key, LpmTrie},
    Array, HashMap, MapData,
};
use aya::Ebpf;
use xdp_dp_common::{
    Config, CtEntry, CtKey, FwMeta, FwRule, FwRuleKey, IfaceKey, IfaceValue, InspectEntry, LbKey,
    LbValue, Local, MaglevKey, NatKey, NatValue, NeighborNatEntry, PortMeta, RouteLpmData,
    RouteValue, UnderlayValue, VipKey,
};

/// Typed handle over the `INTERFACES` BPF map (overlay (VNI, IPv4) -> delivery info).
// Exercised by the roundtrip test now; wired into the gRPC control plane in Task 12.
#[allow(dead_code)]
pub struct Interfaces {
    map: HashMap<MapData, IfaceKey, IfaceValue>,
}

#[allow(dead_code)]
impl Interfaces {
    /// Take ownership of the `INTERFACES` map from a loaded eBPF object.
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(
            ebpf.take_map("INTERFACES")
                .context("INTERFACES map missing")?,
        )?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, key: IfaceKey, val: IfaceValue) -> anyhow::Result<()> {
        self.map.insert(key, val, 0).context("insert iface")
    }

    pub fn get(&self, key: &IfaceKey) -> Option<IfaceValue> {
        self.map.get(key, 0).ok()
    }
}

/// Typed handle over the single-entry `LOCAL` Array map.
#[allow(dead_code)]
pub struct LocalMap {
    map: Array<MapData, Local>,
}

#[allow(dead_code)]
impl LocalMap {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = Array::try_from(ebpf.take_map("LOCAL").context("LOCAL map missing")?)?;
        Ok(Self { map })
    }

    pub fn set(&mut self, local: &Local) -> anyhow::Result<()> {
        self.map.set(0, local, 0).context("write LOCAL[0]")
    }
}

/// Typed handle over the single-entry `CONFIG` Array map.
pub struct ConfigMap {
    map: Array<MapData, Config>,
}

#[allow(dead_code)]
impl ConfigMap {
    /// Take ownership of the `CONFIG` map from a loaded eBPF object.
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = Array::try_from(ebpf.take_map("CONFIG").context("CONFIG map missing")?)?;
        Ok(Self { map })
    }

    /// Write a `Config` into entry 0.
    pub fn set(&mut self, cfg: &Config) -> anyhow::Result<()> {
        self.map.set(0, cfg, 0).context("write CONFIG[0]")
    }

    /// Read entry 0.
    pub fn get(&self) -> anyhow::Result<Config> {
        self.map.get(&0, 0).context("read CONFIG[0]")
    }
}

/// Typed handle over the `PORT_META` BPF map (ifindex -> per-port metadata).
#[allow(dead_code)]
pub struct PortMetaMap {
    map: HashMap<MapData, u32, PortMeta>,
}

#[allow(dead_code)]
impl PortMetaMap {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(
            ebpf.take_map("PORT_META")
                .context("PORT_META map missing")?,
        )?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, ifindex: u32, meta: PortMeta) -> anyhow::Result<()> {
        self.map
            .insert(ifindex, meta, 0)
            .context("insert port_meta")
    }

    pub fn get(&self, ifindex: u32) -> Option<PortMeta> {
        self.map.get(&ifindex, 0).ok()
    }
}

/// Typed handle over the single-entry `INSPECT` Array map (debug packet inspector).
pub struct InspectMap {
    map: Array<MapData, InspectEntry>,
}

impl InspectMap {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = Array::try_from(ebpf.take_map("INSPECT").context("INSPECT map missing")?)?;
        Ok(Self { map })
    }

    pub fn get(&self) -> anyhow::Result<InspectEntry> {
        self.map.get(&0, 0).context("read INSPECT[0]")
    }
}

/// Typed handle over the `ROUTES` BPF LPM trie map.
#[allow(dead_code)]
pub struct Routes {
    map: LpmTrie<MapData, RouteLpmData, RouteValue>,
}

#[allow(dead_code)]
impl Routes {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = LpmTrie::try_from(ebpf.take_map("ROUTES").context("ROUTES map missing")?)?;
        Ok(Self { map })
    }

    pub fn upsert(
        &mut self,
        vni: u32,
        ipv4: [u8; 4],
        prefix_len: u32,
        val: RouteValue,
    ) -> anyhow::Result<()> {
        let key = Key::new(
            32 + prefix_len.min(32),
            RouteLpmData {
                vni: vni.to_be_bytes(),
                ipv4,
            },
        );
        self.map.insert(&key, val, 0).context("insert route")
    }

    pub fn remove(&mut self, vni: u32, ipv4: [u8; 4], prefix_len: u32) -> anyhow::Result<()> {
        let key = Key::new(
            32 + prefix_len.min(32),
            RouteLpmData {
                vni: vni.to_be_bytes(),
                ipv4,
            },
        );
        self.map.remove(&key).context("remove route")
    }
}

/// Typed handle over the `VIPS` BPF map.
#[allow(dead_code)]
pub struct Vips {
    map: HashMap<MapData, VipKey, [u8; 4]>,
}

#[allow(dead_code)]
impl Vips {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(ebpf.take_map("VIPS").context("VIPS map missing")?)?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, key: VipKey, val: [u8; 4]) -> anyhow::Result<()> {
        self.map.insert(key, val, 0).context("insert vip")
    }

    pub fn remove(&mut self, key: &VipKey) -> anyhow::Result<()> {
        self.map.remove(key).context("remove vip")
    }

    pub fn get(&self, key: &VipKey) -> Option<[u8; 4]> {
        self.map.get(key, 0).ok()
    }
}

/// Typed handle over the `LB` BPF map.
#[allow(dead_code)]
pub struct Lb {
    map: HashMap<MapData, LbKey, LbValue>,
}

#[allow(dead_code)]
impl Lb {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(ebpf.take_map("LB").context("LB map missing")?)?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, key: LbKey, val: LbValue) -> anyhow::Result<()> {
        self.map.insert(key, val, 0).context("insert lb")
    }

    pub fn remove(&mut self, key: &LbKey) -> anyhow::Result<()> {
        self.map.remove(key).context("remove lb")
    }

    pub fn get(&self, key: &LbKey) -> Option<LbValue> {
        self.map.get(key, 0).ok()
    }
}

/// Typed handle over the `MAGLEV` BPF map.
#[allow(dead_code)]
pub struct Maglev {
    map: HashMap<MapData, MaglevKey, [u8; 16]>,
}

#[allow(dead_code)]
impl Maglev {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(ebpf.take_map("MAGLEV").context("MAGLEV map missing")?)?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, key: MaglevKey, val: [u8; 16]) -> anyhow::Result<()> {
        self.map.insert(key, val, 0).context("insert maglev")
    }

    pub fn remove(&mut self, key: &MaglevKey) -> anyhow::Result<()> {
        self.map.remove(key).context("remove maglev")
    }

    pub fn get(&self, key: &MaglevKey) -> Option<[u8; 16]> {
        self.map.get(key, 0).ok()
    }
}

/// Typed handle over the `CONNTRACK` BPF map (LRU hash map).
#[allow(dead_code)]
pub struct Conntrack {
    map: HashMap<MapData, CtKey, CtEntry>,
}

#[allow(dead_code)]
impl Conntrack {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(
            ebpf.take_map("CONNTRACK")
                .context("CONNTRACK map missing")?,
        )?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, key: CtKey, val: CtEntry) -> anyhow::Result<()> {
        self.map.insert(key, val, 0).context("insert conntrack")
    }

    pub fn remove(&mut self, key: &CtKey) -> anyhow::Result<()> {
        self.map.remove(key).context("remove conntrack")
    }

    pub fn get(&self, key: &CtKey) -> Option<CtEntry> {
        self.map.get(key, 0).ok()
    }

    /// Snapshot all (key, entry) pairs for a GC sweep.
    pub fn entries(&self) -> Vec<(CtKey, CtEntry)> {
        self.map.iter().filter_map(|r| r.ok()).collect()
    }
}

/// Typed handle over the `NAT` BPF map ((vni, guest ipv4) -> nat config).
#[allow(dead_code)]
pub struct Nat {
    map: HashMap<MapData, NatKey, NatValue>,
}

#[allow(dead_code)]
impl Nat {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(ebpf.take_map("NAT").context("NAT map missing")?)?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, key: NatKey, val: NatValue) -> anyhow::Result<()> {
        self.map.insert(key, val, 0).context("insert nat")
    }

    pub fn remove(&mut self, key: &NatKey) -> anyhow::Result<()> {
        self.map.remove(key).context("remove nat")
    }

    pub fn get(&self, key: &NatKey) -> Option<NatValue> {
        self.map.get(key, 0).ok()
    }
}

/// Typed handle over the `FW_RULES` BPF map ((ifindex, slot) -> rule).
#[allow(dead_code)]
pub struct FwRules {
    map: HashMap<MapData, FwRuleKey, FwRule>,
}

#[allow(dead_code)]
impl FwRules {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(ebpf.take_map("FW_RULES").context("FW_RULES map missing")?)?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, key: FwRuleKey, val: FwRule) -> anyhow::Result<()> {
        self.map.insert(key, val, 0).context("insert fw rule")
    }

    pub fn remove(&mut self, key: &FwRuleKey) -> anyhow::Result<()> {
        self.map.remove(key).context("remove fw rule")
    }

    pub fn get(&self, key: &FwRuleKey) -> Option<FwRule> {
        self.map.get(key, 0).ok()
    }
}

/// Typed handle over the `FW_META` BPF map (ifindex -> per-direction rule counts).
#[allow(dead_code)]
pub struct FwMetaMap {
    map: HashMap<MapData, u32, FwMeta>,
}

#[allow(dead_code)]
impl FwMetaMap {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(ebpf.take_map("FW_META").context("FW_META map missing")?)?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, ifindex: u32, val: FwMeta) -> anyhow::Result<()> {
        self.map.insert(ifindex, val, 0).context("insert fw meta")
    }

    pub fn remove(&mut self, ifindex: u32) -> anyhow::Result<()> {
        self.map.remove(&ifindex).context("remove fw meta")
    }

    pub fn get(&self, ifindex: u32) -> Option<FwMeta> {
        self.map.get(&ifindex, 0).ok()
    }
}

/// Typed handle over the single-entry `FW_CONFIG` Array map (entry 0 = enforce flag).
#[allow(dead_code)]
pub struct FwConfig {
    map: Array<MapData, u32>,
}

#[allow(dead_code)]
impl FwConfig {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = Array::try_from(
            ebpf.take_map("FW_CONFIG")
                .context("FW_CONFIG map missing")?,
        )?;
        Ok(Self { map })
    }

    pub fn set(&mut self, enforce: u32) -> anyhow::Result<()> {
        self.map.set(0, &enforce, 0).context("write FW_CONFIG[0]")
    }
}

/// Typed handle over the `UNDERLAY` BPF map (underlay IPv6 -> VNI + tap + guest MAC).
#[allow(dead_code)]
pub struct Underlay {
    map: HashMap<MapData, [u8; 16], UnderlayValue>,
}

#[allow(dead_code)]
impl Underlay {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(ebpf.take_map("UNDERLAY").context("UNDERLAY map missing")?)?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, key: [u8; 16], val: UnderlayValue) -> anyhow::Result<()> {
        self.map.insert(key, val, 0).context("insert underlay")
    }

    pub fn remove(&mut self, key: &[u8; 16]) -> anyhow::Result<()> {
        self.map.remove(key).context("remove underlay")
    }

    pub fn get(&self, key: &[u8; 16]) -> Option<UnderlayValue> {
        self.map.get(key, 0).ok()
    }
}

/// Typed handle over the `NEIGHBOR_NAT` BPF map (slot index -> NeighborNatEntry).
#[allow(dead_code)]
pub struct NeighborNat {
    map: HashMap<MapData, u32, NeighborNatEntry>,
}

#[allow(dead_code)]
impl NeighborNat {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(
            ebpf.take_map("NEIGHBOR_NAT")
                .context("NEIGHBOR_NAT map missing")?,
        )?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, idx: u32, val: NeighborNatEntry) -> anyhow::Result<()> {
        self.map.insert(idx, val, 0).context("insert neighbor_nat")
    }

    pub fn remove(&mut self, idx: &u32) -> anyhow::Result<()> {
        self.map.remove(idx).context("remove neighbor_nat")
    }
}

/// Typed handle over the single-entry `NEIGHBOR_NAT_COUNT` Array map.
#[allow(dead_code)]
pub struct NeighborNatCount {
    map: Array<MapData, u32>,
}

#[allow(dead_code)]
impl NeighborNatCount {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = Array::try_from(
            ebpf.take_map("NEIGHBOR_NAT_COUNT")
                .context("NEIGHBOR_NAT_COUNT map missing")?,
        )?;
        Ok(Self { map })
    }

    pub fn set(&mut self, count: u32) -> anyhow::Result<()> {
        self.map
            .set(0, &count, 0)
            .context("write NEIGHBOR_NAT_COUNT[0]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires root/CAP_BPF; run via: sudo -E <test-bin> --include-ignored"]
    fn interfaces_roundtrip_through_bpf_map() {
        // Requires CAP_BPF/root and a real kernel; run the test binary under `sudo -E`.
        let mut ebpf = crate::loader::load_ebpf().expect("load ebpf object");
        let mut ifaces = Interfaces::open(&mut ebpf).expect("open INTERFACES");
        let k = IfaceKey::new(100, [10, 0, 0, 5]);
        let v = IfaceValue {
            tap_ifindex: 7,
            is_local: 1,
            underlay_ipv6: [0xfd; 16],
            guest_mac: [2, 0, 0, 0, 0, 5],
            _pad: [0; 2],
        };
        ifaces.upsert(k, v).expect("upsert");
        assert_eq!(ifaces.get(&k), Some(v));
    }
}
