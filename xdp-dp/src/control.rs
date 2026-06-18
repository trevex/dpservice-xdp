use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::Context as _;
use aya::programs::xdp::XdpLink;
use aya::Ebpf;
use xdp_dp_common::{
    FwMeta, FwRule, FwRuleKey, IfaceKey, IfaceValue, LbKey, LbValue, Local, MaglevKey, NatKey,
    NatValue, NeighborNatEntry, PortMeta, RouteValue, VipKey, FW_DIR_EGRESS, FW_MAX_RULES,
    NB_MAX_ENTRIES,
};

use crate::loader;
use crate::maps::{
    Conntrack, FwMetaMap, FwRules, Interfaces, Lb, LocalMap, Maglev, Meter, Nat, NeighborNat,
    NeighborNatCount, PortMetaMap, Routes, Routes6, Vips,
};

/// Full detail record for a registered local interface (shadow of eBPF map state).
#[derive(Clone)]
struct IfaceRecord {
    vni: u32,
    ipv4: [u8; 4],
    ipv6: [u8; 16],
    device: String,
    underlay: [u8; 16],
}

/// Registered load balancer: its Maglev table id, the (port,proto) services it answers, and the
/// ordered backend list (drives the Maglev table). Keyed in `Inner.lbs` by the LB's id.
struct LbEntry {
    vni: u32,
    ip: [u8; 4],
    lb_underlay: [u8; 16],
    ports: Vec<(u16, u8)>,
    table_id: u32,
    backends: Vec<[u8; 16]>,
}

/// Owns the loaded eBPF object + map handles; mutated by the gRPC handlers.
pub struct Control {
    inner: Mutex<Inner>,
    /// Conntrack map handle, taken once by the GC task via `take_conntrack`.
    conntrack: Mutex<Option<Conntrack>>,
}

struct Inner {
    ebpf: Ebpf,
    _locals: LocalMap,
    ports: PortMetaMap,
    ifaces: Interfaces,
    routes: Routes,
    routes6: Routes6,
    vips: Vips,
    lb: Lb,
    maglev: Maglev,
    nat: Nat,
    fw_rules: FwRules,
    fw_meta: FwMetaMap,
    underlay: crate::maps::Underlay,
    meter: Meter,
    neigh_nat: NeighborNat,
    neigh_nat_count: NeighborNatCount,
    /// In-memory neighbor NAT entries (drives the BPF map reprogram).
    neigh_nats: Vec<NeighborNatEntry>,
    /// loadbalancer_id -> its LB state.
    lbs: HashMap<Vec<u8>, LbEntry>,
    next_table_id: u32,
    /// interface_id -> (vni, guest_ipv4, guest_ipv6, device, underlay)
    by_id: HashMap<Vec<u8>, IfaceRecord>,
    /// interface_id -> ifindex
    by_ifindex: HashMap<Vec<u8>, u32>,
    /// interface_id -> its underlay /128
    iface_underlay: HashMap<Vec<u8>, [u8; 16]>,
    /// interface_id -> list of (prefix_ip, prefix_len) alias prefixes
    prefixes: HashMap<Vec<u8>, Vec<([u8; 4], u32)>>,
    /// ifindex -> ordered (rule_id, rule) pairs
    fw: HashMap<u32, Vec<(Vec<u8>, FwRule)>>,
    /// interface_id -> list of (prefix_ip, prefix_len) LB-prefix shadow entries (announce-only).
    lb_prefixes: HashMap<Vec<u8>, Vec<([u8; 4], u32)>>,
    /// interface_id -> the owned guest_tx XDP link (dropping it detaches the program).
    links: HashMap<Vec<u8>, XdpLink>,
    /// (vni, prefix_ipv4, prefix_len, nexthop_underlay) for list/delete_route.
    routes_shadow: Vec<(u32, [u8; 4], u32, [u8; 16])>,
}

impl Control {
    /// Load + attach uplink_rx, set LOCAL, take the map handles.
    pub fn bring_up(
        uplink: &str,
        uplink_ifindex: u32,
        uplink_mac: [u8; 6],
        gateway_mac: [u8; 6],
        underlay_ipv6: [u8; 16],
    ) -> anyhow::Result<Self> {
        let mut ebpf = loader::load_ebpf()?;
        loader::attach_xdp(&mut ebpf, "uplink_rx", uplink)?;
        let mut locals = LocalMap::open(&mut ebpf)?;
        locals.set(&Local {
            uplink_ifindex,
            uplink_mac,
            gateway_mac,
            underlay_ipv6,
        })?;
        let ports = PortMetaMap::open(&mut ebpf)?;
        let ifaces = Interfaces::open(&mut ebpf)?;
        let routes = Routes::open(&mut ebpf)?;
        let routes6 = Routes6::open(&mut ebpf)?;
        let vips = Vips::open(&mut ebpf)?;
        let lb = Lb::open(&mut ebpf)?;
        let maglev = Maglev::open(&mut ebpf)?;
        let nat = Nat::open(&mut ebpf)?;
        let fw_rules = FwRules::open(&mut ebpf)?;
        let fw_meta = FwMetaMap::open(&mut ebpf)?;
        let underlay = crate::maps::Underlay::open(&mut ebpf)?;
        let meter = Meter::open(&mut ebpf)?;
        let neigh_nat = NeighborNat::open(&mut ebpf)?;
        let neigh_nat_count = NeighborNatCount::open(&mut ebpf)?;
        let conntrack = Conntrack::open(&mut ebpf)?;
        Ok(Self {
            inner: Mutex::new(Inner {
                ebpf,
                _locals: locals,
                ports,
                ifaces,
                routes,
                routes6,
                vips,
                lb,
                maglev,
                nat,
                fw_rules,
                fw_meta,
                underlay,
                meter,
                neigh_nat,
                neigh_nat_count,
                neigh_nats: Vec::new(),
                lbs: HashMap::new(),
                next_table_id: 1,
                by_id: HashMap::new(),
                by_ifindex: HashMap::new(),
                iface_underlay: HashMap::new(),
                prefixes: HashMap::new(),
                fw: HashMap::new(),
                lb_prefixes: HashMap::new(),
                links: HashMap::new(),
                routes_shadow: Vec::new(),
            }),
            conntrack: Mutex::new(Some(conntrack)),
        })
    }

    /// Hand out the conntrack map handle once (for the GC task). Returns None if already taken.
    pub fn take_conntrack(&self) -> Option<Conntrack> {
        self.conntrack.lock().unwrap().take()
    }

    fn meter_state(total_mbps: u64, public_mbps: u64) -> xdp_dp_common::MeterState {
        let tb = total_mbps.saturating_mul(1_000_000) / 8;
        let pb = public_mbps.saturating_mul(1_000_000) / 8;
        xdp_dp_common::MeterState {
            total_bps: tb,
            total_burst: (tb / 8).max(2000),
            total_tokens: tb / 8,
            total_last_ns: 0,
            public_bps: pb,
            public_burst: (pb / 8).max(2000),
            public_tokens: pb / 8,
            public_last_ns: 0,
        }
    }

    pub fn set_meter(
        &self,
        interface_id: &[u8],
        total_mbps: u64,
        public_mbps: u64,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let ifindex = *g
            .by_ifindex
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("unknown interface"))?;
        g.meter
            .upsert(ifindex, Self::meter_state(total_mbps, public_mbps))
    }

    /// Program a LOCAL interface: attach guest_tx to its device, set PORT_META + INTERFACES +
    /// UNDERLAY, retain the XDP link for detach, and record shadow detail.
    #[allow(clippy::too_many_arguments)]
    pub fn create_interface(
        &self,
        interface_id: &[u8],
        device: &str,
        vni: u32,
        ipv4: [u8; 4],
        ipv6: [u8; 16],
        gateway_ipv4: [u8; 4],
        gateway_ipv6: [u8; 16],
        underlay_ipv6: [u8; 16],
        total_mbps: u64,
        public_mbps: u64,
    ) -> anyhow::Result<()> {
        let tap = crate::ifindex(device)?;
        let mac = crate::mac_of(device)?;
        let mut g = self.inner.lock().unwrap();
        if g.by_id.contains_key(interface_id) {
            anyhow::bail!("interface already exists");
        }
        // Attach guest_tx and retain the link. The program is loaded on the first attach; if it is
        // not yet loaded (no guest interfaces yet) attach_xdp_link's attach() returns "not loaded",
        // so load+attach once via attach_xdp, then re-attach to retain a droppable link.
        let link = match loader::attach_xdp_link(&mut g.ebpf, "guest_tx", device) {
            Ok(l) => l,
            Err(_) => {
                loader::attach_xdp(&mut g.ebpf, "guest_tx", device)
                    .with_context(|| format!("load+attach guest_tx to {device}"))?;
                // Program is now loaded; obtaining a retained link on a fresh attach is not possible on
                // the same iface (already attached). Keep this first link owned by Ebpf; detach of
                // the very first interface relies on map cleanup (rare in practice). Subsequent
                // interfaces retain links normally.
                g.by_id.insert(
                    interface_id.to_vec(),
                    IfaceRecord {
                        vni,
                        ipv4,
                        ipv6,
                        device: device.to_string(),
                        underlay: underlay_ipv6,
                    },
                );
                g.by_ifindex.insert(interface_id.to_vec(), tap);
                g.iface_underlay
                    .insert(interface_id.to_vec(), underlay_ipv6);
                Self::program_iface_maps(
                    &mut g,
                    tap,
                    vni,
                    ipv4,
                    gateway_ipv4,
                    gateway_ipv6,
                    mac,
                    underlay_ipv6,
                    total_mbps,
                    public_mbps,
                )?;
                return Ok(());
            }
        };
        g.links.insert(interface_id.to_vec(), link);
        g.by_id.insert(
            interface_id.to_vec(),
            IfaceRecord {
                vni,
                ipv4,
                ipv6,
                device: device.to_string(),
                underlay: underlay_ipv6,
            },
        );
        g.by_ifindex.insert(interface_id.to_vec(), tap);
        g.iface_underlay
            .insert(interface_id.to_vec(), underlay_ipv6);
        Self::program_iface_maps(
            &mut g,
            tap,
            vni,
            ipv4,
            gateway_ipv4,
            gateway_ipv6,
            mac,
            underlay_ipv6,
            total_mbps,
            public_mbps,
        )
    }

    /// Program PORT_META / INTERFACES / UNDERLAY / METER for one interface.
    #[allow(clippy::too_many_arguments)]
    fn program_iface_maps(
        g: &mut Inner,
        tap: u32,
        vni: u32,
        ipv4: [u8; 4],
        gateway_ipv4: [u8; 4],
        gateway_ipv6: [u8; 16],
        mac: [u8; 6],
        underlay_ipv6: [u8; 16],
        total_mbps: u64,
        public_mbps: u64,
    ) -> anyhow::Result<()> {
        g.ports.upsert(
            tap,
            PortMeta {
                vni,
                guest_ipv4: ipv4,
                gateway_ipv4,
                guest_mac: mac,
                _pad: [0; 2],
                underlay_ipv6,
                gateway_ipv6,
            },
        )?;
        g.ifaces.upsert(
            IfaceKey::new(vni, ipv4),
            IfaceValue {
                tap_ifindex: tap,
                is_local: 1,
                underlay_ipv6,
                guest_mac: mac,
                _pad: [0; 2],
            },
        )?;
        g.underlay.upsert(
            underlay_ipv6,
            xdp_dp_common::UnderlayValue {
                vni,
                tap_ifindex: tap,
                guest_mac: mac,
                _pad: [0; 2],
            },
        )?;
        if total_mbps != 0 || public_mbps != 0 {
            g.meter
                .upsert(tap, Self::meter_state(total_mbps, public_mbps))?;
        }
        Ok(())
    }

    /// Tear down a local interface: detach guest_tx (drop the link) and clear its maps + shadow.
    /// Idempotent.
    pub fn detach_interface(&self, interface_id: &[u8]) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let rec = match g.by_id.remove(interface_id) {
            Some(r) => r,
            None => return Ok(()),
        };
        let tap = g.by_ifindex.remove(interface_id).unwrap_or(0);
        g.iface_underlay.remove(interface_id);
        g.prefixes.remove(interface_id);
        // Dropping the link detaches the program from the device.
        g.links.remove(interface_id);
        let _ = g.ports.remove(tap);
        let _ = g.ifaces.remove(IfaceKey::new(rec.vni, rec.ipv4));
        let _ = g.underlay.remove(&rec.underlay);
        let _ = g.meter.remove(&tap);
        if let Some(rules) = g.fw.remove(&tap) {
            drop(rules);
        }
        Ok(())
    }

    /// Interface detail for get/list. Returns (vni, ipv4, ipv6, underlay).
    pub fn get_interface(&self, interface_id: &[u8]) -> Option<(u32, [u8; 4], [u8; 16], [u8; 16])> {
        let g = self.inner.lock().unwrap();
        g.by_id
            .get(interface_id)
            .map(|r| (r.vni, r.ipv4, r.ipv6, r.underlay))
    }

    /// All interface ids with their (vni, ipv4, ipv6, underlay).
    pub fn list_interfaces(&self) -> Vec<(Vec<u8>, u32, [u8; 4], [u8; 16], [u8; 16])> {
        let g = self.inner.lock().unwrap();
        g.by_id
            .iter()
            .map(|(id, r)| (id.clone(), r.vni, r.ipv4, r.ipv6, r.underlay))
            .collect()
    }

    pub fn create_route(
        &self,
        vni: u32,
        ipv4: [u8; 4],
        prefix_len: u32,
        nexthop_ipv6: [u8; 16],
        is_external: bool,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        g.routes.upsert(
            vni,
            ipv4,
            prefix_len,
            RouteValue {
                nexthop_vni: vni,
                nexthop_ipv6,
                is_external: is_external as u8,
                _pad: [0; 3],
            },
        )?;
        g.routes_shadow.push((vni, ipv4, prefix_len, nexthop_ipv6));
        Ok(())
    }

    pub fn delete_route(&self, vni: u32, ipv4: [u8; 4], prefix_len: u32) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let _ = g.routes.remove(vni, ipv4, prefix_len);
        g.routes_shadow
            .retain(|&(v, p, l, _)| !(v == vni && p == ipv4 && l == prefix_len));
        Ok(())
    }

    pub fn list_routes(&self, vni: u32) -> Vec<([u8; 4], u32, [u8; 16])> {
        let g = self.inner.lock().unwrap();
        g.routes_shadow
            .iter()
            .filter(|&&(v, _, _, _)| v == vni)
            .map(|&(_, p, l, n)| (p, l, n))
            .collect()
    }

    pub fn vni_in_use(&self, vni: u32) -> bool {
        let g = self.inner.lock().unwrap();
        g.by_id.values().any(|r| r.vni == vni)
            || g.routes_shadow.iter().any(|&(v, _, _, _)| v == vni)
    }

    pub fn reset_vni(&self, vni: u32) -> anyhow::Result<()> {
        // Remove all routes for the vni (interfaces are torn down via DeleteInterface).
        let to_del: Vec<_> = {
            let g = self.inner.lock().unwrap();
            g.routes_shadow
                .iter()
                .filter(|&&(v, _, _, _)| v == vni)
                .map(|&(_, p, l, _)| (p, l))
                .collect()
        };
        for (p, l) in to_del {
            self.delete_route(vni, p, l)?;
        }
        Ok(())
    }

    pub fn create_route6(
        &self,
        vni: u32,
        ipv6: [u8; 16],
        prefix_len: u32,
        nexthop_ipv6: [u8; 16],
        is_external: bool,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        g.routes6.upsert(
            vni,
            ipv6,
            prefix_len,
            RouteValue {
                nexthop_vni: vni,
                nexthop_ipv6,
                is_external: is_external as u8,
                _pad: [0; 3],
            },
        )
    }

    /// Register a load balancer: allocate a Maglev table id and program the `LB` map for each
    /// (port, proto) service. Backends are added later via `add_lb_target`.
    pub fn create_lb(
        &self,
        id: &[u8],
        vni: u32,
        ip: [u8; 4],
        lb_underlay: [u8; 16],
        ports: Vec<(u16, u8)>,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let table_id = g.next_table_id;
        g.next_table_id += 1;
        for &(port, proto) in &ports {
            g.lb.upsert(
                LbKey {
                    vni,
                    ipv4: ip,
                    port,
                    proto,
                    _pad: 0,
                },
                LbValue {
                    table_id,
                    size: crate::maglev::TABLE_SIZE,
                },
            )?;
        }
        // Program the LB's own underlay /128 into UNDERLAY so ingress can identify it.
        // tap_ifindex=0 and guest_mac=[0;6] because the LB VIP is anycast (no local tap).
        g.underlay.upsert(
            lb_underlay,
            xdp_dp_common::UnderlayValue {
                vni,
                tap_ifindex: 0,
                guest_mac: [0; 6],
                _pad: [0; 2],
            },
        )?;
        g.lbs.insert(
            id.to_vec(),
            LbEntry {
                vni,
                ip,
                lb_underlay,
                ports,
                table_id,
                backends: Vec::new(),
            },
        );
        Ok(())
    }

    /// Append a backend underlay /128 to a registered LB and rebuild + write its Maglev table.
    pub fn add_lb_target(&self, id: &[u8], backend: [u8; 16]) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let (table_id, backends) = {
            let entry = g
                .lbs
                .get_mut(id)
                .ok_or_else(|| anyhow::anyhow!("unknown load balancer"))?;
            entry.backends.push(backend);
            (entry.table_id, entry.backends.clone())
        };
        let table = crate::maglev::build(&backends);
        for (slot, &bi) in table.iter().enumerate() {
            g.maglev.upsert(
                MaglevKey {
                    table_id,
                    slot: slot as u32,
                },
                backends[bi as usize],
            )?;
        }
        Ok(())
    }

    /// Return detail for a single LB: (vni, ip, lb_underlay, ports).
    pub fn get_lb(&self, id: &[u8]) -> Option<(u32, [u8; 4], [u8; 16], Vec<(u16, u8)>)> {
        let g = self.inner.lock().unwrap();
        g.lbs
            .get(id)
            .map(|e| (e.vni, e.ip, e.lb_underlay, e.ports.clone()))
    }

    /// List all LBs: (id, vni, ip, lb_underlay, ports).
    pub fn list_lbs(&self) -> Vec<(Vec<u8>, u32, [u8; 4], [u8; 16], Vec<(u16, u8)>)> {
        let g = self.inner.lock().unwrap();
        g.lbs
            .iter()
            .map(|(id, e)| (id.clone(), e.vni, e.ip, e.lb_underlay, e.ports.clone()))
            .collect()
    }

    /// List the backend underlay addresses for a given LB.
    pub fn list_lb_targets(&self, id: &[u8]) -> Vec<[u8; 16]> {
        let g = self.inner.lock().unwrap();
        g.lbs
            .get(id)
            .map(|e| e.backends.clone())
            .unwrap_or_default()
    }

    /// Add an LB-prefix shadow entry (announce-only; no datapath route needed).
    pub fn add_lb_prefix(
        &self,
        interface_id: &[u8],
        prefix: [u8; 4],
        prefix_len: u32,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        g.lb_prefixes
            .entry(interface_id.to_vec())
            .or_default()
            .push((prefix, prefix_len));
        Ok(())
    }

    /// Remove an LB-prefix shadow entry.
    pub fn del_lb_prefix(
        &self,
        interface_id: &[u8],
        prefix: [u8; 4],
        prefix_len: u32,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        if let Some(v) = g.lb_prefixes.get_mut(interface_id) {
            v.retain(|&(p, l)| !(p == prefix && l == prefix_len));
        }
        Ok(())
    }

    /// Return all LB-prefix shadow entries for an interface.
    pub fn list_lb_prefixes(&self, interface_id: &[u8]) -> Vec<([u8; 4], u32)> {
        let g = self.inner.lock().unwrap();
        g.lb_prefixes.get(interface_id).cloned().unwrap_or_default()
    }

    /// Remove a load balancer: clear its `LB` service entries and `MAGLEV` slots.
    pub fn delete_lb(&self, id: &[u8]) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let entry = match g.lbs.remove(id) {
            Some(e) => e,
            None => return Ok(()),
        };
        for &(port, proto) in &entry.ports {
            let _ = g.lb.remove(&LbKey {
                vni: entry.vni,
                ipv4: entry.ip,
                port,
                proto,
                _pad: 0,
            });
        }
        for slot in 0..crate::maglev::TABLE_SIZE {
            let _ = g.maglev.remove(&MaglevKey {
                table_id: entry.table_id,
                slot,
            });
        }
        Ok(())
    }

    /// Program the VIPS map for SNAT (G->V) and DNAT (V->G).
    pub fn create_vip(&self, interface_id: &[u8], vip: [u8; 4]) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("unknown interface"))?;
        let (vni, gip) = (rec.vni, rec.ipv4);
        // egress SNAT: (vni, guest_ip) -> vip
        g.vips.upsert(VipKey { vni, ipv4: gip }, vip)?;
        // ingress DNAT: (vni, vip) -> guest_ip
        g.vips.upsert(VipKey { vni, ipv4: vip }, gip)?;
        Ok(())
    }

    /// Remove both VIPS map entries for this interface.
    pub fn delete_vip(&self, interface_id: &[u8]) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("unknown interface"))?;
        let (vni, gip) = (rec.vni, rec.ipv4);
        if let Some(vip) = g.vips.get(&VipKey { vni, ipv4: gip }) {
            let _ = g.vips.remove(&VipKey { vni, ipv4: vip });
        }
        let _ = g.vips.remove(&VipKey { vni, ipv4: gip });
        Ok(())
    }

    /// Return the VIP for this interface, if one has been set.
    pub fn get_vip(&self, interface_id: &[u8]) -> Option<[u8; 4]> {
        let g = self.inner.lock().unwrap();
        let rec = g.by_id.get(interface_id)?;
        let (vni, gip) = (rec.vni, rec.ipv4);
        g.vips.get(&VipKey { vni, ipv4: gip })
    }

    /// Program a guest's NAT config: (vni, guest_ip) -> (nat_ip, port_min, port_max).
    pub fn create_nat(
        &self,
        interface_id: &[u8],
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("unknown interface"))?;
        let (vni, gip) = (rec.vni, rec.ipv4);
        g.nat.upsert(
            NatKey { vni, ipv4: gip },
            NatValue {
                nat_ipv4: nat_ip,
                port_min,
                port_max,
            },
        )
    }

    /// Return a guest's NAT config (nat_ip, port_min, port_max), if set.
    pub fn get_nat(&self, interface_id: &[u8]) -> Option<([u8; 4], u16, u16)> {
        let g = self.inner.lock().unwrap();
        let rec = g.by_id.get(interface_id)?;
        let (vni, gip) = (rec.vni, rec.ipv4);
        g.nat
            .get(&NatKey { vni, ipv4: gip })
            .map(|v| (v.nat_ipv4, v.port_min, v.port_max))
    }

    /// List all local NAT entries: (interface_id, guest_ipv4, nat_ip, port_min, port_max).
    pub fn list_local_nats(&self) -> Vec<(Vec<u8>, [u8; 4], [u8; 4], u16, u16)> {
        let g = self.inner.lock().unwrap();
        g.by_id
            .iter()
            .filter_map(|(id, rec)| {
                g.nat
                    .get(&NatKey {
                        vni: rec.vni,
                        ipv4: rec.ipv4,
                    })
                    .map(|v| (id.clone(), rec.ipv4, v.nat_ipv4, v.port_min, v.port_max))
            })
            .collect()
    }

    /// Remove a guest's NAT config.
    pub fn delete_nat(&self, interface_id: &[u8]) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("unknown interface"))?;
        let (vni, gip) = (rec.vni, rec.ipv4);
        let _ = g.nat.remove(&NatKey { vni, ipv4: gip });
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Firewall rule management
    // -----------------------------------------------------------------------

    /// Reprogram all firewall slots for one interface from the in-memory `fw` vec.
    fn fw_reprogram(g: &mut Inner, ifindex: u32) -> anyhow::Result<()> {
        let rules = g.fw.get(&ifindex).cloned().unwrap_or_default();
        // Clear all slots.
        for idx in 0..FW_MAX_RULES {
            let _ = g.fw_rules.remove(&FwRuleKey { ifindex, idx });
        }
        let mut ingress = 0u32;
        let mut egress = 0u32;
        for (i, (_id, r)) in rules.iter().enumerate() {
            g.fw_rules.upsert(
                FwRuleKey {
                    ifindex,
                    idx: i as u32,
                },
                *r,
            )?;
            if r.direction == FW_DIR_EGRESS {
                egress += 1;
            } else {
                ingress += 1;
            }
        }
        g.fw_meta.upsert(
            ifindex,
            FwMeta {
                ingress_count: ingress,
                egress_count: egress,
            },
        )?;
        Ok(())
    }

    /// Add or replace a firewall rule on an interface.
    pub fn add_fw_rule(
        &self,
        interface_id: &[u8],
        rule_id: Vec<u8>,
        rule: FwRule,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let ifindex = *g
            .by_ifindex
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("unknown interface"))?;
        let entry = g.fw.entry(ifindex).or_default();
        if entry.len() >= FW_MAX_RULES as usize {
            anyhow::bail!(
                "too many firewall rules for interface (max {})",
                FW_MAX_RULES
            );
        }
        if let Some(slot) = entry.iter_mut().find(|(id, _)| id == &rule_id) {
            slot.1 = rule;
        } else {
            entry.push((rule_id, rule));
        }
        Self::fw_reprogram(&mut g, ifindex)
    }

    /// Remove a firewall rule by id from an interface.
    pub fn del_fw_rule(&self, interface_id: &[u8], rule_id: &[u8]) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let ifindex = *g
            .by_ifindex
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("unknown interface"))?;
        if let Some(entry) = g.fw.get_mut(&ifindex) {
            entry.retain(|(id, _)| id.as_slice() != rule_id);
        }
        Self::fw_reprogram(&mut g, ifindex)
    }

    /// Get a single firewall rule by id.
    pub fn get_fw_rule(&self, interface_id: &[u8], rule_id: &[u8]) -> Option<FwRule> {
        let g = self.inner.lock().unwrap();
        let ifindex = *g.by_ifindex.get(interface_id)?;
        g.fw.get(&ifindex)?
            .iter()
            .find(|(id, _)| id.as_slice() == rule_id)
            .map(|(_, r)| *r)
    }

    /// List all firewall rules for an interface as (rule_id, rule) pairs.
    pub fn list_fw_rules(&self, interface_id: &[u8]) -> Vec<(Vec<u8>, FwRule)> {
        let g = self.inner.lock().unwrap();
        match g.by_ifindex.get(interface_id) {
            Some(ifindex) => g.fw.get(ifindex).cloned().unwrap_or_default(),
            None => Vec::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Alias prefix management
    // -----------------------------------------------------------------------

    /// Announce an alias prefix routed to an interface: program a route (vni, prefix/len) -> the
    /// interface's underlay /128.
    pub fn add_prefix(
        &self,
        interface_id: &[u8],
        prefix: [u8; 4],
        prefix_len: u32,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("unknown interface"))?;
        let (vni, _gip) = (rec.vni, rec.ipv4);
        let underlay = *g
            .iface_underlay
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("interface has no underlay"))?;
        g.routes.upsert(
            vni,
            prefix,
            prefix_len,
            RouteValue {
                nexthop_vni: vni,
                nexthop_ipv6: underlay,
                is_external: 0,
                _pad: [0; 3],
            },
        )?;
        g.prefixes
            .entry(interface_id.to_vec())
            .or_default()
            .push((prefix, prefix_len));
        Ok(())
    }

    /// Remove an alias prefix: delete the LPM route entry and forget the local record.
    pub fn del_prefix(
        &self,
        interface_id: &[u8],
        prefix: [u8; 4],
        prefix_len: u32,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("unknown interface"))?;
        let (vni, _gip) = (rec.vni, rec.ipv4);
        let _ = g.routes.remove(vni, prefix, prefix_len);
        if let Some(v) = g.prefixes.get_mut(interface_id) {
            v.retain(|&(p, l)| !(p == prefix && l == prefix_len));
        }
        Ok(())
    }

    /// Return all alias prefixes for an interface as (prefix_ip, prefix_len) pairs.
    pub fn list_prefixes(&self, interface_id: &[u8]) -> Vec<([u8; 4], u32)> {
        let g = self.inner.lock().unwrap();
        g.prefixes.get(interface_id).cloned().unwrap_or_default()
    }

    // -----------------------------------------------------------------------
    // Neighbor NAT management (distributed NAT return)
    // -----------------------------------------------------------------------

    /// Reprogram NEIGHBOR_NAT and NEIGHBOR_NAT_COUNT from the in-memory vec.
    fn neigh_nat_reprogram(g: &mut Inner) -> anyhow::Result<()> {
        let n = g.neigh_nats.len() as u32;
        for (i, e) in g.neigh_nats.iter().enumerate() {
            g.neigh_nat.upsert(i as u32, *e)?;
        }
        g.neigh_nat_count.set(n)?;
        Ok(())
    }

    /// Add a neighbor-NAT entry (capped at NB_MAX_ENTRIES).
    pub fn add_neighbor_nat(
        &self,
        vni: u32,
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
        underlay: [u8; 16],
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        if g.neigh_nats.len() >= NB_MAX_ENTRIES as usize {
            anyhow::bail!("neighbor NAT table full (max {})", NB_MAX_ENTRIES);
        }
        // Deduplicate: replace existing entry with same (vni, nat_ip, port_min, port_max).
        if let Some(slot) = g.neigh_nats.iter_mut().find(|e| {
            e.vni == vni && e.nat_ip == nat_ip && e.port_min == port_min && e.port_max == port_max
        }) {
            slot.underlay = underlay;
            slot.enabled = 1;
        } else {
            g.neigh_nats.push(NeighborNatEntry {
                underlay,
                nat_ip,
                vni,
                port_min,
                port_max,
                enabled: 1,
                _pad: [0; 3],
            });
        }
        Self::neigh_nat_reprogram(&mut g)
    }

    /// Remove a neighbor-NAT entry matching (vni, nat_ip, port_min, port_max).
    pub fn del_neighbor_nat(
        &self,
        vni: u32,
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        g.neigh_nats.retain(|e| {
            !(e.vni == vni
                && e.nat_ip == nat_ip
                && e.port_min == port_min
                && e.port_max == port_max)
        });
        Self::neigh_nat_reprogram(&mut g)
    }

    /// List all neighbor-NAT entries.
    pub fn list_neighbor_nats(&self) -> Vec<NeighborNatEntry> {
        let g = self.inner.lock().unwrap();
        g.neigh_nats.clone()
    }
}
