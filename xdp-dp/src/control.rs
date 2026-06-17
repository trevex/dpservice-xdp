use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::Context as _;
use aya::Ebpf;
use xdp_dp_common::{
    IfaceKey, IfaceValue, LbKey, LbValue, Local, MaglevKey, PortMeta, RouteKey, RouteValue, VipKey,
};

use crate::loader;
use crate::maps::{Interfaces, Lb, LocalMap, Maglev, PortMetaMap, Routes, Vips};

/// Registered load balancer: its Maglev table id, the (port,proto) services it answers, and the
/// ordered backend list (drives the Maglev table). Keyed in `Inner.lbs` by the LB's id.
struct LbEntry {
    vni: u32,
    ip: [u8; 4],
    ports: Vec<(u16, u8)>,
    table_id: u32,
    backends: Vec<[u8; 4]>,
}

/// Owns the loaded eBPF object + map handles; mutated by the gRPC handlers.
pub struct Control {
    inner: Mutex<Inner>,
}

struct Inner {
    ebpf: Ebpf,
    _locals: LocalMap,
    ports: PortMetaMap,
    ifaces: Interfaces,
    routes: Routes,
    vips: Vips,
    lb: Lb,
    maglev: Maglev,
    /// loadbalancer_id -> its LB state.
    lbs: HashMap<Vec<u8>, LbEntry>,
    next_table_id: u32,
    /// interface_id -> (vni, guest_ipv4)
    by_id: HashMap<Vec<u8>, (u32, [u8; 4])>,
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
        let vips = Vips::open(&mut ebpf)?;
        let lb = Lb::open(&mut ebpf)?;
        let maglev = Maglev::open(&mut ebpf)?;
        Ok(Self {
            inner: Mutex::new(Inner {
                ebpf,
                _locals: locals,
                ports,
                ifaces,
                routes,
                vips,
                lb,
                maglev,
                lbs: HashMap::new(),
                next_table_id: 1,
                by_id: HashMap::new(),
            }),
        })
    }

    /// Program a LOCAL interface: attach guest_tx to its device, set PORT_META + INTERFACES.
    pub fn create_interface(
        &self,
        interface_id: &[u8],
        device: &str,
        vni: u32,
        ipv4: [u8; 4],
        gateway_ipv4: [u8; 4],
        underlay_ipv6: [u8; 16],
    ) -> anyhow::Result<()> {
        let tap = crate::ifindex(device)?;
        let mac = crate::mac_of(device)?;
        let mut g = self.inner.lock().unwrap();
        g.by_id.insert(interface_id.to_vec(), (vni, ipv4));
        // Try attach-only first (program already loaded for a previous interface).
        // Fall back to full load+attach for the first guest interface.
        loader::attach_xdp_extra(&mut g.ebpf, "guest_tx", device)
            .or_else(|_| loader::attach_xdp(&mut g.ebpf, "guest_tx", device))
            .with_context(|| format!("attach guest_tx to {device}"))?;
        g.ports.upsert(
            tap,
            PortMeta {
                vni,
                guest_ipv4: ipv4,
                gateway_ipv4,
                guest_mac: mac,
                _pad: [0; 2],
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
        Ok(())
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
            RouteKey {
                vni,
                prefix_len,
                ipv4,
            },
            RouteValue {
                nexthop_vni: vni,
                nexthop_ipv6,
                is_external: is_external as u8,
                _pad: [0; 3],
            },
        )?;
        Ok(())
    }

    /// Register a load balancer: allocate a Maglev table id and program the `LB` map for each
    /// (port, proto) service. Backends are added later via `add_lb_target`.
    pub fn create_lb(
        &self,
        id: &[u8],
        vni: u32,
        ip: [u8; 4],
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
        g.lbs.insert(
            id.to_vec(),
            LbEntry {
                vni,
                ip,
                ports,
                table_id,
                backends: Vec::new(),
            },
        );
        Ok(())
    }

    /// Append a backend to a registered LB and rebuild + write its Maglev table.
    pub fn add_lb_target(&self, id: &[u8], backend: [u8; 4]) -> anyhow::Result<()> {
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
        let (vni, gip) = *g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("unknown interface"))?;
        // egress SNAT: (vni, guest_ip) -> vip
        g.vips.upsert(VipKey { vni, ipv4: gip }, vip)?;
        // ingress DNAT: (vni, vip) -> guest_ip
        g.vips.upsert(VipKey { vni, ipv4: vip }, gip)?;
        Ok(())
    }

    /// Remove both VIPS map entries for this interface.
    pub fn delete_vip(&self, interface_id: &[u8]) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let (vni, gip) = *g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("unknown interface"))?;
        if let Some(vip) = g.vips.get(&VipKey { vni, ipv4: gip }) {
            let _ = g.vips.remove(&VipKey { vni, ipv4: vip });
        }
        let _ = g.vips.remove(&VipKey { vni, ipv4: gip });
        Ok(())
    }

    /// Return the VIP for this interface, if one has been set.
    pub fn get_vip(&self, interface_id: &[u8]) -> Option<[u8; 4]> {
        let g = self.inner.lock().unwrap();
        let (vni, gip) = *g.by_id.get(interface_id)?;
        g.vips.get(&VipKey { vni, ipv4: gip })
    }
}
