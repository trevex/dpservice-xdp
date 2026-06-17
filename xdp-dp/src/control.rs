use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::Context as _;
use aya::Ebpf;
use xdp_dp_common::{IfaceKey, IfaceValue, Local, PortMeta, RouteKey, RouteValue, VipKey};

use crate::loader;
use crate::maps::{Interfaces, LocalMap, PortMetaMap, Routes, Vips};

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
        Ok(Self {
            inner: Mutex::new(Inner {
                ebpf,
                _locals: locals,
                ports,
                ifaces,
                routes,
                vips,
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
            },
        )?;
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
