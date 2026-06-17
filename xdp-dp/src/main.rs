pub mod pb {
    tonic::include_proto!("dpdkironcore.v1");
}

mod conntrack_gc;
mod control;
mod grpc;
mod loader;
mod maglev;
mod maps;
mod state;

use anyhow::Context;
use clap::{Parser, Subcommand};

// ---------------------------------------------------------------------------
// Sysfs / parse helpers
// ---------------------------------------------------------------------------

/// Read `/sys/class/net/<iface>/ifindex` and parse it as a u32.
pub(crate) fn ifindex(iface: &str) -> anyhow::Result<u32> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .with_context(|| format!("read ifindex for {iface}"))?;
    Ok(s.trim().parse()?)
}

/// Read `/sys/class/net/<iface>/address` and return 6 MAC bytes.
pub(crate) fn mac_of(iface: &str) -> anyhow::Result<[u8; 6]> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .with_context(|| format!("read mac for {iface}"))?;
    parse_mac(s.trim())
}

/// Parse `"aa:bb:cc:dd:ee:ff"` into 6 bytes.
fn parse_mac(s: &str) -> anyhow::Result<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0usize;
    for (i, part) in s.split(':').enumerate() {
        anyhow::ensure!(i < 6, "too many octets in MAC {s}");
        out[i] = u8::from_str_radix(part, 16).with_context(|| format!("bad MAC octet {part}"))?;
        n += 1;
    }
    anyhow::ensure!(n == 6, "MAC {s} must have 6 octets");
    Ok(out)
}

/// Parse an IPv6 literal into 16 octets.
fn parse_ipv6(s: &str) -> anyhow::Result<[u8; 16]> {
    Ok(s.parse::<std::net::Ipv6Addr>()
        .with_context(|| format!("bad IPv6 {s}"))?
        .octets())
}

/// Parse an IPv4 literal into 4 octets.
fn parse_ipv4(s: &str) -> anyhow::Result<[u8; 4]> {
    Ok(s.parse::<std::net::Ipv4Addr>()
        .with_context(|| format!("bad IPv4 {s}"))?
        .octets())
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "xdp-dp")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Load and attach the XDP datapath to an interface, then idle.
    Load {
        #[arg(long)]
        uplink: String,
    },
    /// Start the gRPC control-plane server with a live datapath.
    Serve {
        /// Address to listen on (e.g. 127.0.0.1:1337).
        #[arg(long)]
        addr: String,
        /// Uplink interface (uplink_rx attaches here).
        #[arg(long)]
        uplink: String,
        /// This hypervisor's underlay IPv6 (outer src on encap).
        #[arg(long)]
        local_underlay: String,
        /// Underlay next-hop MAC — outer eth dst for ALL encapped traffic.
        #[arg(long)]
        gateway_mac: String,
        /// Override the CONNTRACK map capacity (entries). Also settable via XDP_DP_CONNTRACK_MAX.
        #[arg(long)]
        conntrack_max: Option<u32>,
    },
    /// Attach the trivial xdp_pass program to an interface (redirect-target enabler), then idle.
    Pass {
        #[arg(long)]
        iface: String,
    },
    /// Attach xdp_inspect to an interface and print the first packet bytes every 500 ms.
    Inspect {
        #[arg(long)]
        iface: String,
    },
    /// Bring up the map-driven datapath: attach programs and program all maps, then idle.
    Bringup {
        /// Uplink interface (uplink_rx attaches here).
        #[arg(long)]
        uplink: String,
        /// This hypervisor's underlay IPv6 (outer src on encap).
        #[arg(long)]
        local_underlay: String,
        /// Overlay gateway IPv4 the datapath answers ARP for (e.g. 10.0.0.1).
        #[arg(long)]
        gateway: String,
        /// Underlay next-hop (gateway/ToR router) MAC — outer eth dst for ALL encapped traffic.
        /// In a flat-L2 lab this is the peer hypervisor's uplink MAC.
        #[arg(long)]
        gateway_mac: String,
        /// Local guest, repeatable:
        /// "<ifname>=<overlay_ipv4>=<guest_mac>=<underlay_ipv6>=<vni>". The per-interface underlay
        /// /128 is the interface's identity on the underlay (UNDERLAY map key); guest_tx attaches
        /// to <ifname> (the hypervisor-side veth peer).
        #[arg(long = "guest")]
        guests: Vec<String>,
        /// Remote guest route, repeatable: "<overlay_ipv4>=<nexthop_underlay_ipv6>=<vni>" where the
        /// nexthop is the remote interface's underlay /128. The outer L2 next-hop is the single
        /// underlay gateway set via --gateway-mac.
        #[arg(long = "remote")]
        remotes: Vec<String>,
        /// VIP mapping, repeatable: "<interface_ipv4>=<vip_ipv4>" (programs both VIPS directions).
        #[arg(long = "vip")]
        vips: Vec<String>,
        /// Load balancer service, repeatable: "<ipv4>:<port>:<proto>" (proto numeric: 1=ICMP,
        /// 6=TCP, 17=UDP). For ICMP use port 0. Allocates a Maglev table; add backends via
        /// --lb-target.
        #[arg(long = "lb")]
        lbs: Vec<String>,
        /// LB backend, repeatable: "<ipv4>:<port>:<proto>=<backend_ipv4>". References an --lb
        /// service and appends a backend, rebuilding that service's Maglev table.
        #[arg(long = "lb-target")]
        lb_targets: Vec<String>,
        /// NAT config, repeatable: "<guest_ipv4>=<nat_ipv4>:<port_min>:<port_max>".
        #[arg(long = "nat")]
        nats: Vec<String>,
        /// Mark a remote route external (NAT-eligible egress), repeatable: "<overlay_ipv4>".
        #[arg(long = "external")]
        externals: Vec<String>,
        /// Override the CONNTRACK map capacity (entries). Also settable via XDP_DP_CONNTRACK_MAX.
        #[arg(long)]
        conntrack_max: Option<u32>,
        /// Firewall rule, repeatable:
        /// "<ifname>:<in|eg>:<accept|drop>:<any|icmp|tcp|udp>:<src_cidr>:<dst_cidr>:<dport|*>".
        #[arg(long = "fw-rule")]
        fw_rules: Vec<String>,
        /// Whether the firewall actually drops on a deny (false = evaluate-only). Default true.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        firewall_enforce: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Load { uplink } => {
            let _ebpf = loader::attach_uplink(&uplink)?;
            println!("attached uplink_rx to {uplink}; ctrl-c to detach");
            tokio::signal::ctrl_c().await?;
        }
        Cmd::Serve {
            addr,
            uplink,
            local_underlay,
            gateway_mac,
            conntrack_max,
        } => {
            if let Some(n) = conntrack_max {
                // SAFETY: single-threaded CLI startup, before any datapath thread is spawned.
                std::env::set_var("XDP_DP_CONNTRACK_MAX", n.to_string());
            }
            let underlay = parse_ipv6(&local_underlay)?;
            let ctrl = control::Control::bring_up(
                &uplink,
                ifindex(&uplink)?,
                mac_of(&uplink)?,
                parse_mac(&gateway_mac)?,
                underlay,
            )?;
            if let Some(ct) = ctrl.take_conntrack() {
                tokio::spawn(conntrack_gc::run(ct, std::time::Duration::from_secs(10)));
            }
            let svc = grpc::Service {
                state: std::sync::Arc::new(state::State::default()),
                control: Some(std::sync::Arc::new(ctrl)),
                underlay,
            };
            let server = crate::pb::dpd_kironcore_server::DpdKironcoreServer::new(svc);
            println!("serving DPDKironcore on {addr}");
            tonic::transport::Server::builder()
                .add_service(server)
                .serve(addr.parse()?)
                .await?;
        }
        Cmd::Bringup {
            uplink,
            local_underlay,
            gateway,
            gateway_mac,
            guests,
            remotes,
            vips: vips_args,
            lbs,
            lb_targets,
            nats,
            externals,
            conntrack_max,
            fw_rules,
            firewall_enforce,
        } => {
            if let Some(n) = conntrack_max {
                // SAFETY: single-threaded CLI startup, before any datapath thread is spawned.
                std::env::set_var("XDP_DP_CONNTRACK_MAX", n.to_string());
            }
            let mut ebpf = loader::load_ebpf()?;

            // Pass 1: attach ALL XDP programs while ebpf is still fully intact
            // (take_map consumes map entries, but programs are separate — still need &mut ebpf).
            // uplink_rx: load + attach once.
            loader::attach_xdp(&mut ebpf, "uplink_rx", &uplink)?;
            // guest_tx: load once (first guest), then attach-only for additional guests.
            for (idx, g) in guests.iter().enumerate() {
                let mut it = g.splitn(3, '=');
                let ifname = it.next().context("--guest must be ifname=ipv4=mac")?;
                if idx == 0 {
                    loader::attach_xdp(&mut ebpf, "guest_tx", ifname)?;
                } else {
                    loader::attach_xdp_extra(&mut ebpf, "guest_tx", ifname)?;
                }
            }

            // Pass 2: open map wrappers (each calls take_map, consuming the map slot).
            let mut local_map = maps::LocalMap::open(&mut ebpf)?;
            local_map.set(&xdp_dp_common::Local {
                uplink_ifindex: ifindex(&uplink)?,
                uplink_mac: mac_of(&uplink)?,
                gateway_mac: parse_mac(&gateway_mac)?,
                underlay_ipv6: parse_ipv6(&local_underlay)?,
            })?;

            let gw = parse_ipv4(&gateway)?;
            let mut ports = maps::PortMetaMap::open(&mut ebpf)?;
            let mut ifaces = maps::Interfaces::open(&mut ebpf)?;
            let mut underlay_map = maps::Underlay::open(&mut ebpf)?;
            // --guest: "<ifname>=<overlay_ipv4>=<guest_mac>=<underlay_ipv6>=<vni>". The per-interface
            // underlay IPv6 is the interface's identity on the underlay; UNDERLAY maps it -> (vni,tap).
            for g in &guests {
                let f: Vec<&str> = g.split('=').collect();
                anyhow::ensure!(
                    f.len() == 5,
                    "--guest must be ifname=ipv4=mac=underlay_ipv6=vni, got {g:?}"
                );
                let ifname = f[0];
                let ip = parse_ipv4(f[1])?;
                let guest_mac = parse_mac(f[2])?;
                let underlay = parse_ipv6(f[3])?;
                let vni: u32 = f[4].parse().context("--guest: bad vni")?;
                let tap = ifindex(ifname)?;
                ports.upsert(
                    tap,
                    xdp_dp_common::PortMeta {
                        vni,
                        guest_ipv4: ip,
                        gateway_ipv4: gw,
                        guest_mac,
                        _pad: [0; 2],
                        underlay_ipv6: underlay,
                    },
                )?;
                ifaces.upsert(
                    xdp_dp_common::IfaceKey::new(vni, ip),
                    xdp_dp_common::IfaceValue {
                        tap_ifindex: tap,
                        is_local: 1,
                        underlay_ipv6: underlay,
                        guest_mac,
                        _pad: [0; 2],
                    },
                )?;
                underlay_map.upsert(
                    underlay,
                    xdp_dp_common::UnderlayValue {
                        vni,
                        tap_ifindex: tap,
                        guest_mac,
                        _pad: [0; 2],
                    },
                )?;
            }

            let external_set: std::collections::HashSet<[u8; 4]> = externals
                .iter()
                .map(|s| parse_ipv4(s))
                .collect::<anyhow::Result<_>>()?;
            let mut routes = maps::Routes::open(&mut ebpf)?;
            // --remote: "<overlay_ipv4>[/len]=<nexthop_underlay_ipv6>=<vni>" (nexthop = the remote
            // interface's underlay /128). An optional /prefix_len suffix enables CIDR routes;
            // bare IPs default to /32 (host route, behavior-preserving).
            for r in &remotes {
                let f: Vec<&str> = r.split('=').collect();
                anyhow::ensure!(
                    f.len() == 3,
                    "--remote must be overlay_ipv4=nexthop_underlay_ipv6=vni, got {r:?}"
                );
                let (ip_s, plen) = match f[0].split_once('/') {
                    Some((ip, l)) => (ip, l.parse::<u32>().context("--remote: bad prefix len")?),
                    None => (f[0], 32u32),
                };
                let ip = parse_ipv4(ip_s)?;
                let nh = parse_ipv6(f[1])?;
                let vni: u32 = f[2].parse().context("--remote: bad vni")?;
                routes.upsert(
                    vni,
                    ip,
                    plen,
                    xdp_dp_common::RouteValue {
                        nexthop_vni: vni,
                        nexthop_ipv6: nh,
                        is_external: external_set.contains(&ip) as u8,
                        _pad: [0; 3],
                    },
                )?;
            }

            let mut vip_map = maps::Vips::open(&mut ebpf)?;
            for v in &vips_args {
                let (g, vip) = v.split_once('=').context("--vip must be ifaceip=vipip")?;
                let g = parse_ipv4(g)?;
                let vip = parse_ipv4(vip)?;
                vip_map.upsert(xdp_dp_common::VipKey { vni: 0, ipv4: g }, vip)?; // (0,G)->V egress SNAT
                vip_map.upsert(xdp_dp_common::VipKey { vni: 0, ipv4: vip }, g)?;
                // (0,V)->G ingress DNAT
            }

            // Load balancers: each --lb allocates a Maglev table_id and an LB service entry;
            // each --lb-target appends a backend to the named service. After collecting all
            // backends we build + write the Maglev table for every service.
            let mut lb_map = maps::Lb::open(&mut ebpf)?;
            let mut maglev_map = maps::Maglev::open(&mut ebpf)?;
            let parse_lb_spec = |spec: &str| -> anyhow::Result<([u8; 4], u16, u8)> {
                let mut it = spec.split(':');
                let ip = parse_ipv4(it.next().context("--lb: missing ipv4")?)?;
                let port: u16 = it.next().context("--lb: missing port")?.parse()?;
                let proto: u8 = it.next().context("--lb: missing proto")?.parse()?;
                Ok((ip, port, proto))
            };
            let mut table_ids: std::collections::HashMap<([u8; 4], u16, u8), u32> =
                std::collections::HashMap::new();
            let mut backends: std::collections::HashMap<u32, Vec<[u8; 4]>> =
                std::collections::HashMap::new();
            let mut next_table_id = 1u32;
            for lb in &lbs {
                let (ip, port, proto) = parse_lb_spec(lb)?;
                let tid = next_table_id;
                next_table_id += 1;
                table_ids.insert((ip, port, proto), tid);
                backends.insert(tid, Vec::new());
                lb_map.upsert(
                    xdp_dp_common::LbKey {
                        vni: 0,
                        ipv4: ip,
                        port,
                        proto,
                        _pad: 0,
                    },
                    xdp_dp_common::LbValue {
                        table_id: tid,
                        size: maglev::TABLE_SIZE,
                    },
                )?;
            }
            for t in &lb_targets {
                let (spec, backend_str) = t
                    .split_once('=')
                    .context("--lb-target must be spec=backend")?;
                let (ip, port, proto) = parse_lb_spec(spec)?;
                let backend = parse_ipv4(backend_str)?;
                let tid = *table_ids
                    .get(&(ip, port, proto))
                    .context("--lb-target references an unknown --lb service")?;
                backends.get_mut(&tid).unwrap().push(backend);
            }
            for (tid, bes) in &backends {
                if bes.is_empty() {
                    continue;
                }
                let table = maglev::build(bes);
                for (slot, &bi) in table.iter().enumerate() {
                    maglev_map.upsert(
                        xdp_dp_common::MaglevKey {
                            table_id: *tid,
                            slot: slot as u32,
                        },
                        bes[bi as usize],
                    )?;
                }
            }

            // NAT-GW: each --nat programs (vni, guest_ip) -> (nat_ip, port_min, port_max). Egress
            // SNAT fires when the dst route is flagged external (see --external).
            let mut nat_map = maps::Nat::open(&mut ebpf)?;
            for n in &nats {
                let (gip_str, cfg) = n.split_once('=').context("--nat must be guestip=cfg")?;
                let gip = parse_ipv4(gip_str)?;
                let mut it = cfg.split(':');
                let nat_ip = parse_ipv4(it.next().context("--nat: missing nat ipv4")?)?;
                let port_min: u16 = it.next().context("--nat: missing port_min")?.parse()?;
                let port_max: u16 = it.next().context("--nat: missing port_max")?.parse()?;
                nat_map.upsert(
                    xdp_dp_common::NatKey { vni: 0, ipv4: gip },
                    xdp_dp_common::NatValue {
                        nat_ipv4: nat_ip,
                        port_min,
                        port_max,
                    },
                )?;
            }

            // Firewall: each --fw-rule programs a per-interface rule; rules are appended in order
            // to FW_RULES[(ifindex, slot)] and the per-direction counts to FW_META[ifindex].
            // Whitelist semantics live in the datapath (empty direction => accept).
            let mut fw_rules_map = maps::FwRules::open(&mut ebpf)?;
            let mut fw_meta_map = maps::FwMetaMap::open(&mut ebpf)?;
            let mut fw_config = maps::FwConfig::open(&mut ebpf)?;
            fw_config.set(if firewall_enforce { 1 } else { 0 })?;
            // ifindex -> (ingress_count, egress_count) accumulators while assigning slots.
            let mut fw_slots: std::collections::HashMap<u32, u32> =
                std::collections::HashMap::new();
            let mut fw_counts: std::collections::HashMap<u32, (u32, u32)> =
                std::collections::HashMap::new();
            let parse_cidr = |s: &str| -> anyhow::Result<([u8; 4], [u8; 4])> {
                let (ip_s, len_s) = s
                    .split_once('/')
                    .context("--fw-rule: cidr must be ip/len")?;
                let ip = parse_ipv4(ip_s)?;
                let len: u32 = len_s.parse().context("--fw-rule: bad prefix length")?;
                anyhow::ensure!(len <= 32, "--fw-rule: prefix length > 32");
                let mask = if len == 0 {
                    0u32
                } else {
                    u32::MAX << (32 - len)
                };
                Ok((ip, mask.to_be_bytes()))
            };
            for spec in &fw_rules {
                let f: Vec<&str> = spec.split(':').collect();
                anyhow::ensure!(
                    f.len() == 7,
                    "--fw-rule must be ifname:dir:action:proto:src_cidr:dst_cidr:dport, got {spec:?}"
                );
                let ifindex = ifindex(f[0])?;
                let direction = match f[1] {
                    "in" => xdp_dp_common::FW_DIR_INGRESS,
                    "eg" => xdp_dp_common::FW_DIR_EGRESS,
                    o => anyhow::bail!("--fw-rule dir must be in|eg, got {o}"),
                };
                let action = match f[2] {
                    "accept" => xdp_dp_common::FW_ACTION_ACCEPT,
                    "drop" => xdp_dp_common::FW_ACTION_DROP,
                    o => anyhow::bail!("--fw-rule action must be accept|drop, got {o}"),
                };
                let proto: u8 = match f[3] {
                    "any" => 0,
                    "icmp" => 1,
                    "tcp" => 6,
                    "udp" => 17,
                    o => anyhow::bail!("--fw-rule proto must be any|icmp|tcp|udp, got {o}"),
                };
                let (src_ip, src_mask) = parse_cidr(f[4])?;
                let (dst_ip, dst_mask) = parse_cidr(f[5])?;
                let (dst_port_min, dst_port_max) = if f[6] == "*" {
                    (0u16, 65535u16)
                } else {
                    let p: u16 = f[6].parse().context("--fw-rule: bad dport")?;
                    (p, p)
                };
                let slot = fw_slots.entry(ifindex).or_insert(0);
                anyhow::ensure!(
                    *slot < xdp_dp_common::FW_MAX_RULES,
                    "--fw-rule: more than {} rules for {}",
                    xdp_dp_common::FW_MAX_RULES,
                    f[0]
                );
                fw_rules_map.upsert(
                    xdp_dp_common::FwRuleKey {
                        ifindex,
                        idx: *slot,
                    },
                    xdp_dp_common::FwRule {
                        src_ip,
                        src_mask,
                        dst_ip,
                        dst_mask,
                        src_port_min: 0,
                        src_port_max: 65535,
                        dst_port_min,
                        dst_port_max,
                        icmp_type: 0xffff,
                        icmp_code: 0xffff,
                        proto,
                        action,
                        direction,
                        enabled: 1,
                    },
                )?;
                *slot += 1;
                let c = fw_counts.entry(ifindex).or_insert((0, 0));
                if direction == xdp_dp_common::FW_DIR_EGRESS {
                    c.1 += 1;
                } else {
                    c.0 += 1;
                }
            }
            for (ifindex, (ingress_count, egress_count)) in &fw_counts {
                fw_meta_map.upsert(
                    *ifindex,
                    xdp_dp_common::FwMeta {
                        ingress_count: *ingress_count,
                        egress_count: *egress_count,
                    },
                )?;
            }

            let ct = maps::Conntrack::open(&mut ebpf)?;
            tokio::spawn(conntrack_gc::run(ct, std::time::Duration::from_secs(10)));

            println!(
                "bringup: uplink={uplink} guests={} routes={} vips={} lbs={} nats={} fw={}; ctrl-c to stop",
                guests.len(),
                remotes.len(),
                vips_args.len(),
                lbs.len(),
                nats.len(),
                fw_rules.len()
            );
            tokio::signal::ctrl_c().await?;
        }
        Cmd::Pass { iface } => {
            let mut ebpf = loader::load_ebpf()?;
            loader::attach_xdp(&mut ebpf, "xdp_pass", &iface)?;
            println!("attached xdp_pass to {iface}; ctrl-c to detach");
            tokio::signal::ctrl_c().await?;
        }
        Cmd::Inspect { iface } => {
            let mut ebpf = loader::load_ebpf()?;

            // Try native (driver) mode first; fall back to SKB (generic) mode if rejected.
            let prog: &mut aya::programs::Xdp = ebpf
                .program_mut("xdp_inspect")
                .context("xdp_inspect program missing")?
                .try_into()?;
            prog.load().context("verify xdp_inspect")?;
            let mode = match prog.attach(&iface, aya::programs::XdpFlags::default()) {
                Ok(_) => "native/driver",
                Err(native_err) => {
                    eprintln!("native attach failed ({native_err}), retrying with SKB_MODE");
                    prog.attach(&iface, aya::programs::XdpFlags::SKB_MODE)
                        .with_context(|| format!("attach xdp_inspect to {iface} (SKB_MODE)"))?;
                    "SKB/generic"
                }
            };
            println!("xdp_inspect attached to {iface} in {mode} mode");

            let inspect = maps::InspectMap::open(&mut ebpf)?;

            let mut prev_seen = 0u32;
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                        match inspect.get() {
                            Ok(e) => {
                                if e.seen != prev_seen {
                                    prev_seen = e.seen;
                                    let hex: String = e.bytes.iter()
                                        .map(|b| format!("{b:02x}"))
                                        .collect::<Vec<_>>()
                                        .join(" ");
                                    // Probe multiple offsets for the ethertype-like u16.
                                    let et12 = u16::from_be_bytes([e.bytes[12], e.bytes[13]]);
                                    let et10 = u16::from_be_bytes([e.bytes[10], e.bytes[11]]);
                                    let et14 = u16::from_be_bytes([e.bytes[14], e.bytes[15]]);
                                    let et22 = u16::from_be_bytes([e.bytes[22], e.bytes[23]]);
                                    println!(
                                        "seen={} len={} bytes=[{hex}] \
                                         et@10={et10:#06x} et@12={et12:#06x} et@14={et14:#06x} et@22={et22:#06x}",
                                        e.seen, e.len,
                                    );
                                }
                            }
                            Err(e) => eprintln!("inspect read error: {e}"),
                        }
                    }
                }
            }
            println!("detaching");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests (no root required)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mac_valid() {
        assert_eq!(parse_mac("02:00:00:00:00:01").unwrap(), [2, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn parse_mac_rejects_bad_octet() {
        assert!(parse_mac("zz:00:00:00:00:01").is_err());
    }

    #[test]
    fn parse_mac_rejects_too_short() {
        assert!(parse_mac("02:00:00:00:00").is_err());
    }

    #[test]
    fn parse_mac_rejects_too_long() {
        assert!(parse_mac("02:00:00:00:00:01:ff").is_err());
    }

    #[test]
    fn parse_ipv4_basic() {
        assert_eq!(parse_ipv4("10.0.0.5").unwrap(), [10, 0, 0, 5]);
    }

    #[test]
    fn parse_ipv4_rejects_garbage() {
        assert!(parse_ipv4("not-an-ip").is_err());
    }

    #[test]
    fn parse_ipv6_last_byte() {
        let octets = parse_ipv6("fd00::1").unwrap();
        assert_eq!(octets[15], 1);
    }

    #[test]
    fn parse_ipv6_rejects_garbage() {
        assert!(parse_ipv6("not-an-ip").is_err());
    }
}
