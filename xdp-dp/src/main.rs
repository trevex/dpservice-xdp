pub mod pb {
    tonic::include_proto!("dpdkironcore.v1");
}

mod control;
mod grpc;
mod loader;
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
    },
    /// Attach the trivial xdp_pass program to an interface (redirect-target enabler), then idle.
    Pass {
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
        /// Local guest, repeatable: "<ifname>=<overlay_ipv4>=<guest_mac>" where <guest_mac> is
        /// the MAC of the guest interface inside the guest netns (inner eth dst on decap delivery).
        /// guest_tx attaches to <ifname> (the hypervisor-side veth peer).
        #[arg(long = "guest")]
        guests: Vec<String>,
        /// Remote guest route, repeatable: "<overlay_ipv4>=<nexthop_ipv6>". MAC-free — the outer
        /// L2 next-hop is the single underlay gateway set via --gateway-mac, not per-route.
        #[arg(long = "remote")]
        remotes: Vec<String>,
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
        } => {
            let underlay = parse_ipv6(&local_underlay)?;
            let ctrl = control::Control::bring_up(
                &uplink,
                ifindex(&uplink)?,
                mac_of(&uplink)?,
                parse_mac(&gateway_mac)?,
                underlay,
            )?;
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
        } => {
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
            for g in &guests {
                let mut it = g.splitn(3, '=');
                let ifname = it.next().context("--guest must be ifname=ipv4=mac")?;
                let ip_str = it.next().context("--guest must be ifname=ipv4=mac")?;
                let mac_str = it.next().context("--guest must be ifname=ipv4=mac")?;
                let ip = parse_ipv4(ip_str)?;
                let guest_mac = parse_mac(mac_str)?;
                let tap = ifindex(ifname)?;
                ports.upsert(
                    tap,
                    xdp_dp_common::PortMeta {
                        vni: 0,
                        guest_ipv4: ip,
                        gateway_ipv4: gw,
                        guest_mac,
                        _pad: [0; 2],
                    },
                )?;
                ifaces.upsert(
                    xdp_dp_common::IfaceKey::new(0, ip),
                    xdp_dp_common::IfaceValue {
                        tap_ifindex: tap,
                        is_local: 1,
                        underlay_ipv6: parse_ipv6(&local_underlay)?,
                        guest_mac,
                        _pad: [0; 2],
                    },
                )?;
            }

            let mut routes = maps::Routes::open(&mut ebpf)?;
            for r in &remotes {
                let mut it = r.splitn(2, '=');
                let ip = parse_ipv4(it.next().context("remote: missing overlay ipv4")?)?;
                let nh = parse_ipv6(it.next().context("remote: missing nexthop ipv6")?)?;
                routes.upsert(
                    xdp_dp_common::RouteKey {
                        vni: 0,
                        prefix_len: 32,
                        ipv4: ip,
                    },
                    xdp_dp_common::RouteValue {
                        nexthop_vni: 0,
                        nexthop_ipv6: nh,
                    },
                )?;
            }

            println!(
                "bringup: uplink={uplink} guests={} routes={}; ctrl-c to stop",
                guests.len(),
                remotes.len()
            );
            tokio::signal::ctrl_c().await?;
        }
        Cmd::Pass { iface } => {
            let mut ebpf = loader::load_ebpf()?;
            loader::attach_xdp(&mut ebpf, "xdp_pass", &iface)?;
            println!("attached xdp_pass to {iface}; ctrl-c to detach");
            tokio::signal::ctrl_c().await?;
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
