pub mod pb {
    tonic::include_proto!("dpdkironcore.v1");
}

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
fn ifindex(iface: &str) -> anyhow::Result<u32> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .with_context(|| format!("read ifindex for {iface}"))?;
    Ok(s.trim().parse()?)
}

/// Read `/sys/class/net/<iface>/address` and return 6 MAC bytes.
fn mac_of(iface: &str) -> anyhow::Result<[u8; 6]> {
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
    /// Start the gRPC control-plane server.
    Serve {
        #[arg(long)]
        addr: String,
    },
    /// Attach both XDP programs and populate CONFIG[0], then idle until ctrl-c.
    Bringup {
        /// Guest-facing interface name (guest_tx is attached here).
        #[arg(long)]
        guest: String,
        /// Uplink-facing interface name (uplink_rx is attached here).
        #[arg(long)]
        uplink: String,
        /// Overlay VNI.
        #[arg(long)]
        vni: u32,
        /// This hypervisor's underlay IPv6 address (outer src on encap).
        #[arg(long)]
        local_underlay: String,
        /// Peer hypervisor's underlay IPv6 address (outer dst on encap).
        #[arg(long)]
        peer_underlay: String,
        /// Peer uplink MAC address (outer eth dst on encap), e.g. 02:00:00:00:00:02.
        #[arg(long)]
        peer_mac: String,
        /// Guest MAC address (inner eth dst on decap), e.g. 02:00:00:00:00:0a.
        #[arg(long)]
        guest_mac: String,
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
        Cmd::Serve { addr } => {
            let svc = grpc::Service {
                state: std::sync::Arc::new(state::State::default()),
            };
            let server = crate::pb::dpd_kironcore_server::DpdKironcoreServer::new(svc);
            println!("serving DPDKironcore on {addr}");
            tonic::transport::Server::builder()
                .add_service(server)
                .serve(addr.parse()?)
                .await?;
        }
        Cmd::Bringup {
            guest,
            uplink,
            vni,
            local_underlay,
            peer_underlay,
            peer_mac,
            guest_mac,
        } => {
            let mut ebpf = loader::load_ebpf()?;
            loader::attach_xdp(&mut ebpf, "guest_tx", &guest)?;
            loader::attach_xdp(&mut ebpf, "uplink_rx", &uplink)?;
            let cfg = xdp_dp_common::Config {
                vni,
                uplink_ifindex: ifindex(&uplink)?,
                guest_ifindex: ifindex(&guest)?,
                _pad: 0,
                local_underlay_ipv6: parse_ipv6(&local_underlay)?,
                peer_underlay_ipv6: parse_ipv6(&peer_underlay)?,
                local_mac: mac_of(&uplink)?,
                peer_mac: parse_mac(&peer_mac)?,
                guest_mac: parse_mac(&guest_mac)?,
                _pad2: [0; 2],
            };
            let mut config_map = maps::ConfigMap::open(&mut ebpf)?;
            config_map.set(&cfg)?;
            println!(
                "bringup: guest={guest}(if{}) uplink={uplink}(if{}) vni={vni}; CONFIG written; ctrl-c to stop",
                cfg.guest_ifindex, cfg.uplink_ifindex
            );
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
    fn parse_ipv6_last_byte() {
        let octets = parse_ipv6("fd00::1").unwrap();
        assert_eq!(octets[15], 1);
    }

    #[test]
    fn parse_ipv6_rejects_garbage() {
        assert!(parse_ipv6("not-an-ip").is_err());
    }
}
