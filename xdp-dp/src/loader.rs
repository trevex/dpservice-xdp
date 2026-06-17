use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;

/// Load the eBPF object that aya-build compiled to bpfel and placed in OUT_DIR.
///
/// BPF map sizes can be overridden at load time via environment variables, allowing operators to
/// tune hot maps per node role without recompiling:
///
/// | Map        | Env var                  | Compile-time default |
/// |------------|--------------------------|----------------------|
/// | CONNTRACK  | XDP_DP_CONNTRACK_MAX     | 1_048_576            |
/// | ROUTES     | XDP_DP_ROUTES_MAX        | 4_096                |
/// | INTERFACES | XDP_DP_INTERFACES_MAX    | 1_024                |
/// | MAGLEV     | XDP_DP_MAGLEV_MAX        | 65_536               |
/// | NAT        | XDP_DP_NAT_MAX           | 1_024                |
/// | LB         | XDP_DP_LB_MAX            | 1_024                |
/// | PORT_META  | XDP_DP_PORT_META_MAX     | 1_024                |
///
/// Unset variables leave the compile-time `with_max_entries` default in place.
pub fn load_ebpf() -> anyhow::Result<Ebpf> {
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp-dp-prog"));
    let mut loader = aya::EbpfLoader::new();
    // Map name -> env var. Unset => keep the compile-time `with_max_entries` default.
    for (map, var) in [
        ("CONNTRACK", "XDP_DP_CONNTRACK_MAX"),
        ("ROUTES", "XDP_DP_ROUTES_MAX"),
        ("INTERFACES", "XDP_DP_INTERFACES_MAX"),
        ("MAGLEV", "XDP_DP_MAGLEV_MAX"),
        ("NAT", "XDP_DP_NAT_MAX"),
        ("LB", "XDP_DP_LB_MAX"),
        ("PORT_META", "XDP_DP_PORT_META_MAX"),
    ] {
        if let Ok(v) = std::env::var(var) {
            let n: u32 = v
                .parse()
                .with_context(|| format!("{var} must be a u32, got {v:?}"))?;
            loader.set_max_entries(map, n);
        }
    }
    loader.load(bytes).context("load ebpf object")
}

/// Load (verify) and attach a named XDP program to one interface. Call this for the first
/// interface; use `attach_xdp_loaded` for subsequent interfaces with the same program name.
pub fn attach_xdp(ebpf: &mut Ebpf, prog_name: &str, iface: &str) -> anyhow::Result<()> {
    let prog: &mut Xdp = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("{prog_name} program missing"))?
        .try_into()?;
    prog.load().with_context(|| format!("verify {prog_name}"))?;
    prog.attach(iface, XdpFlags::default())
        .with_context(|| format!("attach {prog_name} to {iface}"))?;
    Ok(())
}

/// Attach an already-loaded XDP program to an additional interface (skips the `load()` call).
pub fn attach_xdp_extra(ebpf: &mut Ebpf, prog_name: &str, iface: &str) -> anyhow::Result<()> {
    let prog: &mut Xdp = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("{prog_name} program missing"))?
        .try_into()?;
    prog.attach(iface, XdpFlags::default())
        .with_context(|| format!("attach {prog_name} to {iface}"))?;
    Ok(())
}

/// Load the eBPF object and attach `uplink_rx` to the named uplink interface.
pub fn attach_uplink(iface: &str) -> anyhow::Result<Ebpf> {
    let mut ebpf = load_ebpf()?;
    attach_xdp(&mut ebpf, "uplink_rx", iface)?;
    Ok(ebpf)
}

#[cfg(test)]
mod tests {
    use aya::programs::Xdp;

    #[test]
    #[ignore = "requires root/CAP_BPF; loads programs through the verifier"]
    fn both_programs_pass_verifier() {
        let mut ebpf = super::load_ebpf().expect("load ebpf object");
        for name in ["uplink_rx", "guest_tx"] {
            let prog: &mut Xdp = ebpf
                .program_mut(name)
                .unwrap_or_else(|| panic!("program {name} missing"))
                .try_into()
                .expect("is xdp");
            prog.load()
                .unwrap_or_else(|e| panic!("verifier rejected {name}: {e}"));
        }
    }
}
