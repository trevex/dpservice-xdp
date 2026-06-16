use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;

/// Load the eBPF object that aya-build compiled to bpfel and placed in OUT_DIR.
pub fn load_ebpf() -> anyhow::Result<Ebpf> {
    Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xdp-dp-prog"
    )))
    .context("load ebpf object")
}

/// Load the eBPF object and attach `uplink_rx` to the named uplink interface.
pub fn attach_uplink(iface: &str) -> anyhow::Result<Ebpf> {
    let mut ebpf = load_ebpf()?;
    let prog: &mut Xdp = ebpf
        .program_mut("uplink_rx")
        .context("uplink_rx program missing")?
        .try_into()?;
    prog.load().context("verify uplink_rx")?;
    prog.attach(iface, XdpFlags::default())
        .with_context(|| format!("attach uplink_rx to {iface}"))?;
    Ok(ebpf)
}
