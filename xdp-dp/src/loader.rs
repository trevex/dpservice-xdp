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

/// Attach a named XDP program in an already-loaded `Ebpf` to an interface.
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
