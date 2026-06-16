use anyhow::{anyhow, Context as _};
use aya_build::{Package, Toolchain};

fn main() -> anyhow::Result<()> {
    // Locate the xdp-dp-ebpf package and compile its bin to bpfel via build-std + bpf-linker.
    // aya-build places the resulting object at $OUT_DIR/xdp-dp-ebpf.
    let metadata = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("cargo metadata")?;
    let ebpf = metadata
        .packages
        .into_iter()
        .find(|p| p.name.as_str() == "xdp-dp-ebpf")
        .ok_or_else(|| anyhow!("xdp-dp-ebpf package not found"))?;
    let root_dir = ebpf
        .manifest_path
        .parent()
        .ok_or_else(|| anyhow!("no parent dir for {}", ebpf.manifest_path))?
        .to_string();
    aya_build::build_ebpf(
        [Package {
            name: "xdp-dp-ebpf",
            root_dir: root_dir.as_str(),
            ..Default::default()
        }],
        Toolchain::Custom("nightly-2026-01-15"),
    )
}
