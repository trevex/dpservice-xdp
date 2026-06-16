use anyhow::{anyhow, Context as _};
use aya_build::{Package, Toolchain};

fn main() -> anyhow::Result<()> {
    // 1) Compile the eBPF object via aya-build (unchanged from Task 5).
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
    )?;

    // 2) Generate the DPDKironcore gRPC service (server only).
    tonic_build::configure()
        .build_client(false)
        .compile_protos(&["../proto/dpdk.proto"], &["../proto"])
        .context("tonic-build compile dpdk.proto")?;
    println!("cargo:rerun-if-changed=../proto/dpdk.proto");
    // Re-run aya-build when the eBPF crate sources change. Without this, the build.rs has a
    // rerun-if-changed directive (the proto above), so cargo would otherwise NOT re-run it on
    // edits to xdp-dp-ebpf/src/*.rs (the build-dependency edge only covers that crate's lib
    // target, not its bin), leaving a stale embedded object.
    println!("cargo:rerun-if-changed=../xdp-dp-ebpf/src");
    println!("cargo:rerun-if-changed=../xdp-dp-ebpf/Cargo.toml");
    Ok(())
}
