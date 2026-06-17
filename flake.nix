{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    go-overlay = {
      url = "github:purpleclay/go-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    git-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, go-overlay, git-hooks, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ go-overlay.overlays.default ];
        pkgs = import nixpkgs { inherit system overlays; };
        go = pkgs.go-bin.latest;
        # Rust is managed entirely by rustup (community-standard for aya/aya-build), pinned
        # via rust-toolchain.toml to nightly-2026-01-15 (LLVM 21) to match nixpkgs bpf-linker.
        # The pre-commit rustfmt/clippy hooks therefore run through rustup too (system hooks
        # invoking `cargo fmt` / `cargo clippy`), so there is exactly one Rust toolchain.
        pre-commit-check = git-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            rustfmt-rustup = {
              enable = true;
              name = "rustfmt (rustup)";
              entry = "cargo fmt --all -- --check";
              language = "system";
              pass_filenames = false;
              files = "\\.rs$";
            };
            clippy-rustup = {
              enable = true;
              name = "clippy (rustup)";
              # default-members excludes xdp-dp-ebpf, so the host build never tries to compile
              # the #![no_main] eBPF bin; the ebpf object is built via aya-build from build.rs.
              entry = "cargo clippy --all-targets";
              language = "system";
              pass_filenames = false;
              files = "\\.rs$";
            };
          };
        };
      in
      {
        devShells.default = pkgs.mkShell {
          inherit (pre-commit-check) shellHook;

          buildInputs = [
            pkgs.rustup
            go.withDefaultTools
            pkgs.cargo-watch
            pkgs.cargo-edit
            pkgs.cargo-nextest
            pkgs.wasm-tools
            pkgs.mdbook
            pkgs.mdbook-mermaid
            # eBPF + gRPC + VM harness tooling
            pkgs.bpf-linker
            pkgs.protobuf
            pkgs.grpcurl
            pkgs.qemu
            pkgs.libvirt
            pkgs.OVMF
            pkgs.iproute2
            pkgs.bridge-utils
            pkgs.kubectl
            pkgs.socat
            pkgs.python3  # serial-console driver for env/tap-vm-smoke.sh
          ];

          packages = [
            pkgs.just
          ];

          RUST_BACKTRACE = 1;
          PROTOC = "${pkgs.protobuf}/bin/protoc";
        };
      });
}
