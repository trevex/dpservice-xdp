{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
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

  outputs = { self, nixpkgs, rust-overlay, flake-utils, go-overlay, git-hooks, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) go-overlay.overlays.default ];
        pkgs = import nixpkgs { inherit system overlays; };
        # Single nightly toolchain (no rustup on this host): the ambient cargo must be
        # nightly so it can build the eBPF crate for the BPF target via -Z build-std=core.
        # selectLatestNightlyWith pins to the latest nightly in the locked rust-overlay.
        # rust-src is required so `-Z build-std=core` can compile core for the BPF target.
        # NOTE: bpfel-unknown-none is a built-in rustc target compiled via build-std; it is
        # NOT a downloadable rustup `targets` component, so it must not be listed there.
        rustToolchain = pkgs.rust-bin.selectLatestNightlyWith (toolchain:
          toolchain.default.override {
            extensions = [ "rust-src" "rust-analyzer" "rustfmt" "clippy" ];
          });
        go = pkgs.go-bin.latest;
        pre-commit-check = git-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            rustfmt = {
              enable = true;
              packageOverrides = { cargo = rustToolchain; rustfmt = rustToolchain; };
            };
            clippy = {
              enable = true;
              packageOverrides = { cargo = rustToolchain; clippy = rustToolchain; };
            };
          };
        };
      in
      {
        devShells.default = pkgs.mkShell {
          inherit (pre-commit-check) shellHook;

          buildInputs = [
            rustToolchain
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
          ];

          packages = [
            pkgs.just
          ];

          RUST_BACKTRACE = 1;
          PROTOC = "${pkgs.protobuf}/bin/protoc";
        };
      });
}
