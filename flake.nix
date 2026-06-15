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
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "rustfmt" "clippy" ];
          targets = [ "wasm32-unknown-unknown" ];
        };
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
          ];

          packages = [
            pkgs.just
          ];

          RUST_BACKTRACE = 1;
        };
      });
}
