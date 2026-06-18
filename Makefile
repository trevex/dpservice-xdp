# ironcore-net-xdp — common workflows.
#
# Every target runs inside the flake devShell (`nix develop -c ...`), so all tooling — the Rust
# toolchain (rustup), bpf-linker, protobuf, python3+scapy+pytest, the genuine dpservice-cli, qemu,
# iproute2, ethtool, tcpdump — comes from the flake. There are no host-specific paths.
#
# The conformance / e2e / ha / tap targets need passwordless sudo (XDP attach, netns, raw sockets);
# the scripts elevate individual commands themselves.

NIX := nix develop -c

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# --- build -----------------------------------------------------------------
.PHONY: build
build: ## Build the xdp-dp binary (host crates + the eBPF object via aya-build)
	$(NIX) cargo build -p xdp-dp

.PHONY: release
release: ## Build the xdp-dp binary in release mode
	$(NIX) cargo build -p xdp-dp --release

.PHONY: cli
cli: ## Build the genuine dpservice-cli (flake package) into ./result
	nix build .#dpservice-cli

# --- quality ---------------------------------------------------------------
.PHONY: fmt
fmt: ## Format all Rust code
	$(NIX) cargo fmt --all

.PHONY: lint
lint: ## Clippy across all targets (host crates)
	$(NIX) cargo clippy --all-targets

.PHONY: check
check: ## fmt --check + clippy (what the pre-commit hooks run)
	$(NIX) cargo fmt --all -- --check
	$(NIX) cargo clippy --all-targets

# --- tests -----------------------------------------------------------------
.PHONY: test
test: ## Host unit + POD-layout tests (no root needed)
	$(NIX) cargo test -p xdp-dp-common -p xdp-dp

.PHONY: verifier
verifier: ## Load both XDP programs through the kernel verifier (needs root)
	$(NIX) cargo test -p xdp-dp both_programs_pass_verifier -- --ignored

.PHONY: conformance
conformance: ## dpservice conformance suite vs `xdp-dp serve` (veth harness; needs sudo)
	$(NIX) ./test/conformance/run.sh

.PHONY: e2e
e2e: ## 3-node netns end-to-end overlay test (needs sudo)
	$(NIX) ./test/netns-e2e.sh run

.PHONY: ha
ha: ## HA pinned-maps smoke (kill+adopt; needs sudo)
	$(NIX) ./test/ha-smoke.sh run

.PHONY: tap-dhcp-probe
tap-dhcp-probe: ## Native-mode DHCP frame-growth fidelity probe on a real tap (needs sudo)
	$(NIX) ./test/tap-dhcp-probe.sh

.PHONY: tap-vm-smoke
tap-vm-smoke: ## Boot a CirrOS VM on a real tap and verify guest_tx/ARP (needs sudo + KVM)
	$(NIX) ./test/tap-vm-smoke.sh run

.PHONY: test-all
test-all: test e2e ha conformance ## Run the full local test matrix (needs sudo)

# --- housekeeping ----------------------------------------------------------
.PHONY: clean
clean: ## Remove build artifacts
	$(NIX) cargo clean
	rm -rf result
