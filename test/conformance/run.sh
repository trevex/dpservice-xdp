#!/usr/bin/env bash
# Run the vendored dpservice conformance suite against `xdp-dp serve`.
# Expects the flake devShell on PATH (python3+scapy+pytest, dpservice-cli). The Makefile runs it
# via `nix develop`; standalone: `nix develop -c ./test/conformance/run.sh`.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

cargo build -p xdp-dp

# Absolute path: the trap fires at EXIT from whatever cwd we ended in (we cd into test/conformance
# before pytest), so a relative path would not resolve.
SETUP_NET="$ROOT/test/conformance/setup-net.sh"
trap '"$SETUP_NET" down' EXIT INT TERM
"$SETUP_NET" up

# scapy needs CAP_NET_RAW, so pytest runs as root. Use the flake python by absolute path (it is
# self-contained, so it resolves scapy/pytest even under sudo, which resets PATH). The genuine
# dpservice-cli (the gRPC client the tests shell out to) is provided by the flake; pass its
# absolute path through sudo so the root-run grpc_client.py finds it.
PYBIN="$(command -v python3)"
CLI="$(command -v dpservice-cli)"
cd "$ROOT/test/conformance"
TESTS="${CONF_TESTS:-test_vf_to_vf.py test_vf_to_pf.py test_pf_to_vf.py test_encap.py \
  test_arp.py test_ipv6_nd.py test_flows.py test_lb.py test_nat.py test_vni.py test_zzz_grpc.py \
  test_dhcpv4.py}"
sudo "DPSERVICE_CLI=$CLI" "$PYBIN" -m pytest -q $TESTS --build-path="$ROOT" "$@"
