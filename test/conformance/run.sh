#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

cargo build -p xdp-dp

trap './test/conformance/setup-net.sh down' EXIT INT TERM
./test/conformance/setup-net.sh up

# Run the non-DHCP suite. scapy needs CAP_NET_RAW, so pytest runs as root via the flake devShell's
# self-contained python env (resolves scapy/pytest without PYTHONPATH even under sudo). dp_service.py
# launches `xdp-dp serve` (itself via sudo); conftest waits for the gRPC port.
ROOT="$(git rev-parse --show-toplevel)"
PYBIN="$(nix develop "$ROOT" -c bash -c 'command -v python3')"
cd "$ROOT/test/conformance"
TESTS="${CONF_TESTS:-test_vf_to_vf.py test_vf_to_pf.py test_pf_to_vf.py test_encap.py \
  test_arp.py test_ipv6_nd.py test_flows.py test_lb.py test_nat.py test_vni.py test_zzz_grpc.py}"
sudo "$PYBIN" -m pytest -q $TESTS --build-path="$ROOT" "$@"
