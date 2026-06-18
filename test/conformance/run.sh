#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

cargo build -p xdp-dp

trap './test/conformance/setup-net.sh down' EXIT INT TERM
./test/conformance/setup-net.sh up

# Run the non-DHCP suite via the flake devShell python (scapy+pytest). dp_service.py launches
# xdp-dp serve via the patched cmd; conftest waits for the gRPC port.
cd test/conformance
nix develop "$(git rev-parse --show-toplevel)" -c python3 -m pytest -q \
  test_vf_to_vf.py test_vf_to_pf.py test_pf_to_vf.py test_encap.py \
  test_arp.py test_ipv6_nd.py test_flows.py test_lb.py test_nat.py test_vni.py test_zzz_grpc.py \
  --build-path="$(git rev-parse --show-toplevel)" "$@"
