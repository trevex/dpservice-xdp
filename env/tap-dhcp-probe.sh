#!/usr/bin/env bash
# env/tap-dhcp-probe.sh — wrapper for tap-dhcp-probe.py.
# Builds xdp-dp, resolves the flake python (scapy), then runs the probe under sudo.
# See tap-dhcp-probe.py for what it proves (native-mode DHCP frame-growth on a real tap).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

cargo build -p xdp-dp >/dev/null 2>&1
PYBIN="/nix/store/jk8blrf778rkcvfga9fqkkc6z6i2m4kx-python3-3.13.13-env/bin/python3"
[ -x "$PYBIN" ] || PYBIN="$(nix develop "$ROOT" -c bash -c 'command -v python3')"

# Clean any leftovers from a prior aborted run.
sudo pkill -f 'xdp-dp bringup --uplink dhu0' 2>/dev/null || true
sudo ip link del dhg0 2>/dev/null || true
sudo ip link del dhu0 2>/dev/null || true
sleep 1

sudo "$PYBIN" "$ROOT/env/tap-dhcp-probe.py"
