#!/usr/bin/env bash
# Build the veth topology the conformance harness expects. For each dpservice device we create a
# veth pair: the dpservice-named end (scapy side) <-> an xdp-side end (xdp-dp attaches here).
# xdp_pass enablers go on the scapy-side ends so bpf_redirect into them lands.
set -euo pipefail

BIN="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/xdp-dp"
PIDFILE="${TMPDIR:-/tmp}/xdp-conf-pids"

declare -A MAC=( [dtap0]=22:22:22:22:22:00 [dtap1]=22:22:22:22:22:01 \
                 [dtapvf_0]=66:66:66:66:66:00 [dtapvf_1]=66:66:66:66:66:01 \
                 [dtapvf_2]=66:66:66:66:66:02 [dtapvf_3]=66:66:66:66:66:03 )

xside() { echo "x${1}"; }   # dtapvf_0 -> xdtapvf_0

up() {
  : > "$PIDFILE"
  for dev in dtap0 dtap1 dtapvf_0 dtapvf_1 dtapvf_2 dtapvf_3; do
    x="$(xside "$dev")"
    sudo ip link add "$dev" type veth peer name "$x" 2>/dev/null || true
    sudo ip link set "$x" address "${MAC[$dev]}"   # xdp side carries the dpservice MAC (guest_mac)
    sudo ip link set "$dev" up; sudo ip link set "$x" up
    sudo "$BIN" pass --iface "$dev" & echo $! >> "$PIDFILE"   # enabler on the scapy side
  done
}

down() {
  [[ -f "$PIDFILE" ]] && { while read -r p; do sudo kill "$p" 2>/dev/null||true; done < "$PIDFILE"; rm -f "$PIDFILE"; }
  sudo pkill -f 'xdp-dp (serve|pass) --' 2>/dev/null || true
  for dev in dtap0 dtap1 dtapvf_0 dtapvf_1 dtapvf_2 dtapvf_3; do sudo ip link del "$dev" 2>/dev/null || true; done
}

case "${1:-}" in up) up;; down) down;; *) echo "usage: $0 up|down" >&2; exit 1;; esac
