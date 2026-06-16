#!/usr/bin/env bash
# env/netns-e2e.sh — netns-based end-to-end test for the XDP IP-in-IPv6 overlay.
#
# Topology:
#   guesta(10.0.0.5/gA) <-> hypa(gA-h / uA) <-> [uA-br] br-ul [uB-br] <-> hypb(uB / gB-h) <-> guestb(10.0.0.6/gB)
#
# Usage (run from repo root):
#   ./env/netns-e2e.sh up       create namespaces + bridge, attach XDP datapath
#   ./env/netns-e2e.sh test     ping guesta->guestb; show encap tcpdump evidence
#   ./env/netns-e2e.sh down     kill daemons, tear down all namespaces/links/bridge
#   ./env/netns-e2e.sh run      up + test + down  (with cleanup on error)
#
# Requirements:
#   - Passwordless sudo
#   - cargo build -p xdp-dp must have been run (binary at target/debug/xdp-dp)
#   - tcpdump in Nix store (detected automatically)
set -euo pipefail

BIN="$(pwd)/target/debug/xdp-dp"
PIDFILE="/run/xdp-e2e-pids"
IP6TABLES_MARK="xdp-e2e"  # comment tag to identify our rules

# Locate tcpdump: first in PATH, then well-known Nix store paths.
TCPDUMP=""
if command -v tcpdump &>/dev/null; then
    TCPDUMP="$(command -v tcpdump)"
else
    for p in /nix/store/*/bin/tcpdump; do
        if [[ -x "$p" ]]; then
            TCPDUMP="$p"
            break
        fi
    done
fi

die() { echo "ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
cmd_up() {
    [[ -x "$BIN" ]] || die "binary not found at $BIN — run: cargo build -p xdp-dp"

    # ---- bridge ----
    sudo ip link add br-ul type bridge 2>/dev/null || true
    sudo ip link set br-ul up
    # Disable multicast snooping so IPv6 multicast (NDP, ping) crosses the bridge
    sudo ip link set br-ul type bridge mcast_snooping 0

    # ---- namespaces ----
    for ns in hypa hypb guesta guestb; do
        sudo ip netns add "$ns" 2>/dev/null || true
        sudo ip netns exec "$ns" ip link set lo up
    done

    # ---- hypa uplink: uA in hypa <-> uA-br on bridge ----
    if ! sudo ip netns exec hypa ip link show uA &>/dev/null; then
        sudo ip link add uA netns hypa type veth peer name uA-br
    fi
    sudo ip link set uA-br master br-ul 2>/dev/null || true
    sudo ip link set uA-br up
    sudo ip netns exec hypa ip link set uA up
    sudo ip netns exec hypa ip -6 addr add fd00::1/64 dev uA nodad 2>/dev/null || true

    # ---- hypa guest link: gA-h in hypa <-> gA in guesta ----
    if ! sudo ip netns exec hypa ip link show gA-h &>/dev/null; then
        sudo ip link add gA-h netns hypa type veth peer name gA netns guesta
    fi
    sudo ip netns exec hypa ip link set gA-h up
    sudo ip netns exec guesta ip link set gA up
    sudo ip netns exec guesta ip addr add 10.0.0.5/24 dev gA 2>/dev/null || true

    # ---- hypb uplink: uB in hypb <-> uB-br on bridge ----
    if ! sudo ip netns exec hypb ip link show uB &>/dev/null; then
        sudo ip link add uB netns hypb type veth peer name uB-br
    fi
    sudo ip link set uB-br master br-ul 2>/dev/null || true
    sudo ip link set uB-br up
    sudo ip netns exec hypb ip link set uB up
    sudo ip netns exec hypb ip -6 addr add fd00::2/64 dev uB nodad 2>/dev/null || true

    # ---- hypb guest link: gB-h in hypb <-> gB in guestb ----
    if ! sudo ip netns exec hypb ip link show gB-h &>/dev/null; then
        sudo ip link add gB-h netns hypb type veth peer name gB netns guestb
    fi
    sudo ip netns exec hypb ip link set gB-h up
    sudo ip netns exec guestb ip link set gB up
    sudo ip netns exec guestb ip addr add 10.0.0.6/24 dev gB 2>/dev/null || true

    # ---- ip6tables: allow bridge forwarding on br-ul ----
    # Docker sets ip6tables FORWARD policy to DROP with bridge-nf-call-ip6tables=1.
    # We add scoped ACCEPT rules for br-ul instead of touching any global sysctl.
    sudo ip6tables -I FORWARD 1 -i br-ul -o br-ul -j ACCEPT -m comment --comment "$IP6TABLES_MARK" 2>/dev/null || true
    sudo ip6tables -I FORWARD 2 -i uA-br -j ACCEPT -m comment --comment "$IP6TABLES_MARK" 2>/dev/null || true
    sudo ip6tables -I FORWARD 3 -i uB-br -j ACCEPT -m comment --comment "$IP6TABLES_MARK" 2>/dev/null || true

    # ---- static underlay neighs (bypass NDP which may be unreliable in bridges) ----
    UA_MAC=$(sudo ip netns exec hypa cat /sys/class/net/uA/address)
    UB_MAC=$(sudo ip netns exec hypb cat /sys/class/net/uB/address)
    sudo ip netns exec hypa ip -6 neigh replace fd00::2 lladdr "$UB_MAC" dev uA nud permanent
    sudo ip netns exec hypb ip -6 neigh replace fd00::1 lladdr "$UA_MAC" dev uB nud permanent

    # ---- sanity check: underlay IPv6 ping (no XDP yet) ----
    echo "=== Underlay sanity check ==="
    sudo ip netns exec hypa ping -6 -c2 -W2 fd00::2 \
        || die "underlay ping hypa->hypb failed — check bridge/ip6tables"
    echo "Underlay ping OK"

    # ---- capture guest MACs ----
    GA_MAC=$(sudo ip netns exec guesta cat /sys/class/net/gA/address)
    GB_MAC=$(sudo ip netns exec guestb cat /sys/class/net/gB/address)
    echo "UA_MAC=$UA_MAC  UB_MAC=$UB_MAC"
    echo "GA_MAC=$GA_MAC  GB_MAC=$GB_MAC"

    # ---- static neigh entries on guests ----
    # The XDP guest_tx program strips the inner Ethernet header, so the guest's
    # ARP/NDP for the peer overlay IP never gets answered. Static entries bypass that.
    # The lladdr values are dummies — guest_tx ignores the inner Ethernet dst.
    sudo ip netns exec guesta ip neigh replace 10.0.0.6 lladdr 02:00:00:00:00:bb dev gA nud permanent
    sudo ip netns exec guestb ip neigh replace 10.0.0.5 lladdr 02:00:00:00:00:cc dev gB nud permanent

    # ---- redirect-target enablers ----
    # XDP bpf_redirect() into a veth only works if that veth's PEER has an XDP program.
    # uA-br = peer of uA  (guest_tx on gA-h redirects -> uA -> uA-br)
    # uB-br = peer of uB
    # gA    = peer of gA-h (uplink_rx on uA redirects -> gA-h -> gA)
    # gB    = peer of gB-h
    echo "=== Attaching xdp_pass on redirect-target peers ==="
    : > "$PIDFILE"

    sudo "$BIN" pass --iface uA-br &
    echo $! >> "$PIDFILE"
    sudo "$BIN" pass --iface uB-br &
    echo $! >> "$PIDFILE"
    sudo ip netns exec guesta "$BIN" pass --iface gA &
    echo $! >> "$PIDFILE"
    sudo ip netns exec guestb "$BIN" pass --iface gB &
    echo $! >> "$PIDFILE"

    sleep 1

    # ---- datapath bringup on each hypervisor ----
    # --peer-mac  = the OTHER hypervisor's uplink veth MAC (outer Eth dst on encap)
    # --guest-mac = THIS hypervisor's guest interface MAC (inner Eth dst on decap)
    echo "=== Bringing up XDP datapath ==="

    sudo ip netns exec hypa "$BIN" bringup \
        --guest gA-h --uplink uA --vni 100 \
        --local-underlay fd00::1 --peer-underlay fd00::2 \
        --peer-mac "$UB_MAC" --guest-mac "$GA_MAC" &
    echo $! >> "$PIDFILE"

    sudo ip netns exec hypb "$BIN" bringup \
        --guest gB-h --uplink uB --vni 100 \
        --local-underlay fd00::2 --peer-underlay fd00::1 \
        --peer-mac "$UA_MAC" --guest-mac "$GB_MAC" &
    echo $! >> "$PIDFILE"

    sleep 2

    # ---- verify XDP attachments ----
    echo "=== XDP attachment verification ==="
    echo "hypa gA-h (guest_tx):"
    sudo ip netns exec hypa ip -d link show gA-h | grep -E 'xdp|prog' || echo "  WARNING: no xdp on gA-h"
    echo "hypa uA (uplink_rx):"
    sudo ip netns exec hypa ip -d link show uA   | grep -E 'xdp|prog' || echo "  WARNING: no xdp on uA"
    echo "hypb gB-h (guest_tx):"
    sudo ip netns exec hypb ip -d link show gB-h | grep -E 'xdp|prog' || echo "  WARNING: no xdp on gB-h"
    echo "hypb uB (uplink_rx):"
    sudo ip netns exec hypb ip -d link show uB   | grep -E 'xdp|prog' || echo "  WARNING: no xdp on uB"

    echo "=== UP complete ==="
}

# ---------------------------------------------------------------------------
cmd_test() {
    echo "=== Test 1: guesta -> guestb ping (3 packets) ==="
    sudo ip netns exec guesta ping -c 3 -W 2 10.0.0.6
    echo ""

    echo "=== Test 2: IPv6/proto-4 encap evidence on bridge (uA-br) ==="
    # XDP bpf_redirect() bypasses tcpdump on the redirecting interface (uA inside hypa),
    # so we capture on uA-br (the bridge-side peer) instead.
    if [[ -n "$TCPDUMP" ]]; then
        sudo "$TCPDUMP" -ni uA-br 'ip6 and ip6 proto 4' -c 4 2>&1 &
        TDPID=$!
        sleep 0.3
        sudo ip netns exec guesta ping -c 3 -W 2 10.0.0.6 >/dev/null 2>&1
        wait $TDPID 2>/dev/null || true
    else
        echo "  (tcpdump not found — skipping encap capture)"
    fi
    echo ""

    echo "=== Test 3: return path guestb -> guesta ==="
    sudo ip netns exec guestb ping -c 3 -W 2 10.0.0.5

    echo ""
    echo "=== All tests passed ==="
}

# ---------------------------------------------------------------------------
cmd_down() {
    echo "=== Tearing down ==="

    # Kill all backgrounded xdp-dp processes
    if [[ -f "$PIDFILE" ]]; then
        while read -r pid; do
            sudo kill "$pid" 2>/dev/null || true
        done < "$PIDFILE"
        rm -f "$PIDFILE"
    fi
    # Belt-and-suspenders: kill any remaining xdp-dp processes
    sudo pkill -f 'target/debug/xdp-dp' 2>/dev/null || true

    sleep 1

    # Remove scoped ip6tables rules we added
    sudo ip6tables -D FORWARD -i br-ul -o br-ul -j ACCEPT -m comment --comment "$IP6TABLES_MARK" 2>/dev/null || true
    sudo ip6tables -D FORWARD -i uA-br -j ACCEPT -m comment --comment "$IP6TABLES_MARK" 2>/dev/null || true
    sudo ip6tables -D FORWARD -i uB-br -j ACCEPT -m comment --comment "$IP6TABLES_MARK" 2>/dev/null || true

    # Delete namespaces (also removes veth pairs whose netns-end lives inside them)
    for ns in hypa hypb guesta guestb; do
        sudo ip netns del "$ns" 2>/dev/null || true
    done

    # Remove the bridge and any dangling host-netns veths
    for iface in uA-br uB-br br-ul; do
        sudo ip link del "$iface" 2>/dev/null || true
    done

    echo "=== DOWN complete ==="
}

# ---------------------------------------------------------------------------
cmd_run() {
    trap 'echo ""; echo "=== ERROR: cleaning up ==="; cmd_down' ERR INT TERM
    cmd_up
    cmd_test
    cmd_down
    trap - ERR INT TERM
}

# ---------------------------------------------------------------------------
case "${1:-}" in
    up)   cmd_up   ;;
    test) cmd_test ;;
    down) cmd_down ;;
    run)  cmd_run  ;;
    *) echo "Usage: $0 {up|test|down|run}" >&2; exit 1 ;;
esac
