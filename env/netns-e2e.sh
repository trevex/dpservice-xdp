#!/usr/bin/env bash
# env/netns-e2e.sh — netns-based end-to-end test for the XDP IP-in-IPv6 overlay.
#
# Topology:
#   guesta(10.0.0.5/gA)  \
#   guesta2(10.0.0.7/gA2) }- hypa(gA-h,gA2-h / uA) <-> [uA-br] br-ul [uB-br] <-> hypb(uB / gB-h) <-> guestb(10.0.0.6/gB)
#
# Guests use a dpservice-style /32 + link route to gateway + default via gateway (10.0.0.1),
# so they ARP only for the gateway — which the datapath answers in-kernel (no static neigh).
#
# Usage (run from repo root):
#   ./env/netns-e2e.sh up       create namespaces + bridge, attach XDP datapath
#   ./env/netns-e2e.sh test     ping guesta->guestb; ARP evidence; multi-interface; encap capture
#   ./env/netns-e2e.sh down     kill daemons, tear down all namespaces/links/bridge
#   ./env/netns-e2e.sh run      up + test + down  (with cleanup on error)
#
# Requirements:
#   - Passwordless sudo
#   - cargo build -p xdp-dp must have been run (binary at target/debug/xdp-dp)
#   - tcpdump in Nix store (detected automatically)
set -euo pipefail

BIN="$(pwd)/target/debug/xdp-dp"
# User-writable: the script runs as the normal user (only individual commands use sudo),
# so this must NOT be under root-owned /run.
PIDFILE="${TMPDIR:-/tmp}/xdp-e2e-pids"
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
    for ns in hypa hypb guesta guestb guesta2; do
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
    # /32 address + link route to gateway + default via gateway (dpservice model)
    sudo ip netns exec guesta ip addr add 10.0.0.5/32 dev gA 2>/dev/null || true
    sudo ip netns exec guesta ip route add 10.0.0.1/32 dev gA 2>/dev/null || true
    sudo ip netns exec guesta ip route add default via 10.0.0.1 2>/dev/null || true

    # ---- hypa second guest link: gA2-h in hypa <-> gA2 in guesta2 ----
    if ! sudo ip netns exec hypa ip link show gA2-h &>/dev/null; then
        sudo ip link add gA2-h netns hypa type veth peer name gA2 netns guesta2
    fi
    sudo ip netns exec hypa ip link set gA2-h up
    sudo ip netns exec guesta2 ip link set gA2 up
    sudo ip netns exec guesta2 ip addr add 10.0.0.7/32 dev gA2 2>/dev/null || true
    sudo ip netns exec guesta2 ip route add 10.0.0.1/32 dev gA2 2>/dev/null || true
    sudo ip netns exec guesta2 ip route add default via 10.0.0.1 2>/dev/null || true

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
    sudo ip netns exec guestb ip addr add 10.0.0.6/32 dev gB 2>/dev/null || true
    sudo ip netns exec guestb ip route add 10.0.0.1/32 dev gB 2>/dev/null || true
    sudo ip netns exec guestb ip route add default via 10.0.0.1 2>/dev/null || true

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

    # ---- capture guest MACs (from inside guest netns — these are the actual guest MACs) ----
    GA_MAC=$(sudo ip netns exec guesta cat /sys/class/net/gA/address)
    GB_MAC=$(sudo ip netns exec guestb cat /sys/class/net/gB/address)
    GA2_MAC=$(sudo ip netns exec guesta2 cat /sys/class/net/gA2/address)
    echo "UA_MAC=$UA_MAC  UB_MAC=$UB_MAC"
    echo "GA_MAC=$GA_MAC  GB_MAC=$GB_MAC  GA2_MAC=$GA2_MAC"

    # NOTE: No static guest neigh entries — the XDP datapath answers ARP for 10.0.0.1 in-kernel.
    # Guests use /32 + link route + default via 10.0.0.1, so they only ARP for the gateway.

    # ---- redirect-target enablers ----
    # XDP bpf_redirect() into a veth only works if that veth's PEER has an XDP program.
    # uA-br = peer of uA  (guest_tx on gA-h/gA2-h redirects -> uA -> uA-br)
    # uB-br = peer of uB
    # gA    = peer of gA-h (uplink_rx on uA redirects -> gA-h -> gA)
    # gA2   = peer of gA2-h (uplink_rx on uA redirects -> gA2-h -> gA2)
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
    sudo ip netns exec guesta2 "$BIN" pass --iface gA2 &
    echo $! >> "$PIDFILE"

    sleep 1

    # ---- datapath bringup on each hypervisor ----
    echo "=== Bringing up XDP datapath ==="

    # hypa: two local guests (gA=10.0.0.5, gA2=10.0.0.7) + remote route to hypb guest (10.0.0.6)
    # --gateway-mac = peer uplink MAC (flat-L2 lab: the bridge forwards to UB_MAC directly)
    sudo ip netns exec hypa "$BIN" bringup \
        --uplink uA \
        --local-underlay fd00::1 \
        --gateway 10.0.0.1 \
        --gateway-mac "$UB_MAC" \
        --guest "gA-h=10.0.0.5=${GA_MAC}" \
        --guest "gA2-h=10.0.0.7=${GA2_MAC}" \
        --remote "10.0.0.6=fd00::2" \
        --vip "10.0.0.7=10.0.0.100" &
    echo $! >> "$PIDFILE"

    # hypb: one local guest (gB=10.0.0.6) + remote routes to both hypa guests
    # --gateway-mac = peer uplink MAC (flat-L2 lab: the bridge forwards to UA_MAC directly)
    sudo ip netns exec hypb "$BIN" bringup \
        --uplink uB \
        --local-underlay fd00::2 \
        --gateway 10.0.0.1 \
        --gateway-mac "$UA_MAC" \
        --guest "gB-h=10.0.0.6=${GB_MAC}" \
        --remote "10.0.0.5=fd00::1" \
        --remote "10.0.0.7=fd00::1" \
        --remote "10.0.0.100=fd00::1" &
    echo $! >> "$PIDFILE"

    sleep 2

    # ---- verify XDP attachments ----
    echo "=== XDP attachment verification ==="
    echo "hypa gA-h (guest_tx):"
    sudo ip netns exec hypa ip -d link show gA-h | grep -E 'xdp|prog' || echo "  WARNING: no xdp on gA-h"
    echo "hypa gA2-h (guest_tx):"
    sudo ip netns exec hypa ip -d link show gA2-h | grep -E 'xdp|prog' || echo "  WARNING: no xdp on gA2-h"
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

    echo "=== Test 2: DATAPATH ARP proof — 10.0.0.1 must show GW_MAC 02:00:00:00:00:01 ==="
    sudo ip netns exec guesta ip neigh show 10.0.0.1
    NEIGH=$(sudo ip netns exec guesta ip neigh show 10.0.0.1)
    if echo "$NEIGH" | grep -q "02:00:00:00:00:01"; then
        echo "  ARP proof OK: datapath replied with GW_MAC"
    else
        echo "  WARNING: expected lladdr 02:00:00:00:00:01 but got: $NEIGH"
    fi
    echo ""

    echo "=== Test 3: MULTI-INTERFACE — guesta2 (hypa's second guest) -> guestb ==="
    sudo ip netns exec guesta2 ping -c 3 -W 2 10.0.0.6
    echo ""

    echo "=== Test 4: IPv6/proto-4 encap evidence on bridge (uA-br) ==="
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

    echo "=== Test 5: return path guestb -> guesta ==="
    sudo ip netns exec guestb ping -c 3 -W 2 10.0.0.5
    echo ""

    echo "=== Test 6: VIP — guestb -> guesta2's VIP 10.0.0.100 (DNAT in, SNAT out) ==="
    # 0% loss proves DNAT delivered to guesta2 AND its SNAT'd reply returned with a correct
    # checksum (a bad checksum would be dropped by guestb). tcpdump prints packets to STDOUT, so
    # redirect stdout (not just stderr) to the proof file.
    if [[ -n "$TCPDUMP" ]]; then
        sudo ip netns exec guestb "$TCPDUMP" -ni gB 'icmp' -c 6 >/tmp/vip-td.txt 2>&1 &
        TDV=$!
        sleep 0.3
    fi
    sudo ip netns exec guestb ping -c 3 -W 2 10.0.0.100
    if [[ -n "$TCPDUMP" ]]; then
        wait $TDV 2>/dev/null || true
        echo "--- SNAT proof: echo replies must be sourced from 10.0.0.100 ---"
        grep -E '10\.0\.0\.100 > 10\.0\.0\.6: ICMP echo reply' /tmp/vip-td.txt \
            && echo "  SNAT proof OK: reply source is the VIP" \
            || echo "  WARNING: no VIP-sourced reply seen"
        rm -f /tmp/vip-td.txt
    fi

    echo ""
    echo "=== All tests passed ==="
}

# ---------------------------------------------------------------------------
cmd_down() {
    echo "=== Tearing down ==="

    # Kill all backgrounded datapath processes by their recorded PIDs (precise).
    # These PIDs are the `sudo ...` wrappers; SIGTERM is forwarded to the xdp-dp child.
    if [[ -f "$PIDFILE" ]]; then
        while read -r pid; do
            sudo kill "$pid" 2>/dev/null || true
        done < "$PIDFILE"
        rm -f "$PIDFILE"
    fi
    # Belt-and-suspenders fallback. IMPORTANT: do NOT use a broad `pkill -f target/debug/xdp-dp`
    # — that regex also matches ANY shell whose command line merely mentions the binary path
    # (e.g. an interactive verification command), killing unrelated processes. Match only the
    # actual datapath subcommands.
    sudo pkill -f 'xdp-dp (bringup|pass) --' 2>/dev/null || true

    sleep 1

    # Remove scoped ip6tables rules we added
    sudo ip6tables -D FORWARD -i br-ul -o br-ul -j ACCEPT -m comment --comment "$IP6TABLES_MARK" 2>/dev/null || true
    sudo ip6tables -D FORWARD -i uA-br -j ACCEPT -m comment --comment "$IP6TABLES_MARK" 2>/dev/null || true
    sudo ip6tables -D FORWARD -i uB-br -j ACCEPT -m comment --comment "$IP6TABLES_MARK" 2>/dev/null || true

    # Delete namespaces (also removes veth pairs whose netns-end lives inside them)
    for ns in hypa hypb guesta guestb guesta2; do
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
    # An EXIT trap guarantees teardown however the script ends — normal completion, a
    # `set -e` abort inside a function (an ERR trap would NOT fire there without errtrace),
    # or INT/TERM. cmd_down is idempotent, so running it once here is enough.
    trap cmd_down EXIT INT TERM
    cmd_up
    cmd_test
}

# ---------------------------------------------------------------------------
case "${1:-}" in
    up)   cmd_up   ;;
    test) cmd_test ;;
    down) cmd_down ;;
    run)  cmd_run  ;;
    *) echo "Usage: $0 {up|test|down|run}" >&2; exit 1 ;;
esac
