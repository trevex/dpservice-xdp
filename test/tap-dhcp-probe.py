#!/usr/bin/env python3
# env/tap-dhcp-probe.py — does the in-XDP DHCP responder work on a REAL tap in NATIVE mode?
#
# WHY: the conformance harness uses veth pairs (so dpservice's unchanged `sendp(iface=)` tests
# feed XDP's RX), and veth's NATIVE XDP cannot grow a frame via bpf_xdp_adjust_tail — which the
# DHCP responder needs (DISCOVER ~300B -> OFFER ~360B+). That forced XDP_DP_SKB_MODE=1 in the
# harness. But PRODUCTION uses real qemu/libvirt TAPs in native mode. This probe answers the open
# question empirically: create a real tap, attach guest_tx in NATIVE mode (bringup, no SKB env),
# write a DHCP DISCOVER to the tap fd (exactly how qemu delivers a guest's TX -> tap RX -> XDP),
# and check whether the grown OFFER is XDP_TX'd back out the tap fd.
#
# Result interpretation:
#   "OFFER received in native/driver mode" -> real taps support native adjust_tail growth;
#       the SKB workaround is a pure veth-harness artifact; production stays on the fast path.
#   "NO OFFER in native/driver mode"        -> native tap cannot grow either; the responder needs
#       a no-grow redesign (or SKB) for production. A real finding to act on.
#
# Run (inside the flake devShell, which provides python3+scapy): `make tap-dhcp-probe`, or
#   nix develop -c ./test/tap-dhcp-probe.sh

import argparse
import fcntl
import os
import select
import struct
import subprocess
import sys
import time

TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = f"{REPO}/target/debug/xdp-dp"


def open_tap_queue(name):
    """Attach a held fd (a queue) to an EXISTING tap netdev. Unlike mk_tap(), this does not
    create the device or bring it up — the caller (e.g. the tc gate) already did. Writing to this
    fd injects toward the host RX path (tc clsact ingress fires); reading drains the tap egress
    (where the responder's bpf_redirect-to-self delivers the OFFER)."""
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", name.encode(), IFF_TAP | IFF_NO_PI))
    return fd


def dhcp_discover_bytes(client_mac, xid=0x1234):
    """Build a DHCP DISCOVER frame from a client MAC string (aa:bb:..)."""
    from scapy.all import Ether, IP, UDP, BOOTP, DHCP
    chaddr = bytes.fromhex(client_mac.replace(":", ""))
    disc = (Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=chaddr, xid=xid) /
            DHCP(options=[("message-type", "discover"), "end"]))
    return bytes(disc)


def await_offer(fd, timeout=3.0):
    """Read frames off a tap fd until a DHCP OFFER (message-type 2) arrives or timeout. Returns
    (scapy_packet, options_dict) or (None, {})."""
    from scapy.all import Ether, BOOTP, DHCP
    deadline = time.time() + timeout
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.3)
        if not r:
            continue
        data = os.read(fd, 2048)
        p = Ether(data)
        if BOOTP in p and DHCP in p:
            o = {x[0]: x[1] for x in p[DHCP].options if isinstance(x, tuple)}
            if o.get("message-type") == 2:  # OFFER
                return p, o
    return None, {}


def client_only(tap, client_mac, expect_ip, timeout):
    """Drive an ALREADY-RUNNING datapath: open a queue on `tap`, send one DISCOVER from
    `client_mac`, and assert an OFFER for `expect_ip` comes back. Used by test/tc-dhcp-netns.sh."""
    from scapy.all import BOOTP
    fd = open_tap_queue(tap)
    try:
        disc = dhcp_discover_bytes(client_mac)
        os.write(fd, disc)
        print(f"sent DHCP DISCOVER ({len(disc)} bytes) from {client_mac} to tap {tap}")
        offer, opts = await_offer(fd, timeout=timeout)
    finally:
        os.close(fd)
    if offer is None:
        print(f"RESULT: NO OFFER received on {tap} within {timeout}s")
        return 1
    yiaddr = offer[BOOTP].yiaddr
    print(f"RESULT: OFFER received — yiaddr={yiaddr} dns={opts.get('name_server')} "
          f"mtu={opts.get('interface-mtu')} ({len(bytes(offer))} bytes)")
    if str(yiaddr) != expect_ip:
        print(f"  but expected yiaddr {expect_ip}, got {yiaddr}")
        return 1
    return 0


def guest_link_local(client_mac):
    """Derive the guest's link-local (fe80::/64) address from its MAC via EUI-64. Used as the
    NS source so the in-place NA rewrite (which swaps src<->dst) has a sane destination."""
    b = bytearray(bytes.fromhex(client_mac.replace(":", "")))
    b[0] ^= 0x02  # flip the universal/local bit
    eui = bytes(b[0:3]) + b"\xff\xfe" + bytes(b[3:6])
    suffix = ":".join(f"{eui[i]:02x}{eui[i+1]:02x}" for i in range(0, 16 - 8, 2))
    return f"fe80::{suffix}"


def arp_probe(tap, client_mac, gateway_ip, timeout):
    """Send an ARP request who-has <gateway_ip> tell 10.0.0.2 from client_mac on `tap`, expect an
    ARP reply (op=2) for gateway_ip whose hwsrc is the guest's own MAC. Returns 0 on success."""
    from scapy.all import Ether, ARP
    fd = open_tap_queue(tap)
    try:
        req = (Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
               ARP(op=1, hwsrc=client_mac, psrc="10.0.0.2",
                   hwdst="00:00:00:00:00:00", pdst=gateway_ip))
        frame = bytes(req)
        # Pad to 60 bytes so the datapath's pull_data(ETH_LEN+ARP_LEN=42) always succeeds.
        if len(frame) < 60:
            frame += b"\x00" * (60 - len(frame))
        os.write(fd, frame)
        print(f"sent ARP who-has {gateway_ip} ({len(frame)} bytes) from {client_mac} on {tap}")
        deadline = time.time() + timeout
        while time.time() < deadline:
            r, _, _ = select.select([fd], [], [], 0.3)
            if not r:
                continue
            p = Ether(os.read(fd, 2048))
            if ARP in p and p[ARP].op == 2:
                a = p[ARP]
                print(f"got ARP reply: op={a.op} psrc={a.psrc} hwsrc={a.hwsrc}")
                if str(a.psrc) == gateway_ip and a.hwsrc.lower() == client_mac.lower():
                    print("ARP reply OK")
                    return 0
                print(f"  but expected psrc={gateway_ip} hwsrc={client_mac}")
                return 1
    finally:
        os.close(fd)
    print(f"RESULT: NO ARP reply on {tap} within {timeout}s")
    return 1


def nd_probe(tap, client_mac, gateway6, timeout):
    """Send an ICMPv6 Neighbor Solicitation for `gateway6` from client_mac on `tap`, expect a
    Neighbor Advertisement whose target-LL-addr option == the guest's own MAC. Returns 0 on ok."""
    from scapy.all import (Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_NA,
                           ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr)
    fd = open_tap_queue(tap)
    try:
        src6 = guest_link_local(client_mac)
        ns = (Ether(src=client_mac, dst="33:33:00:00:00:01") /
              IPv6(src=src6, dst=gateway6) /
              ICMPv6ND_NS(tgt=gateway6) /
              ICMPv6NDOptSrcLLAddr(lladdr=client_mac))
        frame = bytes(ns)
        os.write(fd, frame)
        print(f"sent ICMPv6 NS for {gateway6} ({len(frame)} bytes) from {client_mac} on {tap}")
        deadline = time.time() + timeout
        while time.time() < deadline:
            r, _, _ = select.select([fd], [], [], 0.3)
            if not r:
                continue
            p = Ether(os.read(fd, 2048))
            if ICMPv6ND_NA in p:
                lladdr = None
                if ICMPv6NDOptDstLLAddr in p:
                    lladdr = p[ICMPv6NDOptDstLLAddr].lladdr
                print(f"got ICMPv6 NA: tgt={p[ICMPv6ND_NA].tgt} dst-lladdr={lladdr}")
                if lladdr is not None and lladdr.lower() == client_mac.lower():
                    print("ND NA OK")
                    return 0
                print(f"  but expected dst-lladdr={client_mac}")
                return 1
    finally:
        os.close(fd)
    print(f"RESULT: NO ICMPv6 NA on {tap} within {timeout}s")
    return 1


def egress_probe(tap, peer, timeout):
    """Egress encap gate: open a queue on `tap`, sniff on the veth `peer`, send one inner IPv4
    frame on `tap` (guest egress), and assert the datapath redirected an ENCAPPED frame onto the
    uplink (read on `peer`): outer Ether + IPv6(nh=4 IPIP, src=fc00:1::1, dst=fc00:2::2) carrying
    the inner IP(src=10.0.0.1, dst=10.0.0.2). Returns 0 on success."""
    from scapy.all import Ether, IP, IPv6, ICMP, sniff, AsyncSniffer

    fd = open_tap_queue(tap)
    captured = []

    def stop_when(p):
        return IPv6 in p

    sniffer = AsyncSniffer(iface=peer, prn=lambda p: captured.append(p),
                           store=True, lfilter=lambda p: IPv6 in p)
    sniffer.start()
    time.sleep(0.5)
    try:
        inner = (Ether(src="52:54:00:00:00:01", dst="aa:aa:aa:aa:aa:aa") /
                 IP(src="10.0.0.1", dst="10.0.0.2") /
                 ICMP())
        frame = bytes(inner)
        os.write(fd, frame)
        print(f"sent inner IPv4 ICMP ({len(frame)} bytes) 10.0.0.1->10.0.0.2 on {tap}")
        deadline = time.time() + timeout
        while time.time() < deadline and not captured:
            time.sleep(0.2)
    finally:
        time.sleep(0.3)
        try:
            sniffer.stop()
        except Exception:
            pass
        os.close(fd)

    # Filter to IPv6 frames (drop any stray veth multicast/MLD).
    cands = [p for p in captured if IPv6 in p]
    if not cands:
        print(f"RESULT: NO IPv6 frame captured on {peer} within {timeout}s")
        return 1
    for p in cands:
        raw = bytes(p)
        print(f"captured {len(raw)} bytes on {peer}: {raw.hex()}")
        ip6 = p[IPv6]
        ok_outer = (ip6.nh == 4 and ip6.src == "fc00:1::1" and ip6.dst == "fc00:2::2")
        ok_inner = False
        if IP in p:
            inner_ip = p[IP]
            ok_inner = (inner_ip.src == "10.0.0.1" and inner_ip.dst == "10.0.0.2")
        print(f"  outer IPv6: nh={ip6.nh} src={ip6.src} dst={ip6.dst} (want nh=4 "
              f"src=fc00:1::1 dst=fc00:2::2)")
        if IP in p:
            print(f"  inner IP:  src={p[IP].src} dst={p[IP].dst} (want 10.0.0.1->10.0.0.2)")
        else:
            print("  inner IP:  <not parsed as IPv4 inside IPv6>")
        if ok_outer and ok_inner:
            print("ENCAP OK")
            return 0
    print("RESULT: captured frame(s) not correctly encapsulated (see hex above)")
    return 1


def mk_tap(name):
    """Create a tap netdev with a held fd (IFF_NO_PI = raw ethernet frames), bring it up,
    disable offloads so the kernel doesn't coalesce/segment and confuse XDP."""
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", name.encode(), IFF_TAP | IFF_NO_PI))
    subprocess.run(["ip", "link", "set", name, "up"], check=True)
    # Best-effort offload disable (ethtool may be absent; a single written DHCP frame is not
    # coalesced anyway, so this is not load-bearing for the probe).
    try:
        subprocess.run(["ethtool", "-K", name, "gro", "off", "tso", "off", "gso", "off"],
                       check=False, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        pass
    return fd


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--client-only", action="store_true",
                    help="drive an already-running datapath on --tap (no bringup); used by the tc gate")
    ap.add_argument("--probe", choices=["dhcp", "arp", "nd"], default="dhcp",
                    help="which probe to run in --client-only mode (default: dhcp)")
    ap.add_argument("--egress", action="store_true",
                    help="egress encap gate: send inner IPv4 on --tap, capture encapped on --peer")
    ap.add_argument("--peer", default=None, help="veth peer to capture redirected uplink frames on")
    ap.add_argument("--tap", default=None, help="existing tap netdev (client-only mode)")
    ap.add_argument("--client-mac", default="52:54:00:00:00:01")
    ap.add_argument("--expect-ip", default="10.0.0.1")
    ap.add_argument("--gateway6", default="fe80::1", help="ND gateway target (nd probe)")
    ap.add_argument("--timeout", type=float, default=3.0)
    args = ap.parse_args()
    if args.egress:
        if not args.tap or not args.peer:
            print("ERROR: --egress requires --tap and --peer", file=sys.stderr)
            return 2
        return egress_probe(args.tap, args.peer, args.timeout)
    if args.client_only:
        if not args.tap:
            print("ERROR: --client-only requires --tap", file=sys.stderr)
            return 2
        if args.probe == "arp":
            return arp_probe(args.tap, args.client_mac, args.expect_ip, args.timeout)
        if args.probe == "nd":
            return nd_probe(args.tap, args.client_mac, args.gateway6, args.timeout)
        return client_only(args.tap, args.client_mac, args.expect_ip, args.timeout)

    if not os.path.exists(BIN):
        print(f"ERROR: {BIN} missing — run: cargo build -p xdp-dp", file=sys.stderr)
        return 2

    gfd = mk_tap("dhg0")  # guest tap: guest_tx attaches here
    ufd = mk_tap("dhu0")  # uplink tap: uplink_rx attaches here (no real peer needed)
    gmac = open("/sys/class/net/dhg0/address").read().strip()
    umac = open("/sys/class/net/dhu0/address").read().strip()

    # bringup attaches via attach_xdp (XdpFlags::default() = NATIVE), and does NOT consult
    # XDP_DP_SKB_MODE — so this is a genuine native-mode test. DHCP config: mtu 1337 + 2 DNS.
    bringup = subprocess.Popen(
        [BIN, "bringup", "--uplink", "dhu0", "--local-underlay", "fd00::1",
         "--gateway", "10.0.0.1", "--gateway-mac", umac,
         "--guest", f"dhg0=10.0.0.50={gmac}=fd00:a::50=0",
         "--dhcp-mtu", "1337", "--dhcp-dns", "8.8.4.4", "--dhcp-dns", "8.8.8.8"],
        stdout=open("/tmp/dhcp-probe-bringup.log", "w"), stderr=subprocess.STDOUT)
    time.sleep(2)

    info = subprocess.run(["ip", "-d", "link", "show", "dhg0"],
                          capture_output=True, text=True).stdout
    mode = "skb/generic" if "xdpgeneric" in info else ("native/driver" if "xdp" in info else "NONE")
    print(f"guest_tx attach mode on dhg0: {mode}")

    from scapy.all import Ether, IP, UDP, BOOTP, DHCP

    disc = (Ether(src="02:aa:bb:cc:dd:ee", dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=bytes.fromhex("02aabbccddee"), xid=0x1234) /
            DHCP(options=[("message-type", "discover"), "end"]))
    disc_bytes = bytes(disc)
    os.write(gfd, disc_bytes)
    print(f"sent DHCP DISCOVER ({len(disc_bytes)} bytes) to the dhg0 fd")

    offer = None
    opts = {}
    deadline = time.time() + 3
    while time.time() < deadline:
        r, _, _ = select.select([gfd], [], [], 0.3)
        if not r:
            continue
        data = os.read(gfd, 2048)
        p = Ether(data)
        if BOOTP in p and DHCP in p:
            o = {x[0]: x[1] for x in p[DHCP].options if isinstance(x, tuple)}
            if o.get("message-type") == 2:  # OFFER
                offer, opts = p, o
                break

    bringup.terminate()
    try:
        bringup.wait(timeout=3)
    except Exception:
        bringup.kill()
    for n in ("dhg0", "dhu0"):
        subprocess.run(["ip", "link", "del", n], check=False, stderr=subprocess.DEVNULL)
    os.close(gfd)
    os.close(ufd)

    print("")
    if offer is None:
        print(f"RESULT: NO OFFER received in {mode} mode")
        print("  -> native tap CANNOT grow the frame (bpf_xdp_adjust_tail fails) — a real")
        print("     production concern: the responder needs a no-grow redesign or SKB in prod.")
        return 1

    offer_bytes = bytes(offer)
    print(f"RESULT: OFFER received in {mode} mode")
    print(f"  reply {len(offer_bytes)} bytes (grown from the {len(disc_bytes)}-byte DISCOVER)")
    print(f"  yiaddr={offer[BOOTP].yiaddr}  interface-mtu={opts.get('interface-mtu')}  "
          f"dns={opts.get('name_server')}")
    ok = (offer[BOOTP].yiaddr == "10.0.0.50" and opts.get("interface-mtu") == 1337
          and len(offer_bytes) > len(disc_bytes))
    if ok and mode == "native/driver":
        print("  -> PROVEN: real taps support native-mode adjust_tail growth. The SKB workaround")
        print("     is a pure veth-harness artifact; production runs DHCP on the native fast path.")
        return 0
    print("  -> OFFER returned but check the mode/values above.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
