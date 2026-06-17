# Design: ironcore-in-a-box drop-in (xdp-dp replaces DPDK dpservice)

**Date:** 2026-06-17
**Status:** Approved design, pre-implementation
**Author:** Niklas Voss (with Claude)
**Builds on:** foundation PoC (complete) + datapath feature-parity M1 "generalize the datapath"
(complete: map-driven multi-interface pipeline, in-datapath ARP responder, gateway-based encap,
gRPC `CreateInterface`/`CreateRoute` programming the maps).

This is **sub-project 2**. Sub-project 1 (VIP / LB / NAT-GW feature parity, spec
`2026-06-17-datapath-feature-parity-design.md`) is independent; M2–M4 of it remain. The build
order between this drop-in and the remaining VIP/LB/NAT features is decided at plan time (see
§9).

## 1. Goal

Run our `xdp-dp` (eBPF/XDP) as the **dpservice replacement** in a fork of
`ironcore-dev/ironcore-in-a-box`, achieving real VM-to-VM overlay connectivity driven by the
unmodified IronCore control plane (metalnet/metalbond over the `DPDKironcore` gRPC contract) —
proving the XDP datapath is a true drop-in for the DPDK one. A key improvement over the current
dev setup: **VM ports are created dynamically on `CreateInterface`** instead of from a
pre-created, fixed tap pool.

## 2. Observed current wiring (why the change)

ironcore-in-a-box runs dpservice as a **DaemonSet using DPDK's TAP PMD** (`--no-pci --no-huge
--no-offload --nic-type=tap`), which pre-creates kernel taps via `net_tap` vdevs:
- `dtap0`/`dtap1` — PF/uplink taps (PF MAC `22:22:22:22:22:00`).
- `dtapvf_0..3` — a fixed **pool** of VF/VM-port taps (`--vf-pattern=dtapvf_`).

metalnet (`--tapdevice-mod`) holds a file-backed `ClaimStore` (`netfns/netfns.go`) that
**claims one tap name per NetworkInterface UID** from that pool, then calls dpservice
`CreateInterface(device_name=<claimed tap>)`; libvirt-provider's apinet plugin attaches the VM
to that tap. The node underlay (`hack/setup-network.sh`) is an `ip6tnl` `overlay-tun`
(`2001:db8:dead:beef::1`, the metalnet `--router-address`), a route `2001:db8:fefe::/48 via
fe80::1 dev dtap0`, a neigh `fe80::1 → dpservice PF MAC`, and fwmark policy-routing out `eth0`.
The overlay is `2001:db8:fefe::/48`; metalbond distributes overlay routes; gRPC on `:1337`.

The **fixed pre-created pool** is the finicky part we replace with dynamic creation.

Validated (XDP-on-tap spike): an XDP program on a QEMU virtio-net tap sees **plain Ethernet**
(the `tun` driver strips the virtio-net header), in **native** mode, even with `vhost=on`. So
our existing datapath offsets work unchanged on real VM taps.

## 3. Architecture

- **`xdp-dp` as a privileged DaemonSet** replacing the `dpservice` DaemonSet: host network +
  `CAP_BPF` + `NET_ADMIN` + `/dev` access; serves `DPDKironcore` gRPC on `:1337`.
- **Dynamic port lifecycle** (core improvement):
  - `CreateInterface` → create a **tap** netdev (deterministic name derived from the interface
    id, via netlink / `TUNSETIFF` `IFF_TAP|IFF_VNET_HDR`), set it up, attach `guest_tx`, program
    `PORT_META` + `INTERFACES`, return the device name (so the VM can be attached to it).
  - `DeleteInterface` → detach XDP + delete the tap + clear the maps.
  - No `--vf-pattern` pool, no `ClaimStore`.
- **Uplink:** attach `uplink_rx` to the node's underlay-facing device. Because our XDP performs
  the IP-in-IPv6 encap itself, we **bypass the kernel `ip6tnl` overlay-tun**; the underlay
  next-hop (gateway) MAC + this node's underlay IPv6 go into `LOCAL`, and metalbond →
  `CreateRoute` → `ROUTES`.
- **In-datapath DHCPv4 responder (new feature, §4).**
- **Minimal cross-repo patches (in the fork):**
  - metalnet `--tapdevice-mod`: drop the pool/claim; derive the device name from the NIC UID and
    let `xdp-dp` create it.
  - libvirt-provider: attach the VM to the `xdp-dp`-created tap (exact attach path confirmed
    during implementation by reading the apinet attach code).
  - node `setup-network.sh`: adapt the uplink/underlay wiring to the XDP model (drop the
    `ip6tnl` path; point `uplink_rx` at the inter-node device; set the gateway MAC).

## 4. New feature: in-datapath DHCPv4 responder

ironcore VMs obtain their IP/gateway/MTU/DNS via **DHCP served by the dataplane** (dpservice's
`--dhcp-*`; confirmed by the CirrOS spike VM emitting `DHCPDISCOVER`). So `xdp-dp` must answer
DHCPv4 in XDP on the guest tap: respond to `DISCOVER`/`REQUEST` with the interface's configured
IPv4, gateway (`=<subnet>.1`, the address the ARP responder already owns), MTU (1450), and DNS.
This is a new datapath module (`dhcp`). DHCPv6 + IPv6 ND are deferred (§8).

## 5. Components & isolation

- `xdp-dp-ebpf`: existing pipeline + a new `dhcp` module (DHCPv4 parse/respond in XDP).
- `xdp-dp` userspace: a `netdev` module owning tap create/delete (netlink); the gRPC handlers
  call it from `CreateInterface`/`DeleteInterface`; a container image + DaemonSet manifest.
- Fork of `ironcore-in-a-box`: a kustomize overlay swapping the dpservice DaemonSet for `xdp-dp`,
  plus the metalnet/libvirt/node-setup patches.
- Each unit keeps one responsibility (tap lifecycle, DHCP, gRPC, manifests) and is testable on
  its own.

## 6. Milestones (large → phased; each independently demoable)

1. **Packaging + dynamic taps (standalone):** container image; `CreateInterface` auto-creates a
   tap + attaches XDP + programs maps + returns the name; `DeleteInterface` cleans up. Validated
   with `grpcurl`/`dpservice-cli` + a netns-style harness (no full ioiab yet).
2. **DHCPv4 responder + VM boot:** add the XDP DHCPv4 responder; boot a real libvirt/QEMU VM on
   an auto-created tap; confirm it DHCPs its IP and reaches its gateway (datapath ARP).
3. **Two-node underlay overlay:** uplink attach + gateway-MAC + metalbond-driven `ROUTES`;
   VM-to-VM across two nodes/hosts with `proto 4` IP-in-IPv6 on the underlay.
4. **Full ironcore-in-a-box fork:** replace the dpservice DaemonSet with `xdp-dp`; patch
   metalnet (pool→dynamic), libvirt attach, and node `setup-network.sh`; `make up`, spin a
   `Machine`, demonstrate VM-to-VM.

## 7. Testing

Per milestone: `grpcurl`/`dpservice-cli` conformance + tap-created/XDP-attached assertions (M1);
a VM DHCPs an IP and pings its gateway (M2); cross-node VM-to-VM + `tcpdump` `proto 4` underlay
(M3); full ioiab `make up` + a `Machine` reachable end-to-end (M4). Reuse the netns-lab style
before standing up the full kind stack where possible.

## 8. Out of scope

VIP/LB/NAT-GW (sub-project 1); DHCPv6 + IPv6 ND (deferred — IPv4 DHCP first); multi-tenant VNI
encoding (M1 single-tenant `vni=0` carries over until a feature needs it); performance/HA tuning;
SmartNIC hardware offload (the offload-ready software path is preserved). Upstreaming the
metalnet/libvirt patches (we work in a fork).

## 9. Build-order note (decided at plan time)

This drop-in (esp. DHCPv4 + the kind stack) is sizable and partly orthogonal to VIP/LB/NAT. Two
viable sequences: (a) finish sub-project-1 **VIP/LB/NAT** first, then this drop-in; or (b) do
**ioiab milestones 1–2** now (dynamic taps + a VM boots) as an early integration win, then return
to features. The choice is made when we transition to writing the first implementation plan.

## 10. Resolved-during-implementation

The exact libvirt VM↔tap attach path (how the created tap name reaches the libvirt domain XML /
the apinet plugin) is confirmed by reading libvirt-provider's apinet attach code at the start of
the milestone that needs it (M2/M4), per the "proceed to design now" decision.
