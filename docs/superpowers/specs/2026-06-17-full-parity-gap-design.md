# Design: Full dpservice Parity — Gap Inventory & Approach

**Date:** 2026-06-17
**Status:** Draft for review
**Author:** Niklas Voss (with Claude)
**Builds on:** `2026-06-15-xdp-dpservice-design.md` (foundation), `2026-06-17-datapath-feature-parity-design.md` (M1–M4, complete).

## 1. Goal & stance

`xdp-dp` must be a **true drop-in replacement** for the DPDK `dpservice` dataplane — not a
lookalike that covers the easy 80%. This document inventories every behavioral gap between the
current implementation (M1–M4: generalized datapath, ARP, VIP, LB/Maglev, single-node NAT) and
upstream dpservice, and lays out a design approach for closing each one. **We do not defer the
hard bits.** HA flow-state sync, distributed (neighbor) NAT, multi-tenancy, NAT64, virtual
services, and hardware-offload-readiness are all in scope and designed here, even where they are
large.

Parity target is **functional + wire-compatible**, not byte-identical internals: the same
`DPDKironcore` gRPC contract, the same observable on-the-wire behavior (encap format, NAT/LB
semantics, firewall semantics, DHCP/ND responses), and the same control-plane surface metalnet
drives. Internal algorithms (Maglev construction, NAT port search, conntrack hashing) need only be
functionally equivalent.

This spec is a **backlog + approach document**; each milestone it defines gets its own
implementation plan (`writing-plans`) before execution.

## 2. Reference: dpservice datapath (rte_graph nodes)

dpservice's datapath is a 22-node `rte_graph`. Current `xdp-dp` coverage:

| dpservice node | Function | xdp-dp status |
|---|---|---|
| `rx` / `tx` / `rx_periodic` | DPDK port I/O + periodic timers | N/A (XDP hooks; periodic → userspace timer) |
| `cls_node` | Packet + **flow-direction classification** (N↔S vs E↔W) | **Gap** — approximated by an `is_external` route flag |
| `arp_node` | ARP responder | **Done** |
| `ipv6_nd_node` | IPv6 Neighbor Discovery responder | **Gap** (also needed for ioiab) |
| `dhcp_node` / `dhcpv6_node` | DHCPv4 / DHCPv6 server | **Gap** (also ioiab) |
| `conntrack_node` | **Unified per-flow table for ALL traffic** + TCP state + aging | **Partial** — LB/NAT flows only, no state/aging |
| `firewall_node` | Stateful per-port rule eval, action cached in conntrack | **Gap** |
| `dnat_node` / `snat_node` | VIP + network NAT (+ NAT64) | **Partial** — VIP + single-node NAT; no NAT64, no neighbor |
| `lb_node` | Maglev LB (backends anywhere via underlay endpoint) | **Partial** — local backends only |
| `ipv4_lookup` / `ipv6_lookup` | **LPM** route/interface lookup | **Partial** — exact `/32` only |
| `ipip_encap` / `ipip_decap` | IP-in-IPv6 overlay | **Done** |
| `virtsvc_node` | Virtual services (DNAT to fixed service endpoints) | **Gap** |
| `packet_relay_node` | Relay (ICMP-error / NAT-related) | **Gap** |
| `sync_node` | **HA flow-state sync** (active→backup process) | **Gap** |
| `drop` / `common` | Plumbing | N/A |

Cross-cutting dpservice features not expressed as single nodes: **multi-VNI tenancy**, **per-port
rate metering (srTCM)**, **hardware offload (`rte_flow` async)**, **packet capture**, and the full
**read/list/delete gRPC surface**.

## 3. The keystone: a unified conntrack

Almost every remaining gap depends on one thing dpservice has and we don't: a **single conntrack
table that every flow passes through**. In dpservice this is `struct flow_value` (`dp_flow.h`):

- Keyed by a 44-byte `flow_key` (both directions stored: `flow_key[ORG]`, `flow_key[REPLY]`).
- Carries `nf_info` (NAT type), `fwall_action[ORG/REPLY]` (the firewall decision, **cached after
  the first packet**), a **TCP state machine** (`NONE → NEW_SYN → NEW_SYNACK → ESTABLISHED →
  FINWAIT → RST_FIN`), `offload_state`, an `aged` flag, and a `timeout_value`.
- Flags: `SRC_NAT`, `DST_NAT`, `DST_LB`, `FIREWALL`, `SRC_NAT64`, `DST_NAT_FWD`, and **`DEFAULT`**
  (plain forwarded traffic also gets an entry).
- Aging: default 30 s; established TCP 1 day; swept by `dp_process_aged_flows` on a timer.

**Design:** introduce a generalized `CONNTRACK` LRU map keyed by a normalized 5-tuple, value
`ConntrackEntry { reverse_key_fields, flags, nat_type, fwall_action, tcp_state, last_seen,
created }`. Both `guest_tx` and `uplink_rx` look up / create the entry up front; VIP, LB, NAT,
and firewall all become **consumers** of this entry instead of owning private maps. M2/M3/M4 maps
(`VIPS` stays config; `LB`/`MAGLEV`/`NAT` stay config; the per-feature `CONNTRACK`/`NAT_CT`
collapse into the unified table). This is **M5** and unblocks firewall, TCP-aware NAT/LB, aging,
and HA sync.

eBPF constraints: a real TCP state machine + `last_seen` timestamping is feasible in XDP
(`bpf_ktime_get_ns`, map value updates). Aging is done by a **userspace GC task** sweeping the map
by `last_seen` (the LRU gives us a safety net; the GC gives dpservice-equivalent idle timeouts).
This keeps the datapath pure-XDP and offload-aligned.

## 4. Per-gap design approach

### 4.1 Firewall (stateful) — depends on §3
dpservice model (`dp_firewall.h`): per-port, priority-ordered rules with `src_ip/dst_ip + mask`,
`protocol`, TCP/UDP `port ranges` or ICMP `type/code`, `action` (ACCEPT/DROP), `direction`
(INGRESS/EGRESS). `firewall_node` evaluates the rule set **once** on the flow's ORG direction and
**caches the action in the conntrack entry** for both directions (stateful: the reply is allowed
because the flow is established).

**Fidelity note + decision:** upstream `firewall_node.c` currently has the actual drop **commented
out** (`// Ignore the drop actions till we have the metalnet ready to set the firewall rules`). We
implement rule storage + per-flow evaluation + conntrack caching like upstream, **but we ship real
enforcement ON by default** (a DROP rule actually drops) — diverging from upstream's temporary
permissive state toward the semantics a user expects, with a config flag (`firewall_enforce`,
default `true`) to disable dropping for upstream-matching behavior if needed. RPCs:
`CreateFirewallRule`/`GetFirewallRule`/`DeleteFirewallRule`/`ListFirewallRules`.

eBPF approach: a `FW_RULES` map (per-interface rule arrays; bounded linear scan in priority order
inside the program — XDP handles bounded loops). Match → write `fwall_action` into the conntrack
entry; subsequent packets read the cached action. **Milestone M6.**

### 4.2 Multi-VNI tenancy
All map keys already carry `vni` (we only ever write `0`). Gap is end-to-end: gRPC must thread the
real VNI from `CreateInterface`/`CreateRoute`/etc.; `port_meta` already carries per-port VNI;
inner lookups must use it. Mostly plumbing + lab work (a second tenant network), but touches every
RPC and the lab. **Milestone M7.**

### 4.3 LPM routing + alias prefixes
dpservice does longest-prefix-match on `ipv4_lookup`/`ipv6_lookup` and supports **alias prefixes**
(`CreatePrefix`/route announcement). Our `routes` is exact `/32`. Replace with an `LPM_TRIE` map
(aya supports `LpmTrie`) keyed by (vni, prefix); add `Create/Delete/ListPrefix` and
`...LoadBalancerPrefix`. **Milestone M8.**

### 4.4 Remote LB backends (re-encap)
dpservice maglev backends carry an **underlay endpoint**, so a selected backend on another
hypervisor is reached by re-encapping in `uplink_rx`. Our LB delivers only to local backends.
Extend `MAGLEV` values to `{backend_ipv4, underlay_ipv6}`; when the backend is remote, re-encap +
redirect to the uplink instead of delivering locally; pin the conntrack so the reply (which comes
back through us) is symmetric. Fold into the unified conntrack. **Milestone M9.**

### 4.5 NAT64 + NeighborNat (distributed NAT return)
Two distinct sub-features:
- **NAT64** (`SRC_NAT64`): an IPv6 guest reaching an IPv4 external — header translation v6→v4 on
  egress, v4→v6 on return. dpservice has `dp_nat_chg_ipv6_to_ipv4_hdr` / the reverse.
- **NeighborNat** (`CreateNeighborNat`): horizontal NAT scaling — return traffic for a NAT IP+port
  range may land on a *different* node that doesn't own the flow; that node looks up a
  `neighbor_nat` table (nat_ip, port range → owning underlay endpoint) and forwards it. This is
  the cross-node piece we stubbed.

Both in scope (no deferral). NAT64 needs IPv6 overlay support (§4.10) to be fully exercisable but
the translation logic is independent. **Milestone M10.**

### 4.6 Virtual services (`virtsvc`)
dpservice `virtsvc_node` + `dp_virtsvc.h`: a guest reaching a **virtual address:port** is DNAT'd
to a real backend service reached over the underlay (used for platform services — metadata, DNS,
etc.), with its own per-connection port mapping (and it participates in HA sync, §4.8). Add a
`VIRTSVC` config map + connection conntrack. **Milestone M11.**

### 4.7 Packet relay + rate metering
- `packet_relay_node`: relays ICMP errors / certain NAT-associated packets that can't be handled
  inline. Lower volume; needed for correctness of path-MTU and unreachable handling.
- **Rate metering:** dpservice applies a per-port srTCM color meter (`public_flow_rate_cap`) on
  south-north traffic and drops RED. An XDP analog uses a token-bucket in a per-port map updated
  with `bpf_ktime_get_ns`. **Milestone M12** (combined; both are per-port policy on egress).

### 4.8 HA flow-state sync (`sync_node` / `dp_sync`) — explicitly in scope
dpservice's sync is **active→backup, same machine**: a hot-standby dpservice *process* receives
incremental state over a local L2 ethertype (`0x88B5`) — `NAT_CREATE`/`NAT_DELETE`,
`VIRTSVC_CONN`, `PORT_MAC`, and `REQUEST_DUMP` (backup asks active to re-send all tables) — so a
failover doesn't drop live NAT/virtsvc connections.

**The eBPF model changes this problem favorably and must be designed deliberately:**
- BPF maps are **kernel-resident**; if we **pin** the conntrack/NAT/virtsvc maps under `bpffs`,
  the dynamic flow state **survives a control-plane (userspace) crash or upgrade** with zero loss
  — covering dpservice's primary HA motivation (process failover) *without* a sync protocol.
- For **active/backup of the whole node** (two processes, or blue/green control planes attaching
  to the same interfaces), the takeover process **re-opens the pinned maps** rather than rebuilding
  state — design `bring_up` to detect and adopt pinned maps.
- True **cross-host** redundancy (a different machine taking over an interface) is the NeighborNat
  territory (§4.5) plus control-plane re-binding, not the dpservice same-machine sync.

**Design deliverable for this milestone (decision: pinned-maps model, no sync protocol):** (a) pin
all dynamic-state maps under `bpffs`; (b) make the loader adopt-or-create pinned maps idempotently;
(c) document the failover model and prove it (kill + restart the control plane mid-flow; flows
survive). The dpservice `0x88B5` same-machine sync protocol is **not** implemented — pinned
kernel-resident maps cover the failover motive in an all-`xdp-dp` deployment, and mixed
dpservice/xdp-dp HA pairs are not a requirement. **Milestone M13.**

### 4.9 Packet capture (`Capture*`)
dpservice offloads capture via `rte_flow` mirror to a pcap sink. XDP analog: a capture flag in
config + `bpf_perf_event_output`/ringbuf to stream matched packets to a userspace pcap writer.
`CaptureStart`/`CaptureStop`/`CaptureStatus`. **Milestone M14.**

### 4.10 IPv6 overlay tenants
Foundation kept the overlay IPv4-over-IPv6. Full parity (and NAT64) needs IPv6 **tenant** support:
`interfaces`/`routes`/conntrack keyed on IPv6 inner addresses too. Large; gated with NAT64.
**Milestone M15** (or merged with M10).

### 4.11 gRPC surface completeness
Implement the remaining read/list/delete RPCs so metalnet's reconcile/observe loops work:
`List/Get/DeleteInterface`, `List/DeleteRoute`, `Get/ListLoadBalancer`,
`List/DeleteLoadBalancerTarget`, `List/DeleteNeighborNat`, `CheckVniInUse`, `ResetVni`. These
require userspace to **retain authoritative shadow state** (it largely does via `by_id`/`lbs`;
extend per feature). Folded into each feature's milestone rather than a separate one.

### 4.12 Offload-readiness (cross-cutting)
dpservice uses `rte_flow` async hardware offload for established flows. We stay pure-XDP, but the
**map-driven, per-flow-keyed** design is the offload-ready shape: an established conntrack entry is
exactly what an `rte_flow`/`tc`/hardware rule would encode. Keep every decision table-driven and
avoid per-packet userspace so a later offload backend (AF_XDP zero-copy, XDP hw-offload, or a
`tc`/`rte_flow` lowering) can mirror conntrack entries into hardware. No dedicated milestone;
enforced as a design review criterion on every milestone.

## 5. Proposed milestone sequence & dependencies

```
M5  Unified conntrack (TCP state + last_seen + userspace GC aging)   [keystone]
        |-> M6  Firewall (stateful, conntrack-cached, enforcement-gated)
        |-> M9  Remote LB backends (re-encap)         (refactor LB onto unified CT)
        |-> M10 NAT64 + NeighborNat                   (refactor NAT onto unified CT)
        |-> M13 HA flow-state (pinned maps + adopt-on-restart)
M7  Multi-VNI tenancy            (independent; touches all RPCs + lab)
M8  LPM routing + alias prefixes (independent)
M11 Virtual services             (depends on M5)
M12 Packet relay + rate metering (depends on M5 for relay; metering independent)
M14 Packet capture               (independent)
M15 IPv6 overlay tenants         (pairs with M10/NAT64)
```

Order: **M5 → M6 → M7 → M8** (the high-value parity core: conntrack, firewall, tenancy, routing),
then **M9/M10/M11** (advanced NAT/LB/virtsvc), then **M12/M13/M14/M15**.

Relationship to **sub-project 2 (ioiab drop-in)**: **decision — complete full parity (M5–M15)
before ioiab.** ioiab needs **ND + DHCPv4/v6 + dynamic taps** (its own spec) and does not depend on
the parity milestones, but we want the drop-in to land on top of a fully parity-complete dataplane
rather than a partial one. ioiab follows M15.

## 6. Testing strategy

Every milestone extends the existing `env/netns-e2e.sh` lab (reliable up/test/down + EXIT-trap)
with a dedicated acceptance gate, and is also validated on the **tap-based harness** (real
`IFF_TAP|IFF_VNET_HDR` devices) so behavior is proven on the production attachment model, not only
veth. eBPF programs stay gated by the verifier-load test. Per-milestone gates:
- **M5:** a TCP flow creates one conntrack entry, transitions states, and is GC'd after idle
  timeout; non-NAT/non-LB traffic now also tracked.
- **M6:** an INGRESS DROP rule is evaluated + cached (and, with enforcement enabled, actually
  drops); established return traffic is allowed statefully.
- **M7:** two VNIs with overlapping guest IPs stay isolated.
- **M8:** a `/24` route wins over a less-specific route (LPM); alias prefix announced.
- **M9:** LB distributes across a **remote** backend (on the peer hypervisor) with symmetric
  return.
- **M10:** NAT64 v6→v4 egress + return; NeighborNat return arriving on a non-owning node forwards
  correctly.
- **M13:** kill + restart the control plane mid-flow → live flows survive (pinned-map adoption).

Plus userspace unit tests per feature (rule matching, LPM, TCP state transitions, GC eligibility).

## 7. Explicitly in scope (no deferral) vs genuinely out

**In scope now (this backlog):** unified conntrack, stateful firewall, multi-VNI, LPM + prefixes,
remote LB backends, NAT64, NeighborNat, virtual services, packet relay, rate metering, HA
flow-state (pinned-map failover model), packet capture, full gRPC surface, IPv6 overlay tenants.

**Genuinely out of scope (not a dpservice dataplane behavior, or hardware-specific):** SR-IOV VF
management (we attach to taps/veths, not VFs); actual NIC hardware offload backends (the design
stays offload-*ready*, but a concrete `rte_flow`/hw-offload lowering is a separate future effort);
byte-exact internal algorithm parity.

## 8. Resolved decisions

1. **Sequencing vs ioiab:** ✅ **Full parity (M5–M15) first, then ioiab.** ioiab follows M15.
2. **Firewall enforcement default:** ✅ **Real enforcement ON by default** (a DROP rule drops),
   with a `firewall_enforce` config flag (default `true`) to disable for upstream-matching
   permissive behavior. (§4.1)
3. **HA dpservice wire compat:** ✅ **Pinned-maps model only** — no `0x88B5` sync protocol. Flow
   state is kernel-resident and survives control-plane restarts; the loader adopts pinned maps.
   (§4.8)
4. **Conntrack table sizing / GC cadence:** ✅ **Mirror dpservice constants** — `850k` max entries,
   30 s default timeout, 1-day established-TCP timeout. (§3)
