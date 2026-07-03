# upf-edge

**5G User Plane Function (UPF) implemented in Rust + eBPF/XDP, with multi-SMF association management compliant with 3GPP TS 29.244 §5.5.**

`upf-edge` is a data-plane accelerator for the 5G User Plane Function. The control plane parses PFCP messages in Rust userspace; the data plane processes GTP-U packets in the Linux kernel via eBPF/XDP. The two halves communicate through eBPF maps as a shared data structure that both sides agree on — userspace writes rules, kernel reads them on every packet, with atomic updates while traffic keeps flowing.

The project interoperates with Open5GS and free5GC control planes over the N4 (PFCP) interface. It runs on commodity Linux servers without dedicated hardware or DPDK's polling-mode CPU dedication.

**Article on architecture and NTN edge scenarios**: [Building a 5G UPF in Rust + eBPF](https://medium.com/@hwangij/building-a-5g-upf-for-the-edge-in-rust-and-ebpf-746cc1a3432d?sharedUserId=hwangij)

---

## Architecture
            ┌──────────────────────────────────────────┐
            │  SMF (from Open5GS / free5GC)            │
            └──────────────────────────────────────────┘
                             │  PFCP / N4
                             ▼
┌── UPF-EDGE ───────────────────────────────────────────────────┐
│ ┌───────────────────────────────────────────────────────────┐ │ 
│ │  Userspace (Rust)                                         │ │ 
│ │  ├── PFCP TLV parser / encoder (pfcp-common)              │ │ 
│ │  ├── Session state machine                                │ │ 
│ │  ├── Multi-SMF association manager (3GPP TS 29.244 §5.5)  │ │ 
│ │  ├── Redis session store (persistence + restart recovery) │ │ 
│ │  └── Ratatui TUI (session list, event log, commands)      │ │ 
│ └───────────────────────────────────────────────────────────┘ │ 
│             │ eBPF maps (SESSION_MAP, PDR_MAP, FAR_MAP)       │ 
│             ▼                                                 │ 
│ ┌───────────────────────────────────────────────────────────┐ │ 
│ │  Kernel (eBPF/XDP via aya)                                │ │ 
│ │  ├── GTP-U encapsulation / decapsulation                  │ │ 
│ │  ├── TEID-based session lookup                            │ │ 
│ │  ├── PDR / FAR rule application                           │ │ 
│ │  ├── N3 ↔ N6 redirect (bpf_redirect)                      │ │ 
│ │  └── UDP/IP checksum recomputation                        │ │ 
│ └───────────────────────────────────────────────────────────┘ │ 
└───────────────────────────────────────────────────────────────┘
          ▲                              ▲
          │                              │
     N3 (gNB → UPF, GTP-U)         N6 (DN, plain IP)

---

## What's implemented

### Data plane (kernel, eBPF/XDP)

- IP → UDP → GTP-U decapsulation on the N3 interface
- GTP-U encapsulation with outer header reconstruction on the N6 return path
- N3 ↔ N6 interface redirect via `bpf_redirect`
- UDP / IP checksum recomputation
- XDP attached to the Docker bridge interface (`br-*`) in `SKB_MODE` for virtual-interface support
- Automatic UE route and neighbor management (installed on Session Establishment, removed on Deletion)
- Three eBPF maps: `SESSION_MAP`, `PDR_MAP`, `FAR_MAP`

### Control plane (userspace, Rust)

- PFCP TLV parser and encoder (`pfcp-common` crate)
- PFCP server handling five core messages:
  - Association Setup Request / Response
  - Session Establishment Request / Response
  - Session Modification Request / Response
  - Session Deletion Request / Response
  - Heartbeat Request / Response
- Session state machine (Establishment → Modification → Deletion lifecycle)
- Redis-backed session persistence with restart recovery

### Multi-SMF support (3GPP TS 29.244 §5.5 compliant)

- `SmfAssociation` per-SMF isolation with exclusive session ownership
- Composite key `(NodeId, cp_seid)` for cross-SMF session identification
- Source SocketAddr verification (IP + port) — allows multiple SMF instances on the same host
- Soft cleanup on heartbeat failure (sessions preserved for potential SMF recovery)
- Replace-on-restart based on Recovery Time Stamp comparison (3GPP TS 29.244 §6.2.6)
- Per-association Recovery TS and heartbeat tracking
- Wire-format compatible with Open5GS and Wireshark PFCP dissector

### Simulator (`smf-sim`)

- Standalone SMF PFCP simulator for functional testing
- Scenario-based test runner (basic session lifecycle)
- Interactive mode via Ratatui
- Multi-instance execution for validating Multi-SMF isolation
- socket2-based transport for source IP/port control

### Operations

- Ratatui TUI showing active sessions, event log, and interactive commands
- Environment setup and teardown scripts (`bootup.sh`, `shutdown.sh`) — idempotent, handling veth, bridge alias, iptables, and `rp_filter`

---

## Verified against

- **Open5GS**: end-to-end integration with `sa-deploy.yaml`. UE attach, IP allocation, uplink/downlink traffic verified with UERANSIM.
- **Wireshark**: PFCP wire format validated against the Open5GS Discord community dissector output.
- **Multi-SMF scenario**: two `smf-sim` instances running concurrently, each establishing an independent session. Q1 exclusive ownership blocks cross-SMF modification and deletion. Q6 replace logic tested by restart with new Recovery TS.

---

## Project structure
upf-edge/
├── Cargo.toml                     # workspace root
├── upf-edge/                      # userspace (control plane)
│   └── src/
│       ├── main.rs
│       ├── pfcp_server.rs         # PFCP server + keepalive
│       ├── handle_msg.rs          # 5 PFCP message handlers
│       ├── association.rs         # SmfAssociation + HeartbeatTracker
│       ├── session_store.rs       # Redis persistence
│       └── tui/                   # Ratatui interface
├── upf-edge-ebpf/                 # kernel (data plane, XDP)
├── upf-edge-common/               # shared types (no_std)
├── pfcp-common/                   # PFCP TLV parser / builder
├── smf-sim/                       # PFCP simulator
│   ├── src/
│   │   ├── main.rs                # scenario runner
│   │   ├── transport.rs           # socket2-based UDP
│   │   └── scenario/              # test scenarios
├── scripts/
│   ├── bootup.sh                  # environment setup (idempotent)
│   └── shutdown.sh                # cleanup (upf-edge, XDP detach, veth, iptables)
└── README.md

---

## Requirements

- Linux (tested on Ubuntu 22.04 in Lima VM)
- Rust nightly `nightly-2026-05-10` (fixed due to LLVM SIGSEGV in later nightlies)
- `RUST_MIN_STACK=67108864` (LLVM stack overflow workaround)
- Docker + Docker Compose (for Open5GS / UERANSIM integration testing)
- Redis (for session persistence)

---

## Quick start

Environment setup (VM reboots wipe network state, so run this after each boot):

```bash
./scripts/bootup.sh              # veth, bridge alias, iptables, rp_filter
docker compose -f sa-deploy.yaml up -d
docker compose -f sa-deploy.yaml stop upf   # replace Open5GS UPF with upf-edge
```

Build and run:

```bash
cargo build --release
sudo RUST_LOG=info ./target/release/upf-edge --iface-n3 upfedge1
```

Standalone testing with the SMF simulator:

```bash
./target/release/smf-sim \
    --config smf-sim/configs/sim-default.toml \
    run --scenario 1 --num-ues 1
```

Cleanup:

```bash
./scripts/shutdown.sh
```

---

## What's not in this project

Intentional scope limits:

- Full PFCP feature set — only the five core messages
- IPSec — production requires it, but out of scope here
- IPv6 — Phase 2
- Full QoS differentiation — basic DSCP marking only
- Lawful interception (LI)
- N9 inter-UPF interface

The scope is set to keep the project completable and its behavior fully understood, not to reproduce a commercial UPF.

---

## What's next

Currently in progress or planned:

- URR (Usage Reporting Rule) implementation for data-plane statistics
- Prometheus metrics exporter
- Performance benchmarking against Open5GS's userspace UPF (deferred until suitable test environment is available)
- Additional PFCP message coverage as needed
- Continued articles on architecture decisions and lessons

---

## References

- 3GPP TS 29.244 (PFCP) — §5.5 Association Management, §7 Message Formats
- 3GPP TS 29.281 (GTP-U) — §5 Header
- 3GPP TS 23.501 (5G System Architecture) — §4
- 3GPP TR 23.700-27 (Satellite Backhauling in 5GS) — Section 6.5, Satellite Edge Computing via on-board UPF

