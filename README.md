# upf-edge

> A Rust + eBPF/XDP implementation of the 5G User Plane Function (UPF) data plane,
> interoperating with Open5GS and UERANSIM.

`upf-edge` accelerates 5G UPF packet processing entirely in the kernel via XDP.
The control plane (PFCP message handling, session state) runs in Rust userspace
and pushes forwarding state into eBPF maps; the kernel does GTP-U
decap/encap, session lookup, and `bpf_redirect` at near line rate.

**Status:** Phase 2 complete — full bidirectional ping from a 5G UE through
`upf-edge` to the public internet, with PFCP control-plane integration to
Open5GS SMF.

---

## Table of contents

- [Demo](#demo)
- [Architecture](#architecture)
- [Data plane flow](#data-plane-flow)
- [What's implemented](#whats-implemented)
- [What's out of scope](#whats-out-of-scope)
- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Detailed setup](#detailed-setup)
- [Testing with smf-sim](#testing with smf-sim)
- [Project structure](#project-structure)
- [eBPF maps](#ebpf-maps)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [References](#references)

---

## Demo

### PFCP control plane (smf-sim driving upf-edge)

https://github.com/Git-ijhwang/upf-edge/raw/main/docs/media/session_test.mp4

End-to-end PFCP cycle without Open5GS:
`add session 1` → both sides show the session →
`del session 0x01` → both sides confirm removal.

### Full 5G data plane (Open5GS + UERANSIM)

https://github.com/Git-ijhwang/upf-edge/raw/main/docs/media/ping_test.mp4

upf-edge running with Open5GS SMF + UERANSIM gNB and UE.
The UE attaches, a PDU session is established via PFCP,
and `ping 8.8.8.8` works end-to-end through the eBPF data plane.

---

## Architecture

`upf-edge` replaces the data-plane component of an Open5GS deployment. The 5G
core (AMF, SMF, AUSF, UDM, NRF, PCF, etc.) and the simulated RAN (UERANSIM gNB
and UE) remain untouched.

```mermaid
flowchart LR
    subgraph RAN["RAN (UERANSIM)"]
        UE["UE<br/>(uesimtun0)"]
        gNB["gNB<br/>172.22.0.23"]
    end

    subgraph Core["5G Core (Open5GS)"]
        AMF["AMF<br/>172.22.0.10"]
        SMF["SMF<br/>172.22.0.7"]
        OTHER["NRF · AUSF · UDM<br/>PCF · UDR · NSSF · SCP"]
    end

    subgraph UPF["upf-edge (this project)"]
        US["Userspace (Rust)<br/>PFCP parser · session FSM<br/>eBPF map updater"]
        XDP["Kernel XDP<br/>GTP-U decap/encap<br/>bpf_redirect"]
        US -.->|maps| XDP
    end

    INTERNET["Internet<br/>(8.8.8.8)"]

    UE <-->|NAS / NR radio| gNB
    gNB <-->|N3: GTP-U| XDP
    SMF <-->|N4: PFCP| US
    AMF <--> SMF
    XDP <-->|N6: plain IP| INTERNET
```

Interfaces handled:

| Interface | Protocol | Direction | Implemented by |
|---|---|---|---|
| **N3** | GTP-U / UDP 2152 | gNB ↔ UPF | XDP (decap + redirect) |
| **N4** | PFCP / UDP 8805 | SMF ↔ UPF | Userspace |
| **N6** | Plain IP | UPF ↔ DN | Kernel routing + NAT |

---

## Data plane flow

Two XDP entry points: `upf_edge_n3` on the gNB-side veth, `upf_edge_n6` on
`upfedge0`.

### Uplink: UE → Internet

```mermaid
sequenceDiagram
    participant UE
    participant gNB
    participant XDP_N3 as XDP (N3)
    participant K as Kernel routing
    participant Net as Internet

    UE->>gNB: IP packet
    gNB->>XDP_N3: GTP-U (UDP/2152)
    Note over XDP_N3: Validate Eth/IP/UDP/GTP-U<br/>Strip outer + opt headers<br/>Rewrite Eth (dst = upfedge0)
    XDP_N3->>K: bpf_redirect(upfedge1)
    K->>Net: NAT via eth0
```

### Downlink: Internet → UE

```mermaid
sequenceDiagram
    participant Net as Internet
    participant K as Kernel routing
    participant XDP_N6 as XDP (N6)
    participant gNB
    participant UE

    Net->>K: Reply IP packet
    K->>K: Route 192.168.100.X/32<br/>via upfedge1 (auto-installed)
    K->>XDP_N6: Packet arrives on upfedge0 RX
    Note over XDP_N6: SESSION_MAP lookup by UE IP<br/>adjust_head -36<br/>Build outer Eth/IP/UDP/GTP-U<br/>Add PDU Session Container ext (8B)<br/>dst MAC = GW_MAC[1] (gNB)
    XDP_N6->>gNB: bpf_redirect(N3 veth)<br/>GTP-U (flags=0x34)
    gNB->>UE: Decoded IP packet
```

The downlink path was the hardest part of Phase 2 — see
[`docs/PFCP_NOTES.md`](docs/PFCP_NOTES.md) for the bugs that
showed up between "encap function gets called" and "ping reply arrives at UE".

---

## What's implemented

| Component | Status |
|---|---|
| GTP-U decapsulation (uplink) | ✅ |
| GTP-U encapsulation (downlink) with PDU Session Container ext | ✅ |
| PFCP Heartbeat | ✅ |
| PFCP Association Setup/Release | ✅ |
| PFCP Session Establishment | ✅ |
| PFCP Session Modification (gnb_ip/teid update) | ✅ |
| PFCP Session Deletion | ✅ |
| `bpf_redirect` on both directions | ✅ |
| Dynamic MAC learning (no hardcoded values) | ✅ |
| Dynamic ifindex from CLI args | ✅ |
| UE route / neighbor auto-install on Session Establishment | ✅ |
| Session persistence in Redis (restart recovery) | ✅ |
| smf-sim PFCP simulator (Scenario 1: full lifecycle) | ✅ |
| smf-sim Scenarios 2–3 (multi-UE, load) | 🔴 planned |
| Ratatui TUI (operational view) | 🟡 partial |
| Prometheus metrics | 🔴 planned |
| Performance benchmarking | 🔴 planned |

---

## What's out of scope

Deliberately omitted to keep the project scoped:

- IPsec on N3 (required in production but adds complexity unrelated to the data-plane)
- IPv6 (will revisit in a later phase)
- Full QoS / 5QI differentiation (basic forwarding only)
- LI (Lawful Interception)
- N9 (UPF ↔ UPF) interface
- Multi-UPF selection logic

---

## Prerequisites

- **Linux host** with kernel ≥ 5.10 (Ubuntu 24.04 tested via Lima on Intel macOS)
- **Rust nightly** (pinned to `nightly-2026-05-10`; later nightlies have an LLVM SIGSEGV regression)
  - `rustup toolchain install nightly-2026-05-10 --component rust-src`
- **bpf-linker:** `cargo install bpf-linker`
- **Docker** with Docker Compose (for Open5GS + UERANSIM)
- **Redis** (for session persistence; optional but recommended)
- Build env variable to avoid LLVM stack overflow: `export RUST_MIN_STACK=67108864`

This project uses [herlesupreeth/docker_open5gs](https://github.com/herlesupreeth/docker_open5gs)
as the reference 5G core + RAN simulator. Clone it separately:

```bash
git clone https://github.com/herlesupreeth/docker_open5gs.git ~/docker-open5gs
```

---

## Quick start

Assuming the host environment is set up (see [Detailed setup](#detailed-setup) for first-time setup):

```bash
# Terminal A: bring up the 5G core, gNB, and find the gNB veth
cd ~/docker-open5gs
docker compose -f sa-deploy.yaml up -d
docker compose -f sa-deploy.yaml stop upf   # we replace the default UPF
docker compose -f nr-gnb.yaml up -d && sleep 8

GNB_LINK=$(docker exec nr_gnb cat /sys/class/net/eth0/iflink)
for v in $(ls /sys/class/net/ | grep veth); do
  idx=$(cat /sys/class/net/$v/ifindex)
  [ "$idx" = "$GNB_LINK" ] && echo "gNB veth: $v"
done

# Terminal B: build & run upf-edge
cd ~/upf-edge
cargo build --release
sudo RUST_LOG=info ./target/release/upf-edge \
  --iface-n3 <gNB_veth_from_above> \
  --iface-n6 upfedge0 \
  --n4-addr 172.22.0.8 \
  --n3-addr 172.22.0.8

# Terminal A: attach the UE
docker compose -f nr-ue.yaml up -d && sleep 15
docker exec nr_ue ping -I uesimtun0 8.8.8.8 -c 5
```

Expected: `0% packet loss`, RTT around 2–3 ms.

---

## Detailed setup

### One-time host setup (VM after reboot)

```bash
# veth pair for the N6 side
sudo ip link add upfedge0 type veth peer name upfedge1
sudo ip addr add 192.168.100.1/24 dev upfedge0
sudo ip link set upfedge0 up
sudo ip link set upfedge1 up

# IP forwarding + disable rp_filter
sudo sysctl -w net.ipv4.ip_forward=1
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
  echo 0 | sudo tee $f > /dev/null
done

# Bridge alias so upf-edge can bind 172.22.0.8 (Open5GS's UPF address)
BR=br-b9f9cfe60aba   # docker_open5gs's bridge name
sudo ip addr add 172.22.0.8/24 dev $BR

# iptables: allow UE subnet through FORWARD chain and MASQUERADE for internet
sudo iptables -I FORWARD -s 192.168.100.0/24 -j ACCEPT
sudo iptables -I FORWARD -d 192.168.100.0/24 -j ACCEPT
sudo iptables -t nat -A POSTROUTING -s 192.168.100.0/24 ! -o $BR -j MASQUERADE
```

### Per-session runbook

Scenarios (full list in [`RUNBOOK.md`](RUNBOOK.md)):

1. **VM reboot**: redo the one-time setup, then Quick start
2. **Code change → retest**: `pkill upf-edge`, rebuild, restart with same args
3. **UE reattach only**: `docker compose -f nr-ue.yaml down && up -d` — routes auto-reinstall

---

## Testing with smf-sim

The `smf-sim` crate is a minimal PFCP SMF simulator that lets you exercise
`upf-edge`'s control plane in isolation — no Open5GS, no UERANSIM, no
containers required (other than for MAC learning on startup).

### Why this exists

The full Open5GS + UERANSIM environment is great for end-to-end ping
validation but painful for fast iteration:

- gNB veth and Docker bridge MACs change on every container recreate
- AMF/SMF interdependencies mean stopping SMF often takes down NGAP too
- A single PFCP message change forces a full UE re-attach cycle to retest
- CI cannot reasonably bring up 15+ containers per PR

`smf-sim` sidesteps all of that. It speaks PFCP directly to `upf-edge` over
UDP/8805 and runs deterministic scenarios end-to-end in under a second
(plus a configurable wait for Heartbeats).

### Running scenario 1

Scenario 1 is the full PFCP lifecycle for a single UE:

```
Association Setup → Session Establishment → Heartbeat × 3
                  → Session Modification → Session Deletion
```

The Modification step exercises the same control-plane path Open5GS uses
when the gNB's N3 endpoint arrives late (see [`docs/PFCP_NOTES.md`](docs/PFCP_NOTES.md) §1).

**One-time setup (in addition to the Detailed setup above):**

```bash
# Stop Open5GS SMF so smf-sim can take the N4 peer slot
docker compose -f sa-deploy.yaml stop smf

# Add the smf-sim bind alias on the docker bridge
sudo ip addr add 172.22.0.50/24 dev br-b9f9cfe60aba
```

**Run:**

```bash
# Terminal B: start upf-edge (any veth is fine for --iface-n3
# since smf-sim doesn't generate GTP-U traffic)
sudo RUST_LOG=info ./target/release/upf-edge \
  --iface-n3 upfedge1 \
  --iface-n6 upfedge0 \
  --n4-addr 172.22.0.8 \
  --n3-addr 172.22.0.8

# Terminal C: run scenario 1
./target/release/smf-sim \
  --config smf-sim/configs/sim-default.toml \
  run --scenario 1 --num-ues 1
```

Expected output from smf-sim:

```
✓ [1/6] Association Setup
✓ [2/6] Session Establishment
✓ [3/6] Heartbeat × 3
✓ [4/6] Session Modification
✓ [5/6] Session Deletion
Scenario 1: PASSED (Association → Est → HB × 3 → Mod → Del)
```

Total runtime ≈ 50 seconds (most of it waiting for the three Heartbeats).

### Scenarios

| # | Name | Status |
|---|---|---|
| 1 | Basic lifecycle (single UE, full PFCP cycle) | ✅ |
| 2 | Multi-UE concurrent (N=3..100) | 🔴 planned |
| 3 | Load test (≥ 100 sessions/s) | 🔴 planned |

### What the validator checks

For every response, the validator confirms:

- PFCP version, message type (`request_type + 1`), sequence number
- All Mandatory IEs present (driven by `pfcp-common/src/dict.rs`)
- `Cause` IE == 1 (Request Accepted) when present
- For Session Establishment Response: F-SEID non-zero, Created PDR
  contains a valid F-TEID (TEID ≠ 0, IP ≠ 0.0.0.0)

This catches regressions in IE encoding, message framing, and the
dictionary's Mandatory/Conditional/Optional flags — exactly the class of
bugs that previously required Open5GS to surface.

### Other modes

`smf-sim` also exposes:

```bash
smf-sim send heartbeat                  # one-shot Heartbeat probe
smf-sim send association                # one-shot Association Setup
smf-sim interactive                     # TUI (Ratatui-based, WIP)
```

`smf-sim --help` for the full CLI.

---


## Project structure

```
upf-edge/
├── upf-edge/              # Userspace (Rust + Tokio)
│   ├── pfcp_server.rs       PFCP UDP listener
│   ├── handle_msg.rs        Per-message-type handlers + UE route automation
│   ├── session_store.rs     Redis persistence
│   └── main.rs              CLI, eBPF loading, map population
│
├── upf-edge-ebpf/         # Kernel XDP programs
│   └── main.rs              try_upf_edge (N3 decap), try_encap (N6 encap)
│
├── upf-edge-common/       # Types shared between userspace and kernel (no_std)
│   └── SessionInfo, FarValue, PdrValue, MacAddr, ...
│
├── pfcp-common/           # PFCP protocol library
│   ├── header.rs, ie.rs     Encoding/decoding
│   ├── messages.rs          Typed Request/Response structs
│   ├── dict.rs              IE validation rules
│   └── builder.rs           Outgoing message builders
│
└── smf-sim/               # PFCP SMF simulator (no Open5GS required)
    ├── main.rs              CLI: run / send / interactive
    ├── scenario/            Test scenarios (Scenario 1 implemented)
    ├── transport.rs         UDP transport with retries + timeouts
    ├── keepalive.rs         Heartbeat keepalive loop
    └── validator.rs         Response validation (driven by pfcp-common/dict)
```

---

## eBPF maps

Userspace populates these on startup and on every PFCP event. The XDP programs
do read-only lookups during packet processing.

```mermaid
flowchart LR
    subgraph US[Userspace]
        BOOT[main.rs<br/>boot-time]
        PFCP[handle_msg.rs<br/>per PFCP message]
    end

    subgraph Maps[eBPF maps]
        GW["GW_MAC<br/>Array&lt;MacAddr&gt;<br/>0: upfedge0<br/>1: gNB"]
        IF["IF_INDEX<br/>Array&lt;u32&gt;<br/>0: N3 veth<br/>1: upfedge1"]
        SES["SESSION_MAP<br/>HashMap&lt;ue_ip, SessionInfo&gt;"]
        PDR["PDR_MAP<br/>HashMap&lt;pdr_id, PdrValue&gt;"]
        FAR["FAR_MAP<br/>HashMap&lt;far_id, FarValue&gt;"]
    end

    subgraph XDP[Kernel XDP]
        N3[try_upf_edge<br/>uplink decap]
        N6[try_encap<br/>downlink encap]
    end

    BOOT -.->|read MAC from sysfs| GW
    BOOT -.->|read ifindex from sysfs| IF
    PFCP -.->|Session Est/Mod/Del| SES
    PFCP -.->|Session Est| PDR
    PFCP -.->|Session Est/Mod| FAR

    GW -->|lookup| N3
    GW -->|lookup| N6
    IF -->|lookup| N3
    IF -->|lookup| N6
    SES -->|lookup| N3
    SES -->|lookup| N6
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Failed to read N3 ifindex` at startup | wrong `--iface-n3` value | Re-run the `GNB_LINK` lookup; the gNB veth changes every restart |
| PFCP Association keeps retrying | upf-edge can't bind `172.22.0.8` | Check `sudo ip addr show $BR \| grep 172.22.0.8` — alias missing |
| `Decapsulated.` logs but no internet | `rp_filter` enabled | `for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 \| sudo tee $f; done` |
| Uplink works, downlink ping timeouts | `iptables FORWARD` rejecting reverse path | Verify the `-d 192.168.100.0/24 -j ACCEPT` rule |
| `Encapsulated:` logs but no packet at gNB | wrong dst MAC | Confirm `GW_MAC[1]` matches `docker exec nr_gnb cat /sys/class/net/eth0/address` |
| PFCP "F-SEID missing" in Session Modification | dict still has it as Mandatory | Already fixed; ensure you're on the latest commit |

When in doubt, this is the bisection order:

```bash
# 1. Are XDP programs attached?
sudo bpftool net show

# 2. Are the maps populated correctly?
sudo bpftool map dump name SESSION_MAP
sudo bpftool map dump name GW_MAC

# 3. Is GTP-U actually arriving at the gNB container?
GNB_PID=$(docker inspect -f '{{.State.Pid}}' nr_gnb)
sudo nsenter -t $GNB_PID -n tcpdump -i eth0 -n "udp port 2152" -c 4

# 4. Are PFCP messages flowing?
sudo tcpdump -i any -n "udp port 8805" -c 10
```

---

## Roadmap

- **Phase 2.5**: round out smf-sim — scenarios 2–6 (multi-UE, error handling, load) and CI integration
- **Phase 3**: performance benchmarking (TRex) vs Open5GS UPF, target ≥ 2× pps
- **Phase 4**: Ratatui TUI completion, Prometheus exporter, Grafana dashboard
- **Phase 5**: IPv6 support, multi-UE QoS, write-up + demo video

See [PFCP_NOTES.md](docs/PFCP_NOTES.md) for an engineering deep-dive on the
subtler bugs found during Phase 2 — particularly the Session Modification
handler and the GTP-U PDU Session Container extension header.

---

## References

### 3GPP specs

- **TS 29.244** — PFCP (control plane between SMF and UPF)
- **TS 29.281** — GTP-U
- **TS 38.415** — PDU Session User Plane Protocol (the extension header)
- **TS 23.501** — System Architecture for 5G

### Open-source projects

- [Open5GS](https://github.com/open5gs/open5gs) — reference 5G core (control plane)
- [UERANSIM](https://github.com/aligungr/UERANSIM) — UE and gNB simulator
- [herlesupreeth/docker_open5gs](https://github.com/herlesupreeth/docker_open5gs) — Dockerised test harness used here
- [aya-rs/aya](https://github.com/aya-rs/aya) — Rust + eBPF framework
- [eUPF](https://github.com/edgecomllc/eupf) — closely related Go + eBPF UPF, good reference reading

### Libraries

- `aya` — Rust eBPF loader/runtime
- `tokio` — async runtime for the userspace control plane
- `ratatui` — TUI
- `redis` — session persistence

---

## License

Dual-licensed under MIT or Apache 2.0, at your option. eBPF programs are
dual-licensed under MIT and GPL-2.0 (the kernel requires a GPL-compatible
license for eBPF helpers).
