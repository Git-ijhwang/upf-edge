# upf-edge Runbook

Operational reference for restarting and testing `upf-edge` in the Lima VM
environment. This complements the [README](README.md) by documenting the
exact command sequences for the most common day-to-day workflows.

> All commands assume:
> - Lima VM `lima-open5gs` is running
> - `~/upf-edge` and `~/docker-open5gs` exist
> - Two terminals open inside the VM:
>   - **Terminal A** — host operations (containers, networking, UE)
>   - **Terminal B** — `upf-edge` process (its own log stream)
>   - **Terminal C** — optional, for `smf-sim` when used

---

## Scenario 1 — VM cold start (everything from scratch)

Use after a VM reboot or when network state has been wiped.

| # | Terminal | Command | Purpose |
|---|---|---|---|
| 1 | A | `sudo ip link add upfedge0 type veth peer name upfedge1` | Create veth pair |
| 2 | A | `sudo ip addr add 192.168.100.1/24 dev upfedge0` | upfedge0 IP |
| 3 | A | `sudo ip link set upfedge0 up && sudo ip link set upfedge1 up` | Bring up |
| 4 | A | `sudo sysctl -w net.ipv4.ip_forward=1` | IP forwarding |
| 5 | A | `for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 \| sudo tee $f > /dev/null; done` | Disable rp_filter |
| 6 | A | `cd ~/docker-open5gs && docker compose -f sa-deploy.yaml up -d && sleep 15` | 5G core (15 containers) |
| 7 | A | `docker compose -f sa-deploy.yaml stop upf` | Stop default UPF (we replace it) |
| 8 | A | `sudo ip addr add 172.22.0.8/24 dev br-b9f9cfe60aba` | Bridge alias for upf-edge |
| 9 | A | `sudo iptables -I FORWARD -s 192.168.100.0/24 -j ACCEPT` | FORWARD chain |
| 10 | A | `sudo iptables -I FORWARD -d 192.168.100.0/24 -j ACCEPT` | FORWARD chain (reverse) |
| 11 | A | `sudo iptables -t nat -A POSTROUTING -s 192.168.100.0/24 ! -o br-b9f9cfe60aba -j MASQUERADE` | NAT for internet egress |
| 12 | A | `docker compose -f nr-gnb.yaml up -d && sleep 8` | Start gNB |
| 13 | A | `docker logs nr_gnb 2>&1 \| grep "NG Setup procedure is successful"` | Verify gNB ↔ AMF |
| 14 | A | See "Find gNB veth" below | Get the dynamic veth name |
| 15 | B | `cd ~/upf-edge && redis-cli FLUSHALL 2>/dev/null` | Clear Redis state |
| 16 | B | See "Start upf-edge" below | Run with the gNB veth found above |
| 17 | A | `docker compose -f nr-ue.yaml up -d && sleep 15` | Start UE |
| 18 | A | `docker logs nr_ue 2>&1 \| grep "TUN interface"` | Verify UE attached |
| 19 | A | `docker exec nr_ue ping -I uesimtun0 8.8.8.8 -c 5` | End-to-end ping test |

---

## Scenario 2 — Code change → retest (core and gNB stay up)

Use after editing source. Most common workflow.

| # | Terminal | Command | Purpose |
|---|---|---|---|
| 1 | B | `sudo pkill -9 -f upf-edge` | Stop running upf-edge |
| 2 | B | `cd ~/upf-edge && cargo build --release 2>&1 \| tail -3` | Rebuild |
| 3 | A | `cd ~/docker-open5gs && docker compose -f nr-ue.yaml down` | Stop UE for clean session |
| 4 | A | `for ip in $(ip route \| grep "dev upfedge1" \| awk '{print $1}'); do sudo ip route del $ip 2>/dev/null; sudo ip neigh del $ip dev upfedge1 2>/dev/null; done` | Clear stale UE routes |
| 5 | A | See "Find gNB veth" — the name may have changed | Refresh veth |
| 6 | B | `redis-cli FLUSHALL 2>/dev/null` | Clear Redis |
| 7 | B | See "Start upf-edge" | Restart with new build |
| 8 | A | `docker compose -f nr-ue.yaml up -d && sleep 15` | Re-attach UE |
| 9 | A | `docker exec nr_ue ping -I uesimtun0 8.8.8.8 -c 5` | Verify |

---

## Scenario 3 — UE reattach only (fastest test cycle)

Use when only the UE side needs to be reset. Routes auto-install via PFCP.

| # | Terminal | Command | Purpose |
|---|---|---|---|
| 1 | A | `cd ~/docker-open5gs && docker compose -f nr-ue.yaml down` | UE down |
| 2 | A | `sleep 5 && docker compose -f nr-ue.yaml up -d && sleep 15` | UE up |
| 3 | A | `docker exec nr_ue ping -I uesimtun0 8.8.8.8 -c 5` | Verify |

No manual `ip route` or `ip neigh` commands needed — the upf-edge PFCP
handlers install/remove them automatically on Session Establishment and
Session Deletion.

---

## Scenario 4 — Smf-sim isolated PFCP testing (no Open5GS)

Use to exercise `upf-edge`'s control plane without depending on Open5GS
SMF, gNB, or UE.

| # | Terminal | Command | Purpose |
|---|---|---|---|
| 1 | A | `docker compose -f sa-deploy.yaml stop smf` | Open5GS SMF must be stopped |
| 2 | A | `sudo ip addr add 172.22.0.50/24 dev br-b9f9cfe60aba` | smf-sim bind alias |
| 3 | B | `sudo pkill -9 -f upf-edge && redis-cli FLUSHALL 2>/dev/null` | Reset upf-edge state |
| 4 | B | See "Start upf-edge" (any veth works for `--iface-n3`) | upf-edge |
| 5 | C | `cd ~/upf-edge && ./target/release/smf-sim --config smf-sim/configs/sim-default.toml run --scenario 1 --num-ues 1` | Run scenario 1 |

Expected output: `Scenario 1: PASSED (Association → Est → HB × 3 → Mod → Del)`

Runtime ≈ 50 seconds (most of it is waiting for the three Heartbeats).

To return to a full-stack ping test after using smf-sim, restart
Open5GS SMF: `docker compose -f sa-deploy.yaml start smf`.

---

# RUNBOOK.md — Scenario 5 (new)

Add this scenario between Scenario 4 and "Shared helpers".

---

## Scenario 5 — Config change (no rebuild)

Use after editing `upf-edge/configs/upf-edge-default.toml`. No code change,
no rebuild — just kick upf-edge to pick up the new file.

| # | Terminal | Command | Purpose |
|---|---|---|---|
| 1 | B | `sudo pkill -9 -f upf-edge` | Stop the running process |
| 2 | B | See "Start upf-edge" | Restart (auto-discovers new config) |
| 3 | A | `docker compose -f nr-ue.yaml down && sleep 3 && docker compose -f nr-ue.yaml up -d && sleep 15` | UE re-attach to pick up new session |
| 4 | A | `docker exec nr_ue ping -I uesimtun0 8.8.8.8 -c 5` | Verify the new config still routes traffic |

The config file is loaded at boot only — there is no SIGHUP reload. The
PFCP session table is not affected by a config change, but UE sessions
must be re-established because the upf-edge process dropped the eBPF
maps with it.

---

## Generic Linux deployment

When deploying on a host that is **not** the Lima VM (no `docker_open5gs`
network, no `nr_gnb` container), use a config like:

```toml
# /etc/upf-edge/upf-edge.toml — generic Linux deployment

[interfaces]
n3_iface = "eth0"          # whatever NIC faces the gNB
n6_iface = "eth1"          # whatever NIC faces the data network
n3_addr = "10.0.0.5"
ue_deliver_iface = "eth1"

[pfcp]
n4_addr = "10.0.0.5"
n4_port = 8805

[peers]
gnb_addr = "10.0.0.10"     # ARP-learned at boot

[redis]
url = "redis://127.0.0.1/"
```

Start with an explicit config path:

```bash
sudo ./target/release/upf-edge --config /etc/upf-edge/upf-edge.toml
```

No CLI args required — the config supplies all interfaces and addresses.


## Shared helpers

### Find gNB veth (run this every restart — the name changes)

```bash
GNB_LINK=$(docker exec nr_gnb cat /sys/class/net/eth0/iflink)
for v in $(ls /sys/class/net/ | grep veth); do
  idx=$(cat /sys/class/net/$v/ifindex)
  [ "$idx" = "$GNB_LINK" ] && echo "★ gNB veth: $v"
done
```

### Start upf-edge

Replace `<gNB_veth>` with the value from above (e.g. `veth9b909bb`):

```bash
sudo RUST_LOG=info ./target/release/upf-edge \
  --iface-n3 <gNB_veth> \
  --iface-n6 upfedge0 \
  --n4-addr 172.22.0.8 \
  --n3-addr 172.22.0.8
```

Expected boot log:

```
GW_MAC[0] upfedge0=[92, b7, 9a, 83, c1, 19]
GW_MAC[1] gNB=[...]               # changes with each gNB container restart
IF_INDEX set: N3(<veth>)=..., N6(upfedge1)=...
N3 XDP attached to <veth>
N6 XDP attached to upfedge0
PFCP Server started on 172.22.0.8:8805
```

---

## Verification logs

What to see in Terminal B (upf-edge) after a successful UE attach:

| Event | Log line |
|---|---|
| PFCP Association | `[Dict] Association Setup Request - IE validation passed` |
| Session Establishment | `Session created: seid=X, UE=192.168.100.X, TEID=0x3eX` |
| Session Modification | `Session Modification: SEID=X, new_gNB=172.22.0.23, new TEID=0x...` |
| Map updated | `eBPF SESSION_MAP updated: UE=... → TEID=..., gNB=172.22.0.23` |
| Route installed | `UE route/neigh installed: 192.168.100.X -> upfedge1` |
| Uplink ping | `GTP-U packet: TEID=...` + `Decapsulated.` |
| Downlink ping | `Encapsulated: TEID=...` |

If any of these are missing, jump to the Troubleshooting section in the
[README](README.md#troubleshooting).

---

## Quick diagnostics

| Goal | Terminal | Command |
|---|---|---|
| Check SESSION_MAP contents | A | `sudo bpftool map dump name SESSION_MAP` |
| Check XDP attach state | A | `sudo bpftool net show` |
| Find the current UE IP | A | `docker exec nr_ue ip addr show uesimtun0 \| grep "inet "` |
| Inspect host routes for UEs | A | `ip route \| grep 192.168.100` |
| Capture GTP-U inside gNB ns | A | `GNB_PID=$(docker inspect -f '{{.State.Pid}}' nr_gnb); sudo nsenter -t $GNB_PID -n tcpdump -i eth0 -n "udp port 2152" -c 4` |
| Capture PFCP on the host | A | `sudo tcpdump -i any -n "udp port 8805" -c 10` |
| Check both bridge aliases | A | `ip addr show br-b9f9cfe60aba \| grep -E "172.22.0.(8\|50)"` |

---

## Notes on environment volatility

Each container restart re-randomizes:

- gNB veth name and ifindex
- Docker bridge MAC
- gNB eth0 MAC

upf-edge handles all of this dynamically at startup (see the README
"eBPF maps" section), so the only operator step is finding the gNB veth
name for `--iface-n3`.

Each VM reboot wipes:

- veth pair `upfedge0`/`upfedge1`
- Bridge aliases (`172.22.0.8`, `172.22.0.50`)
- `iptables` rules
- `sysctl` settings (`ip_forward`, `rp_filter`)

These need to be reapplied via Scenario 1 steps 1–11.
