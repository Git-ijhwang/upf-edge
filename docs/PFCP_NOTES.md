# PFCP & data-plane engineering notes

A deep-dive on the non-obvious problems encountered while making `upf-edge`
interoperate with Open5GS SMF and UERANSIM, beyond the textbook PFCP/GTP-U flow.
Each note describes a concrete failure mode and what it took to fix.

---

## 1. PFCP Session Modification carries the real gNB IP, not Session Establishment

**Symptom:** After PFCP Session Establishment Request, the SESSION_MAP's
`gnb_ip` ended up as `172.22.0.7` (the SMF's address), not `172.22.0.23` (the
real gNB). Uplink worked because the gNB IP is irrelevant on uplink; downlink
encap built GTP-U packets addressed to the SMF, which silently dropped them.

**Root cause:** A 5G PDU Session is established in two phases:

1. AMF asks SMF to set up the session. SMF *does not yet know* the gNB's N3
   endpoint at this point. SMF sends PFCP Session Establishment Request to UPF
   with a placeholder (typically the SMF's own address) in the Outer Header
   Creation IE.
2. AMF later relays the gNB's actual Initial Context Setup Response (which
   carries the gNB's TEID and N3 IP) to SMF. SMF then sends **PFCP Session
   Modification Request** to UPF with the real `gnb_ip` and `teid` in
   Update FAR → Update Forwarding Parameters → Outer Header Creation.

`upf-edge` had no Session Modification handler. The dispatcher fell through to
`Ignored response msg_type=52`.

**Fix:**

- `pfcp-common/src/messages.rs`: added `SessionModificationReq` struct.
- `pfcp-common/src/ie.rs`: added `parse_update_far` (delegates to the existing
  `parse_forwarding_params` since the IE structure is identical).
- `pfcp-common/src/dict.rs`: changed F-SEID from `Mandatory` to `Conditional`
  for `msg_type=52`. The 3GPP spec says F-SEID is conditional when the header
  SEID alone identifies the session — which is what Open5GS does.
- `upf-edge/src/handle_msg.rs`: added `handle_session_modification` that takes
  the header SEID, looks up the existing session, extracts the new
  `gnb_ip` and `teid` from Update FAR's OHC, and writes them back to
  SESSION_MAP and FAR_MAP.

After this, the downlink path used the real gNB address.

---

## 2. `xdp_adjust_head -50` for encap leaves a 14-byte inner Ethernet stranded inside GTP-U payload

**Symptom:** With downlink encap going through the wire to the gNB, packet
captures showed the GTP-U payload starting with two upfedge1 MAC addresses
followed by an Ethernet type, then the inner IP — a 14-byte misalignment that
made the gNB silently drop the packet.

**Root cause:** The incoming packet on `upfedge0` already has its own
Ethernet header (`[outer Eth(14) | inner IP(20) | …]`). The original encap code
did `bpf_xdp_adjust_head(-50)` to make room for `Eth + IP + UDP + GTP-U`, then
wrote a new Ethernet header at the start. The 14 bytes of original outer
Ethernet were never overwritten — they ended up *inside* the GTP-U payload,
between the GTP-U header and the inner IP.

**Fix:** Reduce `add_len` to 36 (`IP + UDP + GTP-U`) so the original 14 outer
Ethernet bytes get *overwritten* by the new Ethernet header. The total grown
region is still 50 bytes (14 new Eth + 36 new headers), but conceptually the
original Eth is replaced rather than pushed deeper.

```rust
// Wrong:
let add_len = (ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + GTPU_HDR_LEN) as i32;

// Right:
let add_len = (IP_HDR_LEN + UDP_HDR_LEN + GTPU_HDR_LEN + GTPU_EXT_HDR_LEN) as i32;
// total header after adjust_head: ETH_HDR_LEN + add_len
```

The pointer-math model that helped: `adjust_head(-N)` grows the headroom by N
bytes — it does **not** push the existing packet contents further along by N.
The first N bytes of `data` are now garbage that you must overwrite.

---

## 3. `XDP_PASS` after encap is not enough — kernel routing fails on the constructed packet

**Symptom:** `Encapsulated: TEID=…` was logged on every reply, packet captures
on `upfedge0` showed `172.22.0.8.2152 > 172.22.0.23.2152` GTP-U packets… but
they never reached the gNB container.

**Root cause:** When XDP returns `XDP_PASS`, the kernel continues normal
processing on the interface the packet arrived on. The packet was reborn as a
GTP-U packet bound for `172.22.0.23` but was sitting on `upfedge0`'s ingress
queue. The kernel's routing decision for the new destination led nowhere
useful — the bridge sent it back out the wrong interface.

**Fix:** End `try_encap` with `bpf_redirect(IF_INDEX[0], 0)` where
`IF_INDEX[0]` is the gNB-side veth (`veth<hash>`). `bpf_redirect` to a veth
deposits the packet directly on the peer's RX queue — i.e., inside the gNB
container's `eth0`. No routing decision, no L2 lookup. Confirmed by
capturing inside the gNB container's net namespace:

```bash
GNB_PID=$(docker inspect -f '{{.State.Pid}}' nr_gnb)
sudo nsenter -t $GNB_PID -n tcpdump -i eth0 'udp port 2152'
# now shows the downlink GTP-U arriving
```

---

## 4. dst MAC swap on encap was wrong — it sent packets to upfedge1 instead of the gNB

**Symptom:** Even after fix #3, packets arrived at the gNB container but were
silently dropped at L2. `tcpdump -e` showed dst MAC = upfedge1's MAC, not the
gNB container's eth0 MAC.

**Root cause:** The reply packet from the internet arrived on `upfedge0` with
`dst MAC = upfedge1` (set by the static neighbor entry). The encap code did the
standard "swap src/dst" trick to build the outer Ethernet header. But the
swapped src/dst were both `upfedge1` — there is no meaningful src MAC for a
packet originating from the kernel via a route.

**Fix:** Hard-set dst MAC to the gNB's eth0 MAC, learned dynamically at startup
via `docker exec nr_gnb cat /sys/class/net/eth0/address` and pushed into
`GW_MAC[1]`. The src MAC is irrelevant (the gNB doesn't check it) — leave it as
whatever the reply had.

---

## 5. GTP-U downlink needs the PDU Session Container extension header

**Symptom:** Downlink GTP-U packets arrived at the gNB with the right TEID,
right dst MAC, right inner IP — and were *still* dropped without reaching the
UE. Meanwhile, uplink GTP-U from the UE always had `flags=0x34` (E bit set) with
an 8-byte option containing a PDU Session Container.

**Root cause:** 3GPP TS 38.415 makes the **PDU Session Container** extension
header *mandatory* on the N3 interface for 5G. The gNB rejects downlink GTP-U
without it (or at least UERANSIM does). Our encap was writing `flags=0x30` (no
extension), which is valid 4G GTP-U but not valid 5G.

**Fix:** Set `flags=0x34` and append an 8-byte option after the GTP-U header:

```
+--------+--------+--------+--------+
|    Seq Number   | N-PDU  | Next=  |
|       0x0000    | 0x00   | 0x85   |
+--------+--------+--------+--------+    GTP-U optional header (4B)
| ExtLen | PDU    | Spare  | Next=  |
| = 1    | Type=0 | / QFI  | 0x00   |
|        | (DL)   | = 1    |        |
+--------+--------+--------+--------+    PDU Session Container ext (4B)
```

`PDU Type = 0` indicates downlink (UL would be 1). `QFI = 1` is a placeholder —
in a real implementation this comes from the QER applied by the FAR.

After this, the gNB accepted the packets and forwarded them to the UE. End-to-end
ping started working.

---

## 6. Static neighbor + /32 route per UE — proxy_arp didn't work

**Symptom:** Reply packets from the internet arrived at the host as
`8.8.8.8 → 192.168.100.X`. The kernel needed to know where to send them.
`proxy_arp` on `upfedge1` was tried but never answered the (kernel's own)
ARP request.

**Root cause:** There's no peer on `upfedge1` to ARP for the UE — the UE lives
inside a gNB tunnel, not on a physical L2 segment.

**Fix:** Userspace installs a static `ip route … dev upfedge1` and `ip neigh …
lladdr <upfedge1's own MAC>` whenever a Session Establishment arrives. Any MAC
works for the neighbor entry — the packet will be intercepted on `upfedge0`'s
RX by XDP before any L2 logic runs. The neighbor entry only exists to satisfy
the kernel's ARP requirement so the packet actually leaves `upfedge1`.

A matching `ip route del` / `ip neigh del` runs on Session Deletion. This
removes the manual `ip route add` step from the operational workflow entirely
— the only thing the operator does is start `upf-edge` and the UE.

---

## 7. Dynamic everything — MAC, ifindex — because the lab environment is volatile

The Docker bridge's MAC and the gNB veth's name/ifindex change every time
containers are recreated. Hardcoding any of these turns "ping doesn't work"
into a long bisection.

The eBPF code now does zero hardcoding:

| Value | Source | When read |
|---|---|---|
| upfedge0 MAC | `/sys/class/net/upfedge0/address` | userspace boot |
| gNB MAC | `docker exec nr_gnb cat /sys/class/net/eth0/address` | userspace boot |
| N3 ifindex | `/sys/class/net/<--iface-n3>/ifindex` | userspace boot |
| upfedge1 ifindex | `/sys/class/net/upfedge1/ifindex` | userspace boot |
| UE IP, gNB IP, TEID | PFCP messages | per session |

All written into `GW_MAC`, `IF_INDEX`, and `SESSION_MAP` for XDP to read at packet time.

---

## 8. The single XDP-attach quirk: veth pairs and `SKB_MODE`

XDP attached to a veth in "driver mode" tends to silently not work in lab
setups. The current code uses `XdpFlags::SKB_MODE` (generic XDP) for both N3
and N6 attaches. Slightly slower than native XDP, but reliable across kernel
versions and on veth pairs.

---

## Useful pcap landmarks

When tcpdumping during debugging, these are the things you actually want to
see:

| What | Filter | Should look like |
|---|---|---|
| Uplink GTP-U from gNB | `udp port 2152 and src 172.22.0.23` | flags=0x34, opt 8B, TEID = our N3 allocation |
| Downlink GTP-U from UPF | `udp port 2152 and src 172.22.0.8` | flags=0x34, opt 8B, TEID = gNB's allocation (from Modification's OHC) |
| PFCP Session Modification | `udp port 8805 and greater 75` | msg_type=52, contains Update FAR (IE type 10) |
| Reply NAT'd back | `host 8.8.8.8 and icmp on eth0` | both directions; downlink should reach `upfedge1 Out` then `upfedge0 In` |
