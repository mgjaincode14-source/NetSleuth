# Phase 3: Deep Packet Parser

Welcome to **Phase 3** of NetSleuth AI! In this phase, we transform raw network frames captured by the Phase 2 engine into structured, typed **ParsedPacket** objects containing Layer 2 through Layer 7 metadata, 5-tuple flow keys, TCP flag states, and payload previews.

---

## 📖 1. What You Learn in Phase 3

### 1.1 Packet Dissection Architecture
When a raw packet arrives, standard packet analyzers dissect it layer by layer:

```
┌────────────────────────────────────────────────────────────────────────┐
│ Raw Packet Data                                                        │
├────────────────────────────────────────────────────────────────────────┤
│ Layer 2: Ethernet Header   -> MAC Addresses (src_mac, dst_mac)         │
│ Layer 3: IPv4 / IPv6       -> IP Addresses (src_ip, dst_ip, ttl, proto) │
│ Layer 4: TCP / UDP         -> Ports, Sequence/Ack, TCP Flags           │
│ Layer 7: Application Data  -> DNS Query/Answer, HTTP Method/Host, ICMP │
└────────────────────────────────────────────────────────────────────────┘
```

---

### 1.2 5-Tuple Network Flow Keys
A **Flow Key** uniquely identifies a bidirectional or unidirectional communication stream between two network endpoints:
- `Source IP`
- `Source Port`
- `Destination IP`
- `Destination Port`
- `Protocol` (e.g. `TCP`, `UDP`, `ICMP`)

Example: `TCP:192.168.1.50:52341->140.82.121.3:443`

---

### 1.3 TCP Flags Inspection
TCP headers contain 8 control flags controlling connection establishment, data push, and teardown:

| Flag | Full Name | Purpose in Packet Parser |
|---|---|---|
| `SYN` | Synchronize | Connection request |
| `ACK` | Acknowledgment | Acknowledges received data |
| `FIN` | Finish | Graceful connection termination |
| `RST` | Reset | Abruptly closes connection |
| `PSH` | Push | Requests receiver to push data immediately |
| `URG` | Urgent | Priority payload data |

---

## 🚀 2. Running Phase 3

### 2.1 Run the Deep Packet Parser (Simulation or Live)
```bash
# Run deep packet parser in simulation mode
./venv/bin/python phase_03_packet_parser/run_parser.py --simulate -d 3.0 --no-clear

# Run deep packet parser on live real-time network traffic (requires root for live raw sockets)
sudo ./venv/bin/python phase_03_packet_parser/run_parser.py -i wlp8s0 -d 5.0
```

### 2.2 Run Automated Unit Tests
```bash
./venv/bin/pytest -v
```
