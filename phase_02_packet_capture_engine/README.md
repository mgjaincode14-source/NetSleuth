# Phase 2: Packet Capture Engine

Welcome to **Phase 2** of NetSleuth AI! In this phase, we build the core network packet sniffing engine using **Scapy** and **Python**, with full start/stop controls, real-time metrics, network interface discovery, and synthetic traffic generation.

---

## 📖 1. What You Learn in Phase 2

### 1.1 How Packet Sniffing Works
A network packet sniffer captures raw network frames as they pass through a physical or virtual Network Interface Card (NIC). 

- **Promiscuous Mode**: By default, a NIC only processes packets addressed to its own MAC address or broadcast packets. In *promiscuous mode*, the NIC passes **all** frames seen on the wire/air to the OS kernel, allowing the sniffer to capture traffic across the local network segment.
- **Raw Sockets (`AF_PACKET` in Linux)**: Under the hood, Scapy uses raw sockets (`socket(AF_PACKET, SOCK_RAW, ...)`). This allows reading packets at Layer 2 (Ethernet frames) or Layer 3 (IP packets) before standard OS network stack filtering.
- **Root / Privilege Requirements**: Opening raw sockets on Linux requires root (`sudo`) or `CAP_NET_RAW` / `CAP_NET_ADMIN` capabilities.
- **NetSleuth Fallback Architecture**: NetSleuth AI includes an integrated **Synthetic Traffic Simulator** so the entire platform can be developed, tested, and demonstrated without needing elevated root permissions.

---

### 1.2 Scapy Basics for Packet Capture
Scapy provides an asynchronous sniffer `AsyncSniffer`:

```python
from scapy.all import AsyncSniffer

def on_packet(pkt):
    print(f"Captured: {pkt.summary()}")

sniffer = AsyncSniffer(
    iface="wlp8s0",          # Network Interface
    filter="tcp port 80",    # BPF (Berkeley Packet Filter)
    prn=on_packet,           # Callback for each packet
    store=False,             # Avoid infinite RAM accumulation
    promisc=True             # Promiscuous mode
)

sniffer.start()   # Starts capturing in a background thread
# ... do work ...
sniffer.stop()    # Stops capture cleanly
```

---

### 1.3 Berkeley Packet Filter (BPF) Syntax
BPF filters are applied directly inside the Linux kernel for zero-copy high-performance packet filtering:

| Filter Expression | Matches |
|---|---|
| `tcp` | Only TCP packets |
| `udp` | Only UDP packets |
| `port 80` | Packets where either source or destination port is 80 (HTTP) |
| `src host 192.168.1.50` | Packets originating from 192.168.1.50 |
| `tcp and not port 22` | All TCP packets except SSH |
| `icmp` | Ping requests and replies |

---

## 🚀 2. Running Phase 2

### 2.1 View Available Network Interfaces
```bash
source ../venv/bin/activate
python interface_manager.py
```

### 2.2 Run the Real-Time Terminal Capture Dashboard
```bash
# Run with automatic interface detection or simulated traffic
python run_capture.py --simulate

# Or capture live traffic on loopback
python run_capture.py -i lo

# Or capture live traffic on Wi-Fi/Ethernet with a filter (requires sudo/CAP_NET_RAW for live raw sockets)
python run_capture.py -i wlp8s0 -f "tcp or udp"
```

### 2.3 Run Automated Unit Tests
```bash
pytest tests/ -v
```

---

## 🏗️ 3. Architecture of Phase 2

```
                               ┌─────────────────────────────┐
                               │     Network Interfaces      │
                               │   (wlp8s0, lo, enp7s0)      │
                               └──────────────┬──────────────┘
                                              │
                     ┌────────────────────────┴────────────────────────┐
                     ▼                                                 ▼
        ┌────────────────────────┐                        ┌────────────────────────┐
        │  Scapy AsyncSniffer    │                        │   TrafficSimulator     │
        │  (Live Raw Socket)     │                        │  (Synthetic Scenarios) │
        └────────────┬───────────┘                        └────────────┬───────────┘
                     │                                                 │
                     └────────────────────────┬────────────────────────┘
                                              │ Scapy Packet
                                              ▼
                               ┌─────────────────────────────┐
                               │    PacketCaptureEngine      │
                               │  - Ring Buffer (10k pkts)   │
                               │  - Sliding Window (PPS/BPS) │
                               │  - Protocol Counter         │
                               │  - Subscriber Callbacks     │
                               └──────────────┬──────────────┘
                                              │
                     ┌────────────────────────┴────────────────────────┐
                     ▼                                                 ▼
        ┌────────────────────────┐                        ┌────────────────────────┐
        │   Rich Terminal UI     │                        │   Downstream Phases    │
        │   (Live PPS & Stats)   │                        │   (Parser, AI, Rules)  │
        └────────────────────────┘                        └────────────────────────┘
```
