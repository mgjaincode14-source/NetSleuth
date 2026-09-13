# Phase 5: Traffic Analytics Engine

Welcome to **Phase 5** of NetSleuth AI! In this phase, we build the stateful network flow reconstruction engine, host-level bandwidth calculator, Top Talker aggregator, and TCP connection state machine.

---

## 📖 1. What You Learn in Phase 5

### 1.1 Stateful 5-Tuple Flow Reconstruction
Network flows group related packets sharing a 5-tuple key (`src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`). 

```
                                ┌──────────────────────────────┐
                                │   Client (192.168.1.50:54321)│
                                └──────────────┬───────────────┘
                                               │
               1. Forward SYN                  │  2. Reverse SYN-ACK
         ─────────────────────────────►        │ ◄────────────────────────────
                                               │
                                ┌──────────────┴───────────────┐
                                │   Server (140.82.121.3:443)  │
                                └──────────────────────────────┘
```

The Phase 5 `FlowTracker` maps reverse packets (`dst_ip:dst_port -> src_ip:src_port`) back to the original forward flow object to compute bidirectional metrics (forward vs. reverse packets and byte volumes).

---

### 1.2 TCP Connection State Machine
The `FlowTracker` implements a finite state machine for TCP connections:
- `SYN_SENT`: Client sends connection request (`SYN`).
- `SYN_ACK_REC`: Server responds with `SYN-ACK`.
- `ESTABLISHED`: Client acknowledges (`ACK`) and data transfer begins.
- `FIN_WAIT`: Either endpoint sends `FIN` to initiate teardown.
- `RESET`: Connection abruptly reset (`RST`).

---

### 1.3 Top Talkers & Traffic Matrix
- **Top Talkers**: Ranks local and remote IP hosts by total transmitted and received byte volume.
- **Traffic Matrix**: Tracks conversation pairs between specific source and destination IPs to identify key network relationships.

---

## 🚀 2. Running Phase 5

### 2.1 Run the Traffic Analytics Terminal Visualizer
```bash
# Run analytics in simulation mode
./venv/bin/python phase_05_traffic_analytics/run_analytics.py --simulate -d 3.0 --no-clear

# Run analytics on live network socket (requires root for raw socket sniffing)
sudo ./venv/bin/python phase_05_traffic_analytics/run_analytics.py -i wlp8s0 -d 5.0
```

### 2.2 Run Automated Unit Tests
```bash
./venv/bin/pytest phase_05_traffic_analytics/tests/ -v
```
