# Phase 6: Rule-Based Threat Detection Engine

Welcome to **Phase 6** of NetSleuth AI! This module implements a stateful, sliding-window **Rule-Based Threat Detection Engine** (Intrusion Detection System / IDS) designed to analyze network traffic in real time and trigger alerts for known attack patterns, anomalous traffic spikes, and host scanning behavior.

---

## 🎯 Key Features & Threat Rules

### 1. Port Scanning Detection (`RULE_PORT_SCAN`)
- **Signature**: Monitors unique destination ports targeted by a single source IP within a sliding time window (default 10s).
- **Threshold**: Triggers when unique ports scanned $\ge 10$.
- **Severity**: `MEDIUM` ($\ge 10$ ports) / `HIGH` ($\ge 20$ ports).

### 2. TCP SYN Flood Attack (`RULE_SYN_FLOOD`)
- **Signature**: Detects unacknowledged TCP `SYN` packets emitted at high rates from a source IP.
- **Threshold**: Triggers when SYN rate $\ge 20$ SYNs/sec.
- **Severity**: `HIGH` / `CRITICAL`.

### 3. ICMP / Ping Flood (`RULE_ICMP_FLOOD`)
- **Signature**: Detects volumetric ICMP Echo Request bursts.
- **Threshold**: Triggers when ICMP rate $\ge 20$ packets in sliding window.
- **Severity**: `HIGH`.

### 4. Brute-Force Connection Attempts (`RULE_BRUTE_FORCE`)
- **Signature**: Identifies rapid repeated connection attempts targeted at high-value service ports (`22` SSH, `21` FTP, `23` Telnet, `3389` RDP, `445` SMB).
- **Threshold**: Triggers when connection attempts $\ge 8$.
- **Severity**: `HIGH`.

### 5. Stealth TCP Scans (`RULE_STEALTH_SCAN`)
- **Signature**: Flags TCP flag combinations commonly used to bypass naive stateful firewalls:
  - **NULL Scan**: No TCP flags set.
  - **XMAS Scan**: `FIN`, `PSH`, and `URG` flags set simultaneously.
  - **FIN Scan**: Only `FIN` flag set.
- **Severity**: `MEDIUM`.

### 6. DNS Anomalies & Tunneling (`RULE_DNS_ANOMALY`)
- **Signature**:
  - **DNS Tunneling**: Domain queries exceeding 60 characters (indicative of encoded exfiltrated data).
  - **Query Bursts**: High query rate (>15 queries/sec).
- **Severity**: `MEDIUM` / `HIGH`.

---

## 🚀 How to Run

### Command-Line Interface (CLI)

Run in simulation mode (synthetic traffic generator):
```bash
./venv/bin/python run.py -p 6 -s
```

Run in live packet capture mode (requires sudo / raw socket permissions):
```bash
sudo ./venv/bin/python run.py -p 6 -i wlp8s0
```

Run with automatic fallback to simulation if non-root:
```bash
./venv/bin/python phase_06_threat_detection/run_detector.py -s -d 15
```

---

## 🧪 Unit Tests

Run the test suite for Phase 6:
```bash
./venv/bin/pytest phase_06_threat_detection/tests/ -v
```
