# NetSleuth AI 🔍📡

**AI-Powered Real-Time Network Monitoring & Threat Detection Platform**

NetSleuth AI is a real-time network monitoring and cybersecurity intelligence platform. It continuously captures packets from your computer or local network, extracts deep protocol metadata, computes flow metrics, identifies cyber threats (such as Port Scans, SYN Floods, and DDoS attacks), and uses Agentic AI (LLMs) to explain anomalies and threats in plain English.

---

## 🧭 Project Roadmap & Phase-Wise Structure

Each phase is self-contained with its own educational guide, code modules, and tests:

| Phase Directory | Title | Core Focus | Status |
|---|---|---|---|
| [`phase_01_networking_fundamentals/`](./phase_01_networking_fundamentals/) | **Networking Fundamentals & Setup** | Packets, IP/MAC, TCP/UDP, Ports, Headers & Environment Setup | ✅ Complete |
| [`phase_02_packet_capture_engine/`](./phase_02_packet_capture_engine/) | **Packet Capture Engine** | Scapy Async Sniffing, Interface Discovery, Start/Stop & Simulator | ✅ Complete |
| `phase_03_packet_parser/` | **Deep Packet Parser** | L2-L7 Extraction, TCP Flags, DNS/HTTP metadata, Pydantic Models | ⏳ Next |
| `phase_04_realtime_dashboard/` | **Real-Time Dashboard** | FastAPI WebSockets + React Tailwind Dashboard | ⏳ Planned |
| `phase_05_traffic_analytics/` | **Traffic Analytics** | Flow Reconstruction (5-Tuple), Bandwidth & Top Talkers | ⏳ Planned |
| `phase_06_threat_detection/` | **Threat Detection Engine** | Rule-based detection (Port Scan, SYN Flood, Ping Flood) | ⏳ Planned |
| `phase_07_machine_learning/` | **ML Anomaly Detection** | IsolationForest / XGBoost flow anomaly scoring | ⏳ Planned |
| `phase_08_ai_assistant/` | **AI Threat Assistant** | Groq + LangChain Agent with tool calling & plain-English advice | ⏳ Planned |
| `phase_09_report_generation/` | **Security Report Generator** | Automated PDF / JSON export of security audits | ⏳ Planned |
| `phase_10_deployment/` | **Deployment & Docker** | Production Docker Compose orchestration | ⏳ Planned |

---

## ⚡ Quick Start

### 1. Set Up Virtual Environment & Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r phase_01_networking_fundamentals/requirements.txt
```

### 2. Verify Environment
```bash
python phase_01_networking_fundamentals/test_environment.py
```

### 3. Run Phase 2 Packet Capture Engine
```bash
# Run real-time capture monitor (Simulated traffic or Live interface)
python phase_02_packet_capture_engine/run_capture.py --simulate

# Run automated tests
pytest phase_02_packet_capture_engine/tests/ -v
```
