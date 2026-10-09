# NetSleuth AI

**AI-Powered Real-Time Network Monitoring & Threat Detection Platform**

NetSleuth AI is a real-time network monitoring and cybersecurity intelligence platform. It continuously captures packets from your computer or local network, extracts deep protocol metadata, computes flow metrics, identifies cyber threats (such as Port Scans, SYN Floods, and DDoS attacks), and uses Agentic AI (LLMs) to explain anomalies and threats in plain English.

---

## Project Structure & Phases

The project is structured into modular phases:

| Phase Directory | Title | Core Focus |
|---|---|---|
| `phase_01_networking_fundamentals/` | **Networking Fundamentals & Setup** | Packets, IP/MAC, TCP/UDP, Ports, Headers & Environment Setup |
| `phase_02_packet_capture_engine/` | **Packet Capture Engine** | Scapy Async Sniffing, Directions, TCP Flags, Real-Time & Simulator |
| `phase_03_packet_parser/` | **Deep Packet Parser** | L2-L7 Extraction, 5-Tuple Flow Keys, DNS/HTTP/ICMP Metadata & Payload |
| `phase_04_realtime_dashboard/` | **Real-Time Web Dashboard** | FastAPI WebSockets + React Dashboard |
| `phase_05_traffic_analytics/` | **Traffic Analytics Engine** | Stateful 5-Tuple Flows, TCP State Machine, Bandwidth & Top Talkers |
| `phase_06_threat_detection/` | **Threat Detection Engine** | Rule-based detection (Port Scan, SYN Flood, Ping Flood) |
| `phase_07_machine_learning/` | **ML Anomaly Detection** | IsolationForest / XGBoost flow anomaly scoring (Planned) |
| `phase_08_ai_assistant/` | **AI Threat Assistant** | Groq + LangChain Agent with tool calling (Planned) |
| `phase_09_report_generation/` | **Security Report Generator** | Automated PDF / JSON export of security audits (Planned) |
| `phase_10_deployment/` | **Deployment & Docker** | Production Docker Compose orchestration (Planned) |

---

## How to Run

NetSleuth AI includes a universal orchestrator that automatically manages your virtual environment, elevates privileges if necessary for live packet capture, detects active interfaces, and launches the entire system simultaneously.

### Start the Platform

Run the following command from the root directory of the project:

```bash
python run.py
```

This single command will:
1. Automatically switch to the project's Python virtual environment.
2. Request `sudo` privileges if needed for live interface sniffing (on Linux/macOS).
3. Start the FastAPI backend and WebSocket manager.
4. Begin the asynchronous background packet capture (Live Mode or Simulation).
5. Serve the real-time React dashboard.

The dashboard will be available at: localhost

### Running Tests

To run the full test suite across all completed phases:

```bash
pytest
```
