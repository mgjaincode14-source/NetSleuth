# Phase 4: Real-Time Web Dashboard

Welcome to **Phase 4** of NetSleuth AI! In this phase, we build a real-time web monitoring application featuring a **FastAPI WebSocket Streaming Server**, **REST APIs**, and a **React + Vite Frontend** designed with the **Breeze – Vibrant and Serious Combos** theme.

---

## 🎨 Design Theme ("Breeze – Vibrant and Serious")

The user interface balances a serious, crisp light background (`#f4f5f7` & `#ffffff`) with vibrant infographic color highlights:
- **Teal (`#00c292`)**: Primary branding, active status pulse, total packet metric card.
- **Pink (`#e83e8c`)**: Security alerts, anomaly flags (`POSSIBLE_SYN_SCAN`), threat counts.
- **Purple (`#7367f0`)**: Protocol distribution Doughnut chart, TCP flag details.
- **Amber (`#ff9f43`)**: Bandwidth gauges, throughput warnings.
- **Green (`#10b981`)**: Real-time Packets-Per-Second (PPS) history chart.

---

## 🚀 Running Phase 4 Dashboard

### 1. Build Frontend & Launch Unified Dashboard
```bash
# Build React frontend & launch FastAPI server on http://localhost:8000
./venv/bin/python phase_04_realtime_dashboard/run_dashboard.py
```

### 2. Run in Live Real-Time Socket Mode (with sudo)
```bash
# Run dashboard with live raw socket packet capture
sudo ./venv/bin/python phase_04_realtime_dashboard/run_dashboard.py
```

### 3. Run Automated Unit Tests
```bash
./venv/bin/pytest phase_04_realtime_dashboard/backend/tests/ -v
```
