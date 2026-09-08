"""
Unit tests for Phase 4 Real-Time Dashboard REST APIs & WebSocket connection endpoints
"""

import pytest
from fastapi.testclient import TestClient
from phase_04_realtime_dashboard.backend.app.main import app

client = TestClient(app)


def test_list_interfaces_endpoint():
    res = client.get("/api/v1/interfaces")
    assert res.status_code == 200
    data = res.json()
    assert "interfaces" in data
    assert "default" in data
    assert isinstance(data["interfaces"], list)


def test_get_status_endpoint():
    res = client.get("/api/v1/status")
    assert res.status_code == 200
    data = res.json()
    assert "total_packets" in data
    assert "packets_per_second" in data
    assert "protocol_counts" in data


def test_start_stop_capture_endpoint():
    # Start simulation
    start_res = client.post("/api/v1/start", json={"simulation_mode": True})
    assert start_res.status_code == 200
    assert start_res.json()["status"] == "started"

    # Stop simulation
    stop_res = client.post("/api/v1/stop")
    assert stop_res.status_code == 200
    assert stop_res.json()["status"] == "stopped"


def test_websocket_connection():
    with client.websocket_connect("/ws/dashboard") as websocket:
        # Wait for stats or packet message
        data = websocket.receive_json()
        assert "type" in data
        assert data["type"] in ["stats", "packet"]
