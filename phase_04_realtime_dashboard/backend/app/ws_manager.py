"""
Phase 4 Backend: WebSocket Connection Manager
Broadcasts real-time capture metrics and parsed packet payloads to connected frontend clients.
"""

import asyncio
import json
import time
from typing import List, Set, Dict, Any, Optional
from fastapi import WebSocket

from phase_02_packet_capture_engine.capture_engine import PacketCaptureEngine, CaptureStats
from phase_03_packet_parser.parser import PacketParser
from phase_03_packet_parser.models import ParsedPacket
from phase_05_traffic_analytics.analytics_engine import AnalyticsEngine
from phase_06_threat_detection.detector import ThreatDetector


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts live network data."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)

    async def broadcast_json(self, data: Dict[str, Any]):
        """Send JSON message to all connected clients."""
        if not self.active_connections:
            return

        dead_sockets = set()
        msg_text = json.dumps(data, default=str)

        async with self._lock:
            for connection in self.active_connections:
                try:
                    await connection.send_text(msg_text)
                except Exception:
                    dead_sockets.add(connection)

            for dead in dead_sockets:
                self.active_connections.remove(dead)


class DashboardBroadcastService:
    """Subscribes to PacketCaptureEngine, PacketParser, AnalyticsEngine, and ThreatDetector to push real-time updates over WebSockets."""

    def __init__(self, ws_manager: ConnectionManager):
        self.ws_manager = ws_manager
        self.engine: Optional[PacketCaptureEngine] = None
        self.parser: Optional[PacketParser] = None
        self.analytics_engine: Optional[AnalyticsEngine] = None
        self.threat_detector: Optional[ThreatDetector] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self.is_running = False

    def attach_engine(self, engine: PacketCaptureEngine):
        """Attach Phase 2 capture engine, Phase 3 packet parser, Phase 5 analytics, and Phase 6 threat detector."""
        self.engine = engine
        self.parser = PacketParser(local_ips=engine.local_ips)
        self.analytics_engine = AnalyticsEngine(local_ips=engine.local_ips)
        self.threat_detector = ThreatDetector()
        self.engine.add_subscriber(self._on_packet_received)

    def _on_packet_received(self, pkt):
        """Thread-safe callback invoked whenever a packet is captured."""
        if not self.parser or not self._loop or not self._loop.is_running():
            return

        try:
            parsed: ParsedPacket = self.parser.parse(pkt)

            # Phase 5: Stateful Flow Tracking & Bandwidth
            if self.analytics_engine:
                self.analytics_engine.process_packet(parsed)

            # Phase 6: Rule-Based Threat Detection
            new_alerts = []
            if self.threat_detector:
                new_alerts = self.threat_detector.process_packet(parsed)

            if not self._loop.is_running():
                return

            packet_payload = {
                "type": "packet",
                "data": parsed.model_dump(mode="json")
            }
            # Schedule packet broadcast on asyncio event loop
            try:
                asyncio.run_coroutine_threadsafe(
                    self.ws_manager.broadcast_json(packet_payload),
                    self._loop
                )
            except RuntimeError:
                pass

            # Broadcast any newly generated threat alerts immediately
            for alert in new_alerts:
                alert_payload = {
                    "type": "alert",
                    "data": alert.model_dump(mode="json")
                }
                try:
                    asyncio.run_coroutine_threadsafe(
                        self.ws_manager.broadcast_json(alert_payload),
                        self._loop
                    )
                except RuntimeError:
                    pass
        except Exception as err:
            print(f"[WS BROADCAST ERROR] {err}")

    async def start_broadcasting(self):
        """Start periodic metrics broadcast loop (2 updates per second)."""
        self._loop = asyncio.get_running_loop()
        self.is_running = True

        while self.is_running:
            if self.engine:
                stats: CaptureStats = self.engine.get_stats()
                stats_payload = {
                    "type": "stats",
                    "data": stats.model_dump(mode="json")
                }
                await self.ws_manager.broadcast_json(stats_payload)

            if self.analytics_engine:
                try:
                    snapshot = self.analytics_engine.get_snapshot()
                    analytics_payload = {
                        "type": "analytics",
                        "data": snapshot.model_dump(mode="json")
                    }
                    await self.ws_manager.broadcast_json(analytics_payload)
                except Exception:
                    pass

            await asyncio.sleep(0.5)

    def stop_broadcasting(self):
        self.is_running = False


_global_broadcast_service: Optional[DashboardBroadcastService] = None


def get_broadcast_service() -> Optional[DashboardBroadcastService]:
    """Retrieve global broadcast service instance."""
    return _global_broadcast_service


def set_broadcast_service(service: DashboardBroadcastService):
    """Register global broadcast service instance."""
    global _global_broadcast_service
    _global_broadcast_service = service

