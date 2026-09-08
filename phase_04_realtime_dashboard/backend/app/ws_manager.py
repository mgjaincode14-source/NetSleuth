"""
Phase 4 Backend: WebSocket Connection Manager
Broadcasts real-time capture metrics and parsed packet payloads to connected frontend clients.
"""

import asyncio
import json
import time
from typing import List, Set, Dict, Any
from fastapi import WebSocket

from phase_02_packet_capture_engine.capture_engine import PacketCaptureEngine, CaptureStats
from phase_03_packet_parser.parser import PacketParser
from phase_03_packet_parser.models import ParsedPacket


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
        msg_text = json.dumps(data)

        async with self._lock:
            for connection in self.active_connections:
                try:
                    await connection.send_text(msg_text)
                except Exception:
                    dead_sockets.add(connection)

            for dead in dead_sockets:
                self.active_connections.remove(dead)


class DashboardBroadcastService:
    """Subscribes to PacketCaptureEngine & PacketParser and pushes real-time updates over WebSockets."""

    def __init__(self, ws_manager: ConnectionManager):
        self.ws_manager = ws_manager
        self.engine: Optional[PacketCaptureEngine] = None
        self.parser: Optional[PacketParser] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._broadcast_task: Optional[asyncio.Task] = None
        self.is_running = False

    def attach_engine(self, engine: PacketCaptureEngine):
        """Attach Phase 2 capture engine and Phase 3 packet parser."""
        self.engine = engine
        self.parser = PacketParser(local_ips=engine.local_ips)

        # Register subscriber callback
        self.engine.add_subscriber(self._on_packet_received)

    def _on_packet_received(self, pkt):
        """Thread-safe callback invoked whenever a packet is captured."""
        if not self.parser or not self.is_running or not self._loop:
            return

        try:
            parsed: ParsedPacket = self.parser.parse(pkt)
            packet_payload = {
                "type": "packet",
                "data": parsed.model_dump()
            }
            # Schedule broadcast on asyncio event loop
            asyncio.run_coroutine_threadsafe(
                self.ws_manager.broadcast_json(packet_payload),
                self._loop
            )
        except Exception:
            pass

    async def start_broadcasting(self):
        """Start periodic metrics broadcast loop (2 updates per second)."""
        self._loop = asyncio.get_running_loop()
        self.is_running = True

        while self.is_running:
            if self.engine:
                stats: CaptureStats = self.engine.get_stats()
                stats_payload = {
                    "type": "stats",
                    "data": stats.model_dump()
                }
                await self.ws_manager.broadcast_json(stats_payload)

            await asyncio.sleep(0.5)

    def stop_broadcasting(self):
        self.is_running = False
