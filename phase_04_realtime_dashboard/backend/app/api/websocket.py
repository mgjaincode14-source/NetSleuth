"""
Phase 4 Backend: WebSocket Endpoint
Handles incoming WebSocket client connections for real-time dashboard streaming.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from phase_04_realtime_dashboard.backend.app.ws_manager import ConnectionManager

router = APIRouter(tags=["websocket"])
ws_manager = ConnectionManager()


@router.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    """Real-Time WebSocket stream endpoint for live packets and metrics."""
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection open and receive optional ping messages from client
            _data = await websocket.receive_text()
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception:
        await ws_manager.disconnect(websocket)
