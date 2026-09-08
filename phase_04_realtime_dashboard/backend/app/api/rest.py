"""
Phase 4 Backend: REST API Endpoints
Provides interface discovery, capture start/stop controls, and status monitoring.
"""

from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from phase_02_packet_capture_engine.interface_manager import InterfaceManager
from phase_02_packet_capture_engine.capture_engine import PacketCaptureEngine


router = APIRouter(prefix="/api/v1", tags=["capture"])

# Global engine instance for dashboard backend
global_engine: Optional[PacketCaptureEngine] = None


def get_global_engine() -> PacketCaptureEngine:
    global global_engine
    if global_engine is None:
        global_engine = PacketCaptureEngine()
    return global_engine


class StartCaptureRequest(BaseModel):
    interface: Optional[str] = None
    bpf_filter: Optional[str] = None
    simulation_mode: bool = False
    auto_fallback: bool = True


@router.get("/interfaces")
def list_interfaces() -> Dict[str, Any]:
    """Retrieve list of available network interfaces."""
    interfaces = InterfaceManager.get_all_interfaces()
    default_iface = InterfaceManager.get_default_interface()
    return {
        "interfaces": [iface.model_dump() for iface in interfaces],
        "default": default_iface.name if default_iface else "lo",
    }


@router.get("/status")
def get_status() -> Dict[str, Any]:
    """Get current capture engine statistics."""
    engine = get_global_engine()
    stats = engine.get_stats()
    return stats.model_dump()


@router.post("/start")
def start_capture(req: StartCaptureRequest) -> Dict[str, Any]:
    """Start or restart packet capture engine."""
    engine = get_global_engine()
    if engine.is_running:
        engine.stop()

    engine.simulation_mode = req.simulation_mode
    try:
        engine.start(
            interface=req.interface,
            bpf_filter=req.bpf_filter,
            simulate_if_permission_denied=req.auto_fallback,
        )
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"status": "started", "stats": engine.get_stats().model_dump()}


@router.post("/stop")
def stop_capture() -> Dict[str, Any]:
    """Stop active packet capture engine."""
    engine = get_global_engine()
    engine.stop()
    return {"status": "stopped", "stats": engine.get_stats().model_dump()}


@router.post("/pause")
def pause_capture() -> Dict[str, Any]:
    """Pause packet capture."""
    engine = get_global_engine()
    engine.pause()
    return {"status": "paused"}


@router.post("/resume")
def resume_capture() -> Dict[str, Any]:
    """Resume packet capture."""
    engine = get_global_engine()
    engine.resume()
    return {"status": "resumed"}


@router.post("/clear")
def clear_buffer() -> Dict[str, Any]:
    """Clear packet buffer and counters."""
    engine = get_global_engine()
    engine.clear_buffer()
    return {"status": "cleared"}
