"""
Phase 4 Backend: Main FastAPI Server Application
Sets up CORS, REST routes, WebSocket broadcasting, and static file serving.
"""

import os
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from phase_04_realtime_dashboard.backend.app.api.rest import router as rest_router, get_global_engine
from phase_04_realtime_dashboard.backend.app.api.websocket import router as ws_router, ws_manager
from phase_04_realtime_dashboard.backend.app.ws_manager import DashboardBroadcastService


broadcast_service = DashboardBroadcastService(ws_manager)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for startup and shutdown background tasks."""
    engine = get_global_engine()
    broadcast_service.attach_engine(engine)

    # Start background stats broadcasting task
    broadcast_task = asyncio.create_task(broadcast_service.start_broadcasting())

    yield

    # Clean shutdown
    broadcast_service.stop_broadcasting()
    broadcast_task.cancel()
    if engine.is_running:
        engine.stop()


app = FastAPI(
    title="NetSleuth AI - Real-Time Dashboard API",
    description="Backend API & WebSocket Server for NetSleuth AI Real-Time Network Monitoring Dashboard",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for local dev servers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(rest_router)
app.include_router(ws_router)

# Static files for frontend build
frontend_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../frontend/dist"))
if os.path.exists(frontend_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        file_path = os.path.join(frontend_dist, full_path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(frontend_dist, "index.html"))
