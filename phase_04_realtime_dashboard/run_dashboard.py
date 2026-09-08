#!/usr/bin/env python3
"""
NetSleuth AI - Phase 4 Real-Time Web Dashboard Runner
Launches FastAPI backend server & WebSocket engine for the Breeze-themed React Dashboard.
"""

import sys
import os
import subprocess
import uvicorn
import argparse

# Add root project directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def build_frontend_if_needed():
    """Check and build frontend production assets if dist doesn't exist."""
    frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "frontend"))
    dist_dir = os.path.join(frontend_dir, "dist")
    node_modules = os.path.join(frontend_dir, "node_modules")

    if not os.path.exists(dist_dir):
        print("--> Building Phase 4 React Frontend (Breeze Theme)...")
        if not os.path.exists(node_modules):
            print("--> Installing frontend npm dependencies...")
            subprocess.run(["npm", "install"], cwd=frontend_dir, check=True)

        subprocess.run(["npm", "run", "build"], cwd=frontend_dir, check=True)
        print("--> Frontend build complete!\n")


def main():
    parser = argparse.ArgumentParser(description="NetSleuth AI - Phase 4 Real-Time Dashboard Server")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    parser.add_argument("--no-build", action="store_true", help="Skip automatic frontend build step")
    args = parser.parse_args()

    if not args.no_build:
        try:
            build_frontend_if_needed()
        except Exception as e:
            print(f"Note: Frontend build step failed ({e}). Proceeding with API server.")

    print("=" * 80)
    print(" 📡 NetSleuth AI - Phase 4 Real-Time Network Monitoring Dashboard")
    print(" Theme: Breeze - Vibrant and Serious Color Combinations")
    print("=" * 80)
    print(f" Web Dashboard URL:   http://localhost:{args.port}")
    print(f" WebSocket Stream:    ws://localhost:{args.port}/ws/dashboard")
    print(f" REST API Docs:       http://localhost:{args.port}/docs")
    print("=" * 80 + "\n")

    uvicorn.run(
        "phase_04_realtime_dashboard.backend.app.main:app",
        host=args.host,
        port=args.port,
        reload=False,
    )


if __name__ == "__main__":
    main()
