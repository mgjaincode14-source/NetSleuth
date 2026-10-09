#!/usr/bin/env python3
"""
NetSleuth AI - Universal Master Runner & Pipeline Orchestrator
Zero-config, single-command launcher across Linux, Windows, and macOS.
Auto-discovers active network interfaces (Wi-Fi / Ethernet), launches the linked
in-memory pipeline (Phases 2-6), and opens the real-time web dashboard.
"""

import sys
import os
import time
import platform
import threading
import argparse

# ---------------------------------------------------------------------------
# Auto-switch to project virtual environment (Linux, Windows, macOS)
# Allows running 'python run.py' directly without manual 'source venv/bin/activate'
# ---------------------------------------------------------------------------
def _ensure_venv():
    in_venv = (
        (hasattr(sys, "base_prefix") and sys.prefix != sys.base_prefix)
        or bool(os.environ.get("VIRTUAL_ENV"))
    )
    if in_venv:
        return

    project_root = os.path.abspath(os.path.dirname(__file__))
    candidates = [
        os.path.join(project_root, "venv", "bin", "python"),
        os.path.join(project_root, "venv", "bin", "python3"),
        os.path.join(project_root, "venv", "Scripts", "python.exe"),
        os.path.join(project_root, ".venv", "bin", "python"),
        os.path.join(project_root, ".venv", "Scripts", "python.exe"),
    ]

    for venv_py in candidates:
        if os.path.isfile(venv_py) and os.path.abspath(sys.executable) != os.path.abspath(venv_py):
            try:
                os.execv(venv_py, [venv_py] + sys.argv)
            except OSError:
                pass


_ensure_venv()

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))


def get_interface_badge(iface_name: str, is_loopback: bool) -> str:
    """Classify network interface into a human-friendly badge."""
    lower = iface_name.lower()
    if is_loopback or lower in ["lo", "loopback"]:
        return "Loopback / Localhost"
    if any(prefix in lower for prefix in ["wl", "wifi", "wlan", "wi-fi", "airport"]):
        return "Wi-Fi"
    if any(prefix in lower for prefix in ["eth", "enp", "eno", "ethernet"]):
        return "Ethernet"
    return "Network Adapter"


def auto_open_browser(url: str, delay: float = 1.5):
    """Launch user default browser in a non-blocking daemon thread."""
    def _open():
        time.sleep(delay)
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:
            pass

    threading.Thread(target=_open, daemon=True).start()


def check_raw_socket_permission() -> bool:
    """Test whether current process has permission to open raw sockets."""
    if platform.system() == "Linux":
        try:
            import socket
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            s.close()
            return True
        except Exception:
            return False
    elif platform.system() == "Darwin":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else True
    return True


def run_unified_platform(
    host: str = "0.0.0.0",
    port: int = 8000,
    forced_interface: str = None,
    simulation_mode: bool = False,
    open_browser: bool = True,
    no_build: bool = False,
):
    """
    Launches the entire NetSleuth AI system in a single command:
    - Auto-detects active network interface (Wi-Fi vs Ethernet)
    - Links Phase 2 (Capture), Phase 3 (Parser), Phase 5 (Analytics), Phase 6 (Threats)
    - Starts Phase 4 FastAPI WebSocket & REST server
    - Opens dashboard in default browser
    """
    # 1. Privilege validation & auto-elevation for live packet sniffing
    has_raw_perm = check_raw_socket_permission()
    if not has_raw_perm and not simulation_mode:
        if sys.stdin.isatty():
            print("\n" + "=" * 82)
            print(" ⚠️  [PRIVILEGE NOTICE] Real-time live packet sniffing requires root privileges on Linux.")
            print(" Elevating permissions via 'sudo' to capture LIVE packets from your network...")
            print(" (To run in simulation mode without sudo, pass: python run.py --simulate)")
            print("=" * 82 + "\n")
            try:
                os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
            except Exception as e:
                print(f"[ELEVATION NOTICE] Could not elevate with sudo ({e}). Falling back to simulation mode.\n")
                simulation_mode = True
        else:
            print("\n[NOTICE] Raw socket capture denied. Falling back to Simulation Mode.\n")
            simulation_mode = True

    from phase_02_packet_capture_engine.interface_manager import InterfaceManager
    from phase_04_realtime_dashboard.run_dashboard import build_frontend_if_needed
    from phase_04_realtime_dashboard.backend.app.api.rest import get_global_engine

    # 2. Interface Auto-Discovery
    if forced_interface:
        target_iface_name = forced_interface
        iface_type = "Manually Specified"
        ip_display = "Custom"
    else:
        default_iface = InterfaceManager.get_default_interface()
        if default_iface:
            target_iface_name = default_iface.name
            iface_type = get_interface_badge(default_iface.name, default_iface.is_loopback)
            ip_display = ", ".join(default_iface.ipv4_addresses) if default_iface.ipv4_addresses else "No IPv4"
        else:
            target_iface_name = "lo"
            iface_type = "Loopback"
            ip_display = "127.0.0.1"

    # Configure global engine prior to server start
    engine = get_global_engine()
    engine.interface = target_iface_name
    engine.simulation_mode = simulation_mode

    # 3. Print Banner
    is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else True
    os_name = f"{platform.system()} {platform.release()} ({platform.machine()})"
    dashboard_url = f"http://localhost:{port}"

    print("=" * 82)
    print(" 📡 NetSleuth AI — AI-Powered Real-Time Network & Threat Intelligence Platform")
    print("=" * 82)
    print(f"  Operating System:    {os_name}")
    print(f"  Active Interface:    {target_iface_name} [{iface_type}] (IP: {ip_display})")
    print(f"  Privilege Level:     {'Administrator / Root' if is_root else 'Standard User'}")
    print(f"  Capture Mode:        {'Simulated Traffic' if simulation_mode else 'Live Network Sniffing'}")
    print(f"  Active Pipeline:     Phase 2 (Capture) ➔ Phase 3 (Parser) ➔ Phase 5 (Analytics)")
    print(f"                       ➔ Phase 6 (Threat Detection) ➔ Phase 4 (Web Dashboard)")
    print(f"  Web Dashboard URL:   {dashboard_url}")
    print(f"  REST API Docs:       {dashboard_url}/docs")
    print(f"  WebSocket Stream:    ws://localhost:{port}/ws/dashboard")
    print("=" * 82)

    # 4. Frontend verification / build
    if not no_build:
        try:
            build_frontend_if_needed()
        except Exception as e:
            print(f"[BUILD NOTICE] Frontend pre-build skipped: {e}")

    # 5. Open browser automatically
    if open_browser:
        print("--> Auto-launching web dashboard in your default browser...\n")
        auto_open_browser(dashboard_url, delay=1.2)

    # 6. Run FastAPI Server (Engine automatically starts inside app lifespan)
    import uvicorn
    uvicorn.run(
        "phase_04_realtime_dashboard.backend.app.main:app",
        host=host,
        port=port,
        reload=False,
    )


def main():
    parser = argparse.ArgumentParser(
        description="NetSleuth AI - Master Unified Runner & Single-Command Launcher",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-p", "--phase", type=int, choices=[0, 2, 3, 4, 5, 6], default=0,
        help=(
            "Phase to execute:\n"
            "  0: UNIFIED (Default - Runs ALL phases linked together with Web Dashboard)\n"
            "  2: Capture Engine standalone CLI\n"
            "  3: Deep Packet Parser standalone CLI\n"
            "  4: Web Dashboard Server\n"
            "  5: Traffic Analytics standalone CLI\n"
            "  6: Threat Detection standalone CLI"
        )
    )
    parser.add_argument("-i", "--interface", type=str, default=None, help="Network interface (auto-detected if omitted)")
    parser.add_argument("-f", "--filter", type=str, default=None, help="BPF filter expression (e.g. 'tcp port 80')")
    parser.add_argument("-s", "--simulate", action="store_true", help="Force synthetic traffic generator mode")
    parser.add_argument("-d", "--duration", type=float, default=None, help="Run duration in seconds")
    parser.add_argument("-c", "--count", type=int, default=None, help="Maximum packet count to capture")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Dashboard host to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Dashboard port to bind (default: 8000)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open the web browser")
    parser.add_argument("--no-build", action="store_true", help="Skip automatic frontend build check")
    parser.add_argument("--no-clear", action="store_true", help="Do not clear screen between terminal updates")
    parser.add_argument("--auto-fallback", action="store_true", help="Fallback to simulation if non-root permission fails")

    args = parser.parse_args()

    # Default (Phase 0) launches the full unified platform linking all phases
    if args.phase == 0 or args.phase == 4:
        run_unified_platform(
            host=args.host,
            port=args.port,
            forced_interface=args.interface,
            simulation_mode=args.simulate,
            open_browser=not args.no_browser,
            no_build=args.no_build,
        )
    elif args.phase == 2:
        from phase_02_packet_capture_engine.capture_cli import run_cli
        run_cli(
            interface=args.interface,
            bpf_filter=args.filter,
            simulation_mode=args.simulate,
            duration=args.duration,
            packet_limit=args.count,
            clear_screen=not args.no_clear,
            fallback_on_permission_error=args.auto_fallback,
        )
    elif args.phase == 3:
        from phase_03_packet_parser.parser_cli import run_parser_cli
        run_parser_cli(
            interface=args.interface,
            bpf_filter=args.filter,
            simulation_mode=args.simulate,
            duration=args.duration,
            packet_limit=args.count,
            clear_screen=not args.no_clear,
        )
    elif args.phase == 5:
        from phase_05_traffic_analytics.cli import run_analytics_cli
        run_analytics_cli(
            interface=args.interface,
            bpf_filter=args.filter,
            simulation_mode=args.simulate,
            duration=args.duration,
            packet_limit=args.count,
            clear_screen=not args.no_clear,
        )
    elif args.phase == 6:
        from phase_06_threat_detection.cli import run_detector_cli
        run_detector_cli(
            interface=args.interface,
            bpf_filter=args.filter,
            simulation_mode=args.simulate,
            duration=args.duration,
            packet_limit=args.count,
            clear_screen=not args.no_clear,
        )


if __name__ == "__main__":
    main()
