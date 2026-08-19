"""
Phase 2: Terminal UI & Capture Monitor
Provides comprehensive plain-text output displaying live metrics, protocol breakdown, and recent packet stream.
"""

import os
import sys
import time
import argparse
from typing import Optional

from phase_02_packet_capture_engine.capture_engine import PacketCaptureEngine


def format_bytes(bytes_val: float) -> str:
    """Format bytes per second into human-readable B/s, KB/s, or MB/s."""
    if bytes_val < 1024:
        return f"{bytes_val:.1f} B/s"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.1f} KB/s"
    else:
        return f"{bytes_val / (1024 * 1024):.2f} MB/s"


def format_total_bytes(bytes_val: int) -> str:
    """Format total volume."""
    if bytes_val < 1024:
        return f"{bytes_val} B"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.1f} KB"
    else:
        return f"{bytes_val / (1024 * 1024):.2f} MB"


def render_plain_dashboard(engine: PacketCaptureEngine, max_packets_to_show: int = 7) -> str:
    """Render full metrics, protocol distribution, and live packet stream in clean plain text."""
    stats = engine.get_stats()
    status_str = "PAUSED" if stats.is_paused else "RUNNING"
    mode_str = "Simulation" if stats.simulation_mode else "Live"

    lines = []
    lines.append("=" * 85)
    lines.append("NetSleuth AI - Phase 2: Packet Capture Engine")
    lines.append(f"Interface: {stats.active_interface or 'Auto-Detect'} | Mode: {mode_str} | Filter: {stats.bpf_filter or 'None'}")
    lines.append("=" * 85)

    # 1. Traffic Metrics Section
    lines.append("[TRAFFIC METRICS]")
    lines.append(
        f"  Status:         {status_str:<12}  Elapsed Time: {stats.elapsed_seconds:.1f}s\n"
        f"  Total Packets:  {stats.total_packets:<12}  Packet Rate:  {stats.packets_per_second:.1f} pkts/s\n"
        f"  Total Volume:   {format_total_bytes(stats.total_bytes):<12}  Bandwidth:    {format_bytes(stats.bytes_per_second)}"
    )
    lines.append("")

    # 2. Protocol Breakdown Section
    lines.append("[PROTOCOL BREAKDOWN]")
    lines.append(f"  {'Protocol':<12} {'Count':<10} {'Share'}")
    lines.append("  " + "-" * 32)
    total_p = max(1, stats.total_packets)
    if stats.protocol_counts:
        for proto, count in sorted(stats.protocol_counts.items(), key=lambda x: x[1], reverse=True):
            pct = (count / total_p) * 100
            lines.append(f"  {proto:<12} {count:<10} {pct:.1f}%")
    else:
        lines.append("  (No packets captured yet)")
    lines.append("")

    # 3. Live Packet Stream Section
    lines.append("[LIVE PACKET STREAM - RECENT PACKETS]")
    lines.append(f"  {'#':<4} {'Layer / Summary':<66} {'Length'}")
    lines.append("  " + "-" * 78)

    buffered = engine.get_buffered_packets(limit=max_packets_to_show)
    if buffered:
        start_idx = max(1, stats.total_packets - len(buffered) + 1)
        for idx, pkt in enumerate(buffered[-max_packets_to_show:]):
            summary = pkt.summary() if hasattr(pkt, "summary") else str(pkt)
            if len(summary) > 64:
                summary = summary[:61] + "..."
            lines.append(f"  {start_idx + idx:<4} {summary:<66} {len(pkt)} B")
    else:
        lines.append("  -    Listening for packets...                                           -")

    lines.append("=" * 85)
    return "\n".join(lines)


def run_cli(
    interface: Optional[str] = None,
    bpf_filter: Optional[str] = None,
    simulation_mode: bool = False,
    duration: Optional[float] = None,
    packet_limit: Optional[int] = None,
    refresh_rate: float = 0.5,
    clear_screen: bool = True,
):
    """Run real-time capture monitor in the terminal."""
    engine = PacketCaptureEngine(
        interface=interface,
        bpf_filter=bpf_filter,
        simulation_mode=simulation_mode,
    )

    print("Starting NetSleuth AI Capture Engine...")
    engine.start(
        interface=interface,
        bpf_filter=bpf_filter,
        packet_limit=packet_limit,
        simulate_if_permission_denied=True,
    )

    start_time = time.time()
    try:
        while engine.is_running:
            dashboard = render_plain_dashboard(engine)
            if clear_screen and sys.stdout.isatty():
                # ANSI escape code to clear terminal screen and reset cursor position without extra symbols
                print("\033[2J\033[H" + dashboard, flush=True)
            else:
                print(dashboard, flush=True)

            time.sleep(refresh_rate)

            if duration and (time.time() - start_time) >= duration:
                break
            if packet_limit and engine.total_packets >= packet_limit:
                break
    except KeyboardInterrupt:
        print("\nStopping capture...")
    finally:
        engine.stop()
        final_dashboard = render_plain_dashboard(engine)
        print("\n" + final_dashboard)
        print("Capture complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetSleuth AI - Phase 2 Packet Capture CLI")
    parser.add_argument("-i", "--interface", type=str, help="Network interface (e.g. wlp8s0, lo)")
    parser.add_argument("-f", "--filter", type=str, help="BPF filter string (e.g. 'tcp port 80')")
    parser.add_argument("-s", "--simulate", action="store_true", help="Run in simulation mode")
    parser.add_argument("-d", "--duration", type=float, help="Duration to capture in seconds")
    parser.add_argument("-c", "--count", type=int, help="Maximum packet count to capture")
    parser.add_argument("--no-clear", action="store_true", help="Do not clear screen between updates")
    args = parser.parse_args()

    run_cli(
        interface=args.interface,
        bpf_filter=args.filter,
        simulation_mode=args.simulate,
        duration=args.duration,
        packet_limit=args.count,
        clear_screen=not args.no_clear,
    )



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetSleuth AI - Phase 2 Packet Capture CLI")
    parser.add_argument("-i", "--interface", type=str, help="Network interface (e.g. wlp8s0, lo)")
    parser.add_argument("-f", "--filter", type=str, help="BPF filter string (e.g. 'tcp port 80')")
    parser.add_argument("-s", "--simulate", action="store_true", help="Run in simulation mode")
    parser.add_argument("-d", "--duration", type=float, help="Duration to capture in seconds")
    parser.add_argument("-c", "--count", type=int, help="Maximum packet count to capture")
    args = parser.parse_args()

    run_cli(
        interface=args.interface,
        bpf_filter=args.filter,
        simulation_mode=args.simulate,
        duration=args.duration,
        packet_limit=args.count,
    )
