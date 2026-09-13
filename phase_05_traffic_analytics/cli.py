"""
Phase 5: Terminal Visualizer for Traffic Analytics
Provides plain-text output displaying stateful flow tables, TCP states, Top Talkers, and Traffic Matrix.
"""

import time
import argparse
from typing import Optional

from phase_02_packet_capture_engine.capture_engine import PacketCaptureEngine
from phase_03_packet_parser.parser import PacketParser
from phase_05_traffic_analytics.analytics_engine import AnalyticsEngine


def format_bytes(bytes_val: float) -> str:
    if bytes_val < 1024:
        return f"{bytes_val:.1f} B"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.1f} KB"
    else:
        return f"{bytes_val / (1024 * 1024):.2f} MB"


def format_rate(bps: float) -> str:
    if bps < 1024:
        return f"{bps:.1f} B/s"
    elif bps < 1024 * 1024:
        return f"{bps / 1024:.1f} KB/s"
    else:
        return f"{bps / (1024 * 1024):.2f} MB/s"


def render_analytics_dashboard(engine: AnalyticsEngine, elapsed: float) -> str:
    """Render full stateful flows, Top Talkers, and Traffic Matrix in plain text."""
    snapshot = engine.get_snapshot()

    lines = []
    lines.append("=" * 95)
    lines.append("NetSleuth AI - Phase 5: Stateful Traffic Analytics Engine")
    lines.append(f"Elapsed Time: {elapsed:.1f}s | Active Flows: {snapshot.active_flow_count} | Closed Flows: {snapshot.closed_flow_count} | Total Volume: {format_bytes(snapshot.total_volume_bytes)}")
    lines.append("=" * 95)

    # 1. Top Talkers Table
    lines.append("[TOP TALKERS - BANDWIDTH CONSUMERS]")
    lines.append(f"  {'IP Address':<18} {'Bytes Sent':<14} {'Bytes Recv':<14} {'Total Volume':<14} {'Share'}")
    lines.append("  " + "-" * 72)
    if snapshot.top_talkers:
        for t in snapshot.top_talkers:
            lines.append(
                f"  {t.ip:<18} {format_bytes(t.bytes_sent):<14} {format_bytes(t.bytes_received):<14} {format_bytes(t.total_bytes):<14} {t.share_pct:.1f}%"
            )
    else:
        lines.append("  (No host traffic recorded yet)")
    lines.append("")

    # 2. Protocol Statistics Table
    lines.append("[PROTOCOL BANDWIDTH & BITRATES]")
    lines.append(f"  {'Protocol':<12} {'Packets':<10} {'Total Volume':<14} {'Bitrate':<14} {'Avg Pkt Size'}")
    lines.append("  " + "-" * 68)
    if snapshot.protocol_bandwidth:
        for pb in snapshot.protocol_bandwidth:
            lines.append(
                f"  {pb.protocol:<12} {pb.packet_count:<10} {format_bytes(pb.total_bytes):<14} {format_rate(pb.bps):<14} {pb.avg_packet_size:.1f} B"
            )
    else:
        lines.append("  (No protocol traffic recorded yet)")
    lines.append("")

    # 3. Traffic Matrix (Conversations)
    lines.append("[TRAFFIC MATRIX - CONVERSATIONS]")
    lines.append(f"  {'Source IP':<18} {'Dest IP':<18} {'Protocol':<10} {'Packets':<10} {'Total Volume'}")
    lines.append("  " + "-" * 72)
    if snapshot.traffic_matrix:
        for tm in snapshot.traffic_matrix:
            lines.append(
                f"  {tm.src_ip:<18} {tm.dst_ip:<18} {tm.primary_protocol:<10} {tm.packet_count:<10} {format_bytes(tm.total_bytes)}"
            )
    else:
        lines.append("  (No conversation pairs recorded yet)")
    lines.append("")

    # 4. Stateful 5-Tuple Active Flows & TCP State Machine
    lines.append("[STATEFUL 5-TUPLE ACTIVE FLOWS & TCP STATES]")
    lines.append(f"  {'Flow Key (5-Tuple)':<42} {'State':<14} {'Pkts (Fwd/Rev)':<16} {'Duration'}")
    lines.append("  " + "-" * 84)
    if snapshot.active_flows_sample:
        for f in snapshot.active_flows_sample:
            fkey = f"{f.protocol}:{f.src_ip}:{f.src_port}->{f.dst_ip}:{f.dst_port}"
            if len(fkey) > 41:
                fkey = fkey[:38] + "..."
            pkts_str = f"{f.packets_forward}/{f.packets_reverse} ({f.total_packets})"
            lines.append(
                f"  {fkey:<42} {f.state.value:<14} {pkts_str:<16} {f.duration_seconds:.1f}s"
            )
    else:
        lines.append("  (No active stateful flows)")

    lines.append("=" * 95)
    return "\n".join(lines)


def run_analytics_cli(
    interface: Optional[str] = None,
    bpf_filter: Optional[str] = None,
    simulation_mode: bool = False,
    duration: Optional[float] = None,
    packet_limit: Optional[int] = None,
    refresh_rate: float = 0.5,
    clear_screen: bool = True,
):
    """Run Traffic Analytics CLI displaying stateful flow tables and Top Talkers."""
    capture_engine = PacketCaptureEngine(
        interface=interface,
        bpf_filter=bpf_filter,
        simulation_mode=simulation_mode,
    )
    packet_parser = PacketParser(local_ips=capture_engine.local_ips)
    analytics_engine = AnalyticsEngine(local_ips=capture_engine.local_ips)

    def on_packet(pkt):
        parsed = packet_parser.parse(pkt)
        analytics_engine.process_packet(parsed)

    capture_engine.add_subscriber(on_packet)

    print("Starting NetSleuth AI Phase 5 Traffic Analytics Engine...")
    capture_engine.start(
        interface=interface,
        bpf_filter=bpf_filter,
        packet_limit=packet_limit,
        simulate_if_permission_denied=True,
    )

    start_time = time.time()
    try:
        while capture_engine.is_running:
            elapsed = time.time() - start_time
            dashboard_str = render_analytics_dashboard(analytics_engine, elapsed)

            if clear_screen:
                print("\033[2J\033[H" + dashboard_str, flush=True)
            else:
                print(dashboard_str, flush=True)

            time.sleep(refresh_rate)

            if duration and elapsed >= duration:
                break
            if packet_limit and capture_engine.total_packets >= packet_limit:
                break
    except KeyboardInterrupt:
        print("\nStopping analytics engine...")
    finally:
        capture_engine.stop()
        final_str = render_analytics_dashboard(analytics_engine, time.time() - start_time)
        print("\n" + final_str)
        print("Completed Phase 5 Traffic Analytics.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetSleuth AI - Phase 5 Traffic Analytics CLI")
    parser.add_argument("-i", "--interface", type=str, help="Network interface")
    parser.add_argument("-f", "--filter", type=str, help="BPF filter")
    parser.add_argument("-s", "--simulate", action="store_true", help="Force synthetic traffic generator")
    parser.add_argument("-d", "--duration", type=float, help="Run duration in seconds")
    parser.add_argument("-c", "--count", type=int, help="Maximum packet count")
    parser.add_argument("--no-clear", action="store_true", help="Do not clear screen between updates")
    args = parser.parse_args()

    run_analytics_cli(
        interface=args.interface,
        bpf_filter=args.filter,
        simulation_mode=args.simulate,
        duration=args.duration,
        packet_limit=args.count,
        clear_screen=not args.no_clear,
    )
