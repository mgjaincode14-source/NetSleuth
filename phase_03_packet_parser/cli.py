"""
Phase 3: Terminal Visualizer for Packet Parser
Displays detailed parsed packet headers, protocol metadata, TCP flags, and payload previews.
"""

import time
import argparse
from typing import Optional

from phase_02_packet_capture_engine.capture_engine import PacketCaptureEngine
from phase_03_packet_parser.parser import PacketParser


def render_parsed_packet_row(parsed) -> str:
    """Format a single parsed packet into plain text columns."""
    flow_str = f"{parsed.flow_key.src_ip}:{parsed.flow_key.src_port}->{parsed.flow_key.dst_ip}:{parsed.flow_key.dst_port}"
    if len(flow_str) > 38:
        flow_str = flow_str[:35] + "..."

    flags_str = parsed.l4.tcp_flags_summary if parsed.l4 and parsed.l4.tcp_flags_summary else "-"

    meta_desc = ""
    if parsed.dns:
        meta_desc = f"DNS {parsed.dns.qtype or 'Query'} '{parsed.dns.qname or ''}'"
    elif parsed.http:
        meta_desc = f"HTTP {parsed.http.method or ''} {parsed.http.path or ''}"
    elif parsed.icmp:
        meta_desc = f"ICMP {parsed.icmp.type_name}"
    elif parsed.arp:
        meta_desc = f"ARP {parsed.arp.operation} {parsed.arp.src_ip}->{parsed.arp.dst_ip}"
    elif parsed.payload_ascii:
        meta_desc = f"Payload: {parsed.payload_ascii[:30]}"
    else:
        meta_desc = f"Length: {parsed.length_bytes}B"

    if len(meta_desc) > 35:
        meta_desc = meta_desc[:32] + "..."

    alert_str = f"[{parsed.anomaly_tag}]" if parsed.anomaly_tag else "NORMAL"

    return (
        f"  {parsed.packet_id:<5} {parsed.direction:<9} {parsed.protocol:<8} "
        f"{flow_str:<39} {flags_str:<9} {meta_desc:<36} {alert_str}"
    )


def run_parser_cli(
    interface: Optional[str] = None,
    bpf_filter: Optional[str] = None,
    simulation_mode: bool = False,
    duration: Optional[float] = None,
    packet_limit: Optional[int] = None,
    refresh_rate: float = 0.5,
    clear_screen: bool = True,
):
    """Capture packets via Phase 2 capture engine and decode them in real-time using Phase 3 PacketParser."""
    engine = PacketCaptureEngine(
        interface=interface,
        bpf_filter=bpf_filter,
        simulation_mode=simulation_mode,
    )
    parser = PacketParser(local_ips=engine.local_ips)

    parsed_history = []

    def on_packet(pkt):
        parsed = parser.parse(pkt)
        parsed_history.append(parsed)
        if len(parsed_history) > 500:
            parsed_history.pop(0)

    engine.add_subscriber(on_packet)

    print("Starting NetSleuth AI Phase 3 Deep Packet Parser Engine...")
    engine.start(
        interface=interface,
        bpf_filter=bpf_filter,
        packet_limit=packet_limit,
        simulate_if_permission_denied=True,
    )

    start_time = time.time()
    try:
        while engine.is_running:
            lines = []
            lines.append("=" * 115)
            lines.append("NetSleuth AI - Phase 3: Deep Packet Parser")
            lines.append(f"Interface: {engine.interface or 'Auto-Detect'} | Mode: {'Simulation' if engine.simulation_mode else 'Live'}")
            lines.append("=" * 115)
            lines.append("[PARSED PACKET STREAM]")
            lines.append(
                f"  {'#':<5} {'Direction':<9} {'Proto':<8} {'Flow 5-Tuple':<39} {'TCP Flags':<9} {'Protocol Metadata / Payload':<36} {'Behavior Flag'}"
            )
            lines.append("  " + "-" * 110)

            recent_items = parsed_history[-10:] if parsed_history else []
            if recent_items:
                for item in recent_items:
                    lines.append(render_parsed_packet_row(item))
            else:
                lines.append("  Listening for packets and dissecting protocol layers...")

            lines.append("=" * 115)
            output_str = "\n".join(lines)

            if clear_screen:
                print("\033[2J\033[H" + output_str, flush=True)
            else:
                print(output_str, flush=True)

            time.sleep(refresh_rate)

            if duration and (time.time() - start_time) >= duration:
                break
            if packet_limit and engine.total_packets >= packet_limit:
                break
    except KeyboardInterrupt:
        print("\nStopping parser...")
    finally:
        engine.stop()
        print(f"\nCompleted Phase 3 Deep Packet Parsing. Total packets parsed: {len(parsed_history)}")


if __name__ == "__main__":
    cli_parser = argparse.ArgumentParser(description="NetSleuth AI - Phase 3 Packet Parser CLI")
    cli_parser.add_argument("-i", "--interface", type=str, help="Network interface")
    cli_parser.add_argument("-f", "--filter", type=str, help="BPF filter")
    cli_parser.add_argument("-s", "--simulate", action="store_true", help="Force synthetic traffic generator")
    cli_parser.add_argument("-d", "--duration", type=float, help="Run duration in seconds")
    cli_parser.add_argument("-c", "--count", type=int, help="Maximum packet count")
    cli_parser.add_argument("--no-clear", action="store_true", help="Do not clear screen between updates")
    args = cli_parser.parse_args()

    run_parser_cli(
        interface=args.interface,
        bpf_filter=args.filter,
        simulation_mode=args.simulate,
        duration=args.duration,
        packet_limit=args.count,
        clear_screen=not args.no_clear,
    )
