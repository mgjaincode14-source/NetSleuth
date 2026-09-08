#!/usr/bin/env python3
"""
NetSleuth AI - Master Unified Runner
Run any phase of NetSleuth AI in live real-time mode or simulation mode.
"""

import sys
import os
import argparse

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))


def main():
    parser = argparse.ArgumentParser(description="NetSleuth AI - Master Unified Runner")
    parser.add_argument(
        "-p", "--phase", type=int, choices=[2, 3], default=3,
        help="Phase to execute (2: Packet Capture Engine, 3: Deep Packet Parser) [Default: 3]"
    )
    parser.add_argument("-i", "--interface", type=str, default=None, help="Network interface (e.g., wlp8s0, lo)")
    parser.add_argument("-f", "--filter", type=str, default=None, help="BPF filter string (e.g., 'tcp port 80')")
    parser.add_argument("-s", "--simulate", action="store_true", help="Force synthetic traffic generator mode")
    parser.add_argument("-d", "--duration", type=float, default=None, help="Run duration in seconds")
    parser.add_argument("-c", "--count", type=int, default=None, help="Maximum packet count to capture")
    parser.add_argument("--no-clear", action="store_true", help="Do not clear screen between terminal updates")
    parser.add_argument("--auto-fallback", action="store_true", help="Fallback to simulation if non-root permission fails")

    args = parser.parse_args()

    if args.phase == 2:
        from phase_02_packet_capture_engine.cli import run_cli
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
        from phase_03_packet_parser.cli import run_parser_cli
        run_parser_cli(
            interface=args.interface,
            bpf_filter=args.filter,
            simulation_mode=args.simulate,
            duration=args.duration,
            packet_limit=args.count,
            clear_screen=not args.no_clear,
        )


if __name__ == "__main__":
    main()
