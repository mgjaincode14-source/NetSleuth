#!/usr/bin/env python3
"""
NetSleuth AI - Phase 2 Capture Engine Quick Runner
Executes packet capture engine and prints live statistics.
"""

import sys
import os

# Add root project directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from phase_02_packet_capture_engine.cli import run_cli
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetSleuth AI - Phase 2 Packet Sniffer")
    parser.add_argument("-i", "--interface", type=str, default=None, help="Interface name (e.g. wlp8s0, lo)")
    parser.add_argument("-f", "--filter", type=str, default=None, help="BPF filter string")
    parser.add_argument("-s", "--simulate", action="store_true", help="Force synthetic traffic generator")
    parser.add_argument("-d", "--duration", type=float, default=None, help="Run duration in seconds")
    parser.add_argument("-c", "--count", type=int, default=None, help="Maximum packet count")
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

