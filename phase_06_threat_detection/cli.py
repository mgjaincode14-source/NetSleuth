"""
NetSleuth AI - Phase 6 Threat Detection CLI Dashboard
"""

import sys
import os
import time
import argparse
from typing import Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from phase_02_packet_capture_engine.capture_engine import PacketCaptureEngine
from phase_03_packet_parser.parser import PacketParser
from phase_06_threat_detection.detector import ThreatDetector
from phase_06_threat_detection.models import Severity


def clear_terminal():
    os.system("cls" if os.name == "nt" else "clear")


def run_detector_cli(
    interface: Optional[str] = None,
    bpf_filter: Optional[str] = None,
    simulation_mode: bool = False,
    duration: Optional[float] = None,
    packet_limit: Optional[int] = None,
    clear_screen: bool = True,
):
    """
    Main CLI entrypoint for Phase 6 Rule-Based Threat Detection Engine.
    """
    engine = PacketCaptureEngine(
        interface=interface,
        bpf_filter=bpf_filter,
        simulation_mode=simulation_mode,
    )
    parser = PacketParser()
    detector = ThreatDetector()

    engine.start()
    if not engine.is_running:
        print("[ERROR] Failed to start packet capture engine. Check permissions or interface.")
        return

    start_time = time.time()
    packet_count = 0

    def packet_callback(raw_pkt):
        nonlocal packet_count
        packet_count += 1
        parsed = parser.parse_packet(raw_pkt)
        detector.process_packet(parsed)

    engine.add_subscriber(packet_callback)

    print("================================================================================")
    print(" NetSleuth AI - Phase 6 Rule-Based Threat Detection Engine")
    print(f" Interface: {engine.interface} | Mode: {'Simulation' if engine.simulation_mode else 'Live Raw Socket'}")
    print("================================================================================")
    print("Press CTRL+C to stop.\n")

    try:
        while True:
            now = time.time()
            elapsed = max(0.1, now - start_time)

            if clear_screen:
                clear_terminal()

                pps = packet_count / elapsed
                summary = detector.get_threat_summary()
                sev_counts = summary["severity_counts"]

                print("================================================================================")
                print(" 🛡️ NetSleuth AI - Phase 6 Real-Time Threat Detection Dashboard")
                print("================================================================================")
                print(f" Interface   : {str(engine.interface):<12} | Mode        : {'Simulation' if engine.simulation_mode else 'Live Capture'}")
                print(f" Elapsed     : {elapsed:6.1f}s       | Packets     : {packet_count:<8} | PPS: {pps:6.1f}")
                print("--------------------------------------------------------------------------------")
                print(f" SEVERITY COUNTS =>  CRITICAL: {sev_counts['CRITICAL']} | HIGH: {sev_counts['HIGH']} | MEDIUM: {sev_counts['MEDIUM']} | LOW: {sev_counts['LOW']} | INFO: {sev_counts['INFO']}")
                print("================================================================================")
                print(" REAL-TIME SECURITY ALERTS LOG (Recent 8 Alerts)")
                print("--------------------------------------------------------------------------------")
                print(f" {'TIME':<8} | {'SEVERITY':<8} | {'RULE NAME':<30} | {'ATTACKER IP':<15} | {'TARGET'}")
                print("--------------------------------------------------------------------------------")

                recent_alerts = detector.get_alerts(limit=8)
                if not recent_alerts:
                    print(" [No threats detected yet. Monitoring active traffic stream...]")
                else:
                    for alert in reversed(recent_alerts):
                        t_str = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
                        target_str = f"{alert.dst_ip}:{alert.dst_port}" if alert.dst_port else alert.dst_ip
                        rule_name = alert.rule_name[:30]
                        print(f" {t_str:<8} | {alert.severity.name:<8} | {rule_name:<30} | {alert.src_ip:<15} | {target_str}")

                print("================================================================================")
                print(" TOP FLAGGED ATTACKER IPs")
                print("--------------------------------------------------------------------------------")
                top_ips = summary["top_attacker_ips"]
                if not top_ips:
                    print(" [No suspicious hosts identified]")
                else:
                    for ip, alert_cnt in top_ips:
                        print(f"  • Attacker IP: {ip:<16} - Total Alerts Triggered: {alert_cnt}")

                print("================================================================================")

            if duration and (now - start_time) >= duration:
                print(f"\n[INFO] Duration limit of {duration}s reached.")
                break

            if packet_limit and packet_count >= packet_limit:
                print(f"\n[INFO] Packet limit of {packet_limit} reached.")
                break

            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n[INFO] Stopping Phase 6 Threat Detection Engine...")
    finally:
        engine.remove_subscriber(packet_callback)
        engine.stop()

    summary = detector.get_threat_summary()
    print("\n================================================================================")
    print(" 📊 PHASE 6 THREAT DETECTION FINAL SUMMARY")
    print("================================================================================")
    print(f" Total Packets Processed : {packet_count}")
    print(f" Total Threat Alerts     : {summary['total_alerts']}")
    print(f" Severity Breakdown      : {summary['severity_counts']}")
    print("================================================================================")


def main():
    parser = argparse.ArgumentParser(description="NetSleuth AI - Phase 6 Threat Detector CLI")
    parser.add_argument("-i", "--interface", type=str, default=None, help="Network interface (e.g., wlp8s0, lo)")
    parser.add_argument("-f", "--filter", type=str, default=None, help="BPF Filter")
    parser.add_argument("-s", "--simulate", action="store_true", help="Force synthetic traffic generator")
    parser.add_argument("-d", "--duration", type=float, default=None, help="Duration in seconds")
    parser.add_argument("-c", "--count", type=int, default=None, help="Packet limit")
    parser.add_argument("--no-clear", action="store_true", help="Do not clear screen between updates")

    args = parser.parse_args()
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
