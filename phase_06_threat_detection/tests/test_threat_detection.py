"""
Unit tests for Phase 6 Rule-Based Threat Detection Engine
"""

import time
import pytest
from phase_06_threat_detection.models import Severity, Alert
from phase_06_threat_detection.detector import ThreatDetector
from phase_06_threat_detection.rules import (
    PortScanRule,
    SYNFloodRule,
    ICMPFloodRule,
    BruteForceRule,
    StealthScanRule,
    DNSAnomalyRule,
)


def test_port_scan_rule():
    detector = ThreatDetector(window_size_sec=5.0, custom_rules=[PortScanRule(port_threshold=5)])
    attacker_ip = "192.168.1.100"

    # Send packets to 4 distinct ports -> no alert yet
    for port in range(1001, 1005):
        pkt = {"src_ip": attacker_ip, "dst_ip": "10.0.0.1", "dst_port": port, "protocol": "TCP"}
        alerts = detector.process_packet(pkt)
        assert len(alerts) == 0

    # 5th distinct port -> triggers Port Scan Alert
    pkt_trigger = {"src_ip": attacker_ip, "dst_ip": "10.0.0.1", "dst_port": 1005, "protocol": "TCP"}
    alerts = detector.process_packet(pkt_trigger)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "RULE_PORT_SCAN"
    assert alert.src_ip == attacker_ip
    assert alert.severity in (Severity.MEDIUM, Severity.HIGH)


def test_syn_flood_rule():
    detector = ThreatDetector(window_size_sec=5.0, custom_rules=[SYNFloodRule(syn_threshold=5)])
    attacker_ip = "10.10.10.50"

    # Send 5 SYN packets
    alerts = []
    for i in range(5):
        pkt = {
            "src_ip": attacker_ip,
            "dst_ip": "10.0.0.2",
            "dst_port": 80,
            "protocol": "TCP",
            "tcp_flags": {"SYN": True, "ACK": False},
        }
        alerts.extend(detector.process_packet(pkt))

    assert len(alerts) >= 1
    alert = alerts[0]
    assert alert.rule_id == "RULE_SYN_FLOOD"
    assert alert.severity in (Severity.HIGH, Severity.CRITICAL)


def test_icmp_flood_rule():
    detector = ThreatDetector(window_size_sec=5.0, custom_rules=[ICMPFloodRule(icmp_threshold=5)])
    attacker_ip = "172.16.0.44"

    alerts = []
    for _ in range(5):
        pkt = {"src_ip": attacker_ip, "dst_ip": "10.0.0.1", "protocol": "ICMP"}
        alerts.extend(detector.process_packet(pkt))

    assert len(alerts) >= 1
    alert = alerts[0]
    assert alert.rule_id == "RULE_ICMP_FLOOD"
    assert alert.severity == Severity.HIGH


def test_brute_force_rule():
    detector = ThreatDetector(window_size_sec=5.0, custom_rules=[BruteForceRule(attempt_threshold=3)])
    attacker_ip = "192.168.1.88"

    alerts = []
    for _ in range(3):
        pkt = {"src_ip": attacker_ip, "dst_ip": "10.0.0.10", "dst_port": 22, "protocol": "TCP"}
        alerts.extend(detector.process_packet(pkt))

    assert len(alerts) >= 1
    alert = alerts[0]
    assert alert.rule_id == "RULE_BRUTE_FORCE"
    assert alert.details["target_service"] == "SSH"


def test_stealth_scan_rule():
    detector = ThreatDetector(window_size_sec=5.0, custom_rules=[StealthScanRule()])
    attacker_ip = "10.0.0.99"

    # NULL scan
    null_pkt = {
        "src_ip": attacker_ip,
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "protocol": "TCP",
        "tcp_flags": {"SYN": False, "ACK": False, "FIN": False, "PSH": False, "RST": False, "URG": False},
    }
    alerts = detector.process_packet(null_pkt)
    assert len(alerts) == 1
    assert "NULL Scan" in alerts[0].details["scan_type"]

    # XMAS scan
    xmas_pkt = {
        "src_ip": attacker_ip,
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "protocol": "TCP",
        "tcp_flags": {"FIN": True, "PSH": True, "URG": True},
    }
    # Wait for cooldown to expire or use different IP
    xmas_pkt["src_ip"] = "10.0.0.100"
    alerts = detector.process_packet(xmas_pkt)
    assert len(alerts) == 1
    assert "XMAS Scan" in alerts[0].details["scan_type"]


def test_dns_tunneling_rule():
    detector = ThreatDetector(window_size_sec=5.0, custom_rules=[DNSAnomalyRule()])
    attacker_ip = "192.168.1.12"

    # Exfiltrated payload long query > 60 chars
    long_domain = "a" * 65 + ".malicious-exfiltration-domain.com"
    dns_pkt = {
        "src_ip": attacker_ip,
        "dst_ip": "8.8.8.8",
        "dst_port": 53,
        "protocol": "DNS",
        "dns_query": long_domain,
    }
    alerts = detector.process_packet(dns_pkt)
    assert len(alerts) == 1
    assert alerts[0].rule_name == "Possible DNS Tunneling Attempt"
    assert alerts[0].severity == Severity.HIGH


def test_detector_summary_and_reset():
    detector = ThreatDetector(window_size_sec=5.0)

    pkt = {
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "protocol": "TCP",
        "tcp_flags": {"FIN": True, "PSH": True, "URG": True},
    }
    detector.process_packet(pkt)

    summary = detector.get_threat_summary()
    assert summary["total_packets_inspected"] == 1
    assert summary["total_alerts"] == 1
    assert ("10.0.0.5", 1) in summary["top_attacker_ips"]

    detector.reset()
    assert len(detector.alerts) == 0
    assert detector.total_packets_inspected == 0
