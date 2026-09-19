"""
NetSleuth AI - Stateful Threat Detector Engine
"""

import time
from collections import defaultdict, deque
from typing import List, Dict, Any, Optional, Set, Tuple

from .models import Alert, Severity, ThreatRule
from .rules import (
    PortScanRule,
    SYNFloodRule,
    ICMPFloodRule,
    BruteForceRule,
    StealthScanRule,
    DNSAnomalyRule,
)


class ThreatDetector:
    """
    Main real-time stateful engine for Rule-Based Threat Detection.
    Maintains rolling sliding windows per source IP and evaluates incoming network
    packets against threat signatures and heuristic anomaly detection rules.
    """

    def __init__(
        self,
        window_size_sec: float = 10.0,
        custom_rules: Optional[List[ThreatRule]] = None,
    ):
        self.window_size_sec = window_size_sec
        self.rules: List[ThreatRule] = custom_rules or [
            PortScanRule(),
            SYNFloodRule(),
            ICMPFloodRule(),
            BruteForceRule(),
            StealthScanRule(),
            DNSAnomalyRule(),
        ]

        # Per IP event tracking: src_ip -> deque of (timestamp, packet)
        self._ip_events: Dict[str, deque] = defaultdict(deque)

        # Cooldown tracker: (rule_id, src_ip) -> float last_alert_time
        self._cooldowns: Dict[Tuple[str, str], float] = {}

        # Alert history store
        self.alerts: List[Alert] = []

        # Processed stats
        self.total_packets_inspected: int = 0

    def _normalize_packet(self, packet: Any) -> Dict[str, Any]:
        """Convert a ParsedPacket object or dict into a normalized dictionary."""
        if isinstance(packet, dict):
            return packet

        src_ip = None
        dst_ip = None
        dst_port = None
        src_port = None
        protocol = getattr(packet, "protocol", "UNKNOWN")
        tcp_flags = None
        dns_query = None

        if hasattr(packet, "flow_key") and packet.flow_key:
            src_ip = getattr(packet.flow_key, "src_ip", None)
            dst_ip = getattr(packet.flow_key, "dst_ip", None)
            dst_port = getattr(packet.flow_key, "dst_port", None)
            src_port = getattr(packet.flow_key, "src_port", None)

        if hasattr(packet, "l3") and packet.l3:
            src_ip = src_ip or getattr(packet.l3, "src_ip", None)
            dst_ip = dst_ip or getattr(packet.l3, "dst_ip", None)

        if hasattr(packet, "l4") and packet.l4:
            dst_port = dst_port if dst_port is not None else getattr(packet.l4, "dst_port", None)
            src_port = src_port if src_port is not None else getattr(packet.l4, "src_port", None)
            tcp_flags = getattr(packet.l4, "tcp_flags", None)

        if hasattr(packet, "dns") and packet.dns:
            dns_query = getattr(packet.dns, "query", None)

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "src_port": src_port,
            "protocol": protocol,
            "tcp_flags": tcp_flags,
            "dns_query": dns_query,
            "payload_summary": getattr(packet, "payload_ascii", None),
        }

    def process_packet(self, packet: Any) -> List[Alert]:
        """
        Process a single packet through the threat detection engine.
        Updates sliding windows, evaluates rules, enforces cooldowns,
        and returns any newly generated Alert objects.
        """
        packet = self._normalize_packet(packet)
        self.total_packets_inspected += 1
        now = time.time()
        src_ip = packet.get("src_ip")

        if src_ip:
            self._ip_events[src_ip].append((now, packet))

        self._prune_expired_events(now)
        state = self._build_state_for_ip(src_ip, now)

        new_alerts: List[Alert] = []

        for rule in self.rules:
            # Check cooldown first
            cooldown_key = (rule.rule_id, src_ip or "0.0.0.0")
            last_alert_time = self._cooldowns.get(cooldown_key, 0.0)

            if (now - last_alert_time) < rule.cooldown_seconds:
                continue

            alert = rule.evaluate(packet, state)
            if alert:
                self._cooldowns[cooldown_key] = now
                self.alerts.append(alert)
                new_alerts.append(alert)

        return new_alerts

    def _prune_expired_events(self, current_time: float) -> None:
        """Removes packet events older than window_size_sec."""
        cutoff = current_time - self.window_size_sec
        empty_ips = []

        for ip, events in self._ip_events.items():
            while events and events[0][0] < cutoff:
                events.popleft()
            if not events:
                empty_ips.append(ip)

        for ip in empty_ips:
            del self._ip_events[ip]

    def _build_state_for_ip(self, src_ip: Optional[str], current_time: float) -> Dict[str, Any]:
        """
        Calculates window metrics for the given source IP.
        """
        if not src_ip or src_ip not in self._ip_events:
            return {"window_size_sec": self.window_size_sec, "ip_windows": {}}

        events = self._ip_events[src_ip]

        distinct_dst_ports: Set[int] = set()
        syn_count = 0
        icmp_count = 0
        dns_count = 0
        sensitive_attempts: Dict[int, int] = defaultdict(int)

        for ts, pkt in events:
            dst_port = pkt.get("dst_port")
            if dst_port is not None:
                distinct_dst_ports.add(dst_port)
                sensitive_attempts[dst_port] += 1

            protocol = pkt.get("protocol", "").upper()

            # TCP flags SYN check
            if protocol == "TCP":
                tcp_flags = pkt.get("tcp_flags", {})
                if isinstance(tcp_flags, dict):
                    if tcp_flags.get("SYN", False) and not tcp_flags.get("ACK", False):
                        syn_count += 1
                elif isinstance(tcp_flags, str):
                    if "S" in tcp_flags and "A" not in tcp_flags:
                        syn_count += 1

            elif protocol == "ICMP":
                icmp_count += 1

            elif protocol == "DNS" or dst_port == 53 or pkt.get("src_port") == 53:
                dns_count += 1

        ip_window_data = {
            "distinct_dst_ports": distinct_dst_ports,
            "syn_count": syn_count,
            "icmp_count": icmp_count,
            "dns_count": dns_count,
            "sensitive_attempts": sensitive_attempts,
            "packet_count": len(events),
        }

        return {
            "window_size_sec": self.window_size_sec,
            "ip_windows": {src_ip: ip_window_data},
        }

    def get_alerts(
        self,
        min_severity: Optional[Severity] = None,
        limit: Optional[int] = None,
    ) -> List[Alert]:
        """Retrieve stored alerts with optional severity filtering and limit."""
        filtered = self.alerts
        if min_severity is not None:
            filtered = [a for a in filtered if a.severity >= min_severity]

        if limit:
            return filtered[-limit:]
        return list(filtered)

    def get_threat_summary(self) -> Dict[str, Any]:
        """
        Get aggregated threat metrics summary.
        """
        counts_by_severity = {s.name: 0 for s in Severity}
        ip_alert_counts: Dict[str, int] = defaultdict(int)

        for alert in self.alerts:
            counts_by_severity[alert.severity.name] += 1
            ip_alert_counts[alert.src_ip] += 1

        top_attacker_ips = sorted(
            ip_alert_counts.items(), key=lambda x: x[1], reverse=True
        )[:5]

        return {
            "total_packets_inspected": self.total_packets_inspected,
            "total_alerts": len(self.alerts),
            "severity_counts": counts_by_severity,
            "top_attacker_ips": top_attacker_ips,
        }

    def reset(self) -> None:
        """Reset internal state, alerts, and counters."""
        self._ip_events.clear()
        self._cooldowns.clear()
        self.alerts.clear()
        self.total_packets_inspected = 0
