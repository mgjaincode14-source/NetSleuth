"""
NetSleuth AI - Rule Definitions for Threat Detection Engine
"""

import time
from typing import Dict, Any, Optional
from .models import ThreatRule, Alert, Severity


class PortScanRule(ThreatRule):
    """
    Detects vertical or horizontal port scanning behavior when a single source IP
    targets multiple distinct destination ports within a short time window.
    """

    rule_id = "RULE_PORT_SCAN"
    rule_name = "Port Scanning Activity Detected"
    default_severity = Severity.HIGH
    cooldown_seconds = 10.0

    def __init__(self, port_threshold: int = 10):
        self.port_threshold = port_threshold

    def evaluate(self, packet: Dict[str, Any], state: Dict[str, Any]) -> Optional[Alert]:
        src_ip = packet.get("src_ip")
        dst_port = packet.get("dst_port")
        if not src_ip or dst_port is None:
            return None

        # State contains sliding window distinct ports set for src_ip
        src_state = state.get("ip_windows", {}).get(src_ip, {})
        distinct_ports = src_state.get("distinct_dst_ports", set())

        count = len(distinct_ports)
        if count >= self.port_threshold:
            severity = Severity.HIGH if count >= 20 else Severity.MEDIUM
            dst_ip = packet.get("dst_ip", "0.0.0.0")
            return Alert(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=severity,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=packet.get("protocol", "TCP"),
                details={
                    "distinct_ports_scanned": count,
                    "target_sample_port": dst_port,
                    "window_sec": state.get("window_size_sec", 10),
                },
                recommendation=f"Block source IP {src_ip} at firewall or enforce strict rate limiting.",
            )
        return None


class SYNFloodRule(ThreatRule):
    """
    Detects SYN Flood DoS/DDoS attacks where a source IP transmits high rates
    of TCP SYN packets without establishing connections.
    """

    rule_id = "RULE_SYN_FLOOD"
    rule_name = "Possible TCP SYN Flood Attack"
    default_severity = Severity.CRITICAL
    cooldown_seconds = 5.0

    def __init__(self, syn_threshold: int = 20):
        self.syn_threshold = syn_threshold

    def evaluate(self, packet: Dict[str, Any], state: Dict[str, Any]) -> Optional[Alert]:
        protocol = packet.get("protocol", "").upper()
        if protocol != "TCP":
            return None

        tcp_flags = packet.get("tcp_flags", {})
        # Support dict format or string format for flags
        is_syn = False
        if isinstance(tcp_flags, dict):
            is_syn = tcp_flags.get("SYN", False) and not tcp_flags.get("ACK", False)
        elif isinstance(tcp_flags, str):
            is_syn = "S" in tcp_flags and "A" not in tcp_flags

        if not is_syn:
            return None

        src_ip = packet.get("src_ip")
        if not src_ip:
            return None

        src_state = state.get("ip_windows", {}).get(src_ip, {})
        syn_count = src_state.get("syn_count", 0)

        if syn_count >= self.syn_threshold:
            severity = Severity.CRITICAL if syn_count >= 40 else Severity.HIGH
            return Alert(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=severity,
                src_ip=src_ip,
                dst_ip=packet.get("dst_ip", "0.0.0.0"),
                dst_port=packet.get("dst_port"),
                protocol="TCP",
                details={
                    "syn_rate_in_window": syn_count,
                    "window_sec": state.get("window_size_sec", 10),
                },
                recommendation=f"Enable TCP SYN cookies on host and filter traffic from {src_ip}.",
            )
        return None


class ICMPFloodRule(ThreatRule):
    """
    Detects ICMP / Ping Flood attacks characterized by rapid ICMP Echo Request bursts.
    """

    rule_id = "RULE_ICMP_FLOOD"
    rule_name = "ICMP Ping Flood Attack Detected"
    default_severity = Severity.HIGH
    cooldown_seconds = 5.0

    def __init__(self, icmp_threshold: int = 20):
        self.icmp_threshold = icmp_threshold

    def evaluate(self, packet: Dict[str, Any], state: Dict[str, Any]) -> Optional[Alert]:
        protocol = packet.get("protocol", "").upper()
        if protocol != "ICMP":
            return None

        src_ip = packet.get("src_ip")
        if not src_ip:
            return None

        src_state = state.get("ip_windows", {}).get(src_ip, {})
        icmp_count = src_state.get("icmp_count", 0)

        if icmp_count >= self.icmp_threshold:
            return Alert(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.HIGH,
                src_ip=src_ip,
                dst_ip=packet.get("dst_ip", "0.0.0.0"),
                dst_port=None,
                protocol="ICMP",
                details={
                    "icmp_packets_in_window": icmp_count,
                    "window_sec": state.get("window_size_sec", 10),
                },
                recommendation=f"Drop ICMP Echo requests from {src_ip} or restrict ICMP rate limit.",
            )
        return None


class BruteForceRule(ThreatRule):
    """
    Detects high-frequency authentication/connection attempts to sensitive ports
    (22 SSH, 21 FTP, 23 Telnet, 3389 RDP, 445 SMB).
    """

    rule_id = "RULE_BRUTE_FORCE"
    rule_name = "Brute-Force Connection Attempts"
    default_severity = Severity.HIGH
    cooldown_seconds = 10.0

    SENSITIVE_PORTS = {21, 22, 23, 445, 3389, 8080}

    def __init__(self, attempt_threshold: int = 8):
        self.attempt_threshold = attempt_threshold

    def evaluate(self, packet: Dict[str, Any], state: Dict[str, Any]) -> Optional[Alert]:
        dst_port = packet.get("dst_port")
        if dst_port not in self.SENSITIVE_PORTS:
            return None

        src_ip = packet.get("src_ip")
        if not src_ip:
            return None

        src_state = state.get("ip_windows", {}).get(src_ip, {})
        sensitive_attempts = src_state.get("sensitive_attempts", {}).get(dst_port, 0)

        if sensitive_attempts >= self.attempt_threshold:
            service_names = {21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP", 8080: "HTTP-Alt"}
            service = service_names.get(dst_port, f"Port {dst_port}")
            return Alert(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.HIGH,
                src_ip=src_ip,
                dst_ip=packet.get("dst_ip", "0.0.0.0"),
                dst_port=dst_port,
                protocol=packet.get("protocol", "TCP"),
                details={
                    "target_service": service,
                    "attempts": sensitive_attempts,
                    "window_sec": state.get("window_size_sec", 10),
                },
                recommendation=f"Block {src_ip} using fail2ban or firewall for brute-forcing {service}.",
            )
        return None


class StealthScanRule(ThreatRule):
    """
    Detects TCP evasion / stealth scan packets:
    - NULL Scan (no flags set)
    - XMAS Scan (FIN, PSH, URG flags set)
    - FIN Scan (only FIN set)
    """

    rule_id = "RULE_STEALTH_SCAN"
    rule_name = "TCP Stealth Scan Detected (NULL/XMAS/FIN)"
    default_severity = Severity.MEDIUM
    cooldown_seconds = 5.0

    def evaluate(self, packet: Dict[str, Any], state: Dict[str, Any]) -> Optional[Alert]:
        protocol = packet.get("protocol", "").upper()
        if protocol != "TCP":
            return None

        tcp_flags = packet.get("tcp_flags", {})
        scan_type = None

        if isinstance(tcp_flags, dict):
            fin = tcp_flags.get("FIN", False)
            syn = tcp_flags.get("SYN", False)
            rst = tcp_flags.get("RST", False)
            psh = tcp_flags.get("PSH", False)
            ack = tcp_flags.get("ACK", False)
            urg = tcp_flags.get("URG", False)

            if not any([fin, syn, rst, psh, ack, urg]):
                scan_type = "NULL Scan (No Flags Set)"
            elif fin and psh and urg:
                scan_type = "XMAS Scan (FIN+PSH+URG Flags Set)"
            elif fin and not any([syn, rst, psh, ack, urg]):
                scan_type = "FIN Scan (FIN-Only Flag Set)"
        elif isinstance(tcp_flags, str):
            flags_str = tcp_flags.upper()
            if flags_str in ("", "0", "NONE"):
                scan_type = "NULL Scan (No Flags Set)"
            elif "F" in flags_str and "P" in flags_str and "U" in flags_str:
                scan_type = "XMAS Scan (FIN+PSH+URG Flags Set)"
            elif flags_str == "F":
                scan_type = "FIN Scan (FIN-Only Flag Set)"

        if scan_type:
            src_ip = packet.get("src_ip", "0.0.0.0")
            return Alert(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.MEDIUM,
                src_ip=src_ip,
                dst_ip=packet.get("dst_ip", "0.0.0.0"),
                dst_port=packet.get("dst_port"),
                protocol="TCP",
                details={"scan_type": scan_type, "raw_flags": str(tcp_flags)},
                recommendation=f"Investigate host scanning activity from {src_ip}.",
            )
        return None


class DNSAnomalyRule(ThreatRule):
    """
    Detects DNS query anomalies including DNS Tunneling attempts (overly long queries)
    and high-rate DNS query bursts.
    """

    rule_id = "RULE_DNS_ANOMALY"
    rule_name = "DNS Tunneling or High-Volume Query Anomaly"
    default_severity = Severity.MEDIUM
    cooldown_seconds = 5.0

    def evaluate(self, packet: Dict[str, Any], state: Dict[str, Any]) -> Optional[Alert]:
        protocol = packet.get("protocol", "").upper()
        payload = packet.get("payload_summary") or packet.get("payload_preview") or ""
        dns_query = packet.get("dns_query") or ""

        is_dns = protocol == "DNS" or packet.get("dst_port") == 53 or packet.get("src_port") == 53

        if not is_dns:
            return None

        src_ip = packet.get("src_ip", "0.0.0.0")
        src_state = state.get("ip_windows", {}).get(src_ip, {})
        dns_count = src_state.get("dns_count", 0)

        # Check DNS tunneling (query length > 60 chars)
        if len(dns_query) > 60:
            return Alert(
                rule_id=self.rule_id,
                rule_name="Possible DNS Tunneling Attempt",
                severity=Severity.HIGH,
                src_ip=src_ip,
                dst_ip=packet.get("dst_ip", "0.0.0.0"),
                dst_port=53,
                protocol="DNS",
                details={
                    "query": dns_query,
                    "query_length": len(dns_query),
                    "reason": "Exceeds standard domain name length threshold",
                },
                recommendation=f"Inspect DNS query content from {src_ip} for exfiltration data.",
            )

        # Check DNS flood rate
        if dns_count >= 15:
            return Alert(
                rule_id=self.rule_id,
                rule_name="DNS High-Frequency Query Burst",
                severity=Severity.MEDIUM,
                src_ip=src_ip,
                dst_ip=packet.get("dst_ip", "0.0.0.0"),
                dst_port=53,
                protocol="DNS",
                details={
                    "dns_query_count": dns_count,
                    "window_sec": state.get("window_size_sec", 10),
                },
                recommendation=f"Check if {src_ip} is compromised or performing malicious host lookup sweeps.",
            )

        return None
