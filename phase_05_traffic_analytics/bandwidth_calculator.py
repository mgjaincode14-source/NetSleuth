"""
Phase 5: Real-Time Bandwidth & Rate Calculator
Computes host-level, protocol-level, and total throughput rates (B/s, KB/s, MB/s, Mbps).
"""

import time
from collections import deque
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from phase_03_packet_parser.models import ParsedPacket


class HostBandwidth(BaseModel):
    """Bandwidth stats for a single IP address."""
    ip: str
    bytes_sent: int = 0
    bytes_received: int = 0
    total_bytes: int = 0
    send_bps: float = 0.0
    recv_bps: float = 0.0
    total_bps: float = 0.0


class ProtocolBandwidth(BaseModel):
    """Bandwidth stats for a specific protocol."""
    protocol: str
    packet_count: int = 0
    total_bytes: int = 0
    bps: float = 0.0
    pps: float = 0.0
    avg_packet_size: float = 0.0


class BandwidthCalculator:
    """Sliding-window real-time bandwidth and throughput calculator."""

    def __init__(self, window_seconds: float = 2.0):
        self.window_seconds = window_seconds
        self.hosts: Dict[str, HostBandwidth] = {}
        self.protocols: Dict[str, ProtocolBandwidth] = {}

        # Sliding window queues: (timestamp, src_ip, dst_ip, proto, bytes)
        self._window: deque = deque(maxlen=5000)

    def process_packet(self, parsed: ParsedPacket):
        """Record packet data into sliding window and host/protocol counters."""
        now = parsed.timestamp or time.time()
        src_ip = parsed.flow_key.src_ip
        dst_ip = parsed.flow_key.dst_ip
        proto = parsed.protocol
        pkt_len = parsed.length_bytes

        # Update host totals
        if src_ip and src_ip != "0.0.0.0":
            if src_ip not in self.hosts:
                self.hosts[src_ip] = HostBandwidth(ip=src_ip)
            self.hosts[src_ip].bytes_sent += pkt_len
            self.hosts[src_ip].total_bytes += pkt_len

        if dst_ip and dst_ip != "0.0.0.0":
            if dst_ip not in self.hosts:
                self.hosts[dst_ip] = HostBandwidth(ip=dst_ip)
            self.hosts[dst_ip].bytes_received += pkt_len
            self.hosts[dst_ip].total_bytes += pkt_len

        # Update protocol totals
        if proto not in self.protocols:
            self.protocols[proto] = ProtocolBandwidth(protocol=proto)
        self.protocols[proto].packet_count += 1
        self.protocols[proto].total_bytes += pkt_len
        self.protocols[proto].avg_packet_size = round(
            self.protocols[proto].total_bytes / self.protocols[proto].packet_count, 1
        )

        self._window.append((now, src_ip, dst_ip, proto, pkt_len))

    def compute_rates(self, current_time: Optional[float] = None):
        """Recompute instantaneous rates (BPS/PPS) over sliding time window."""
        now = current_time or time.time()
        cutoff = now - self.window_seconds

        # Prune old entries
        while self._window and self._window[0][0] < (now - 10.0):
            self._window.popleft()

        recent = [e for e in self._window if e[0] >= cutoff]
        duration = max(0.5, (now - recent[0][0])) if recent else 1.0

        # Reset rates
        host_send_bytes = {}
        host_recv_bytes = {}
        proto_bytes = {}
        proto_packets = {}

        for entry in recent:
            ts, src, dst, proto, blen = entry
            host_send_bytes[src] = host_send_bytes.get(src, 0) + blen
            host_recv_bytes[dst] = host_recv_bytes.get(dst, 0) + blen
            proto_bytes[proto] = proto_bytes.get(proto, 0) + blen
            proto_packets[proto] = proto_packets.get(proto, 0) + 1

        # Update host rates
        for ip, host in self.hosts.items():
            sb = host_send_bytes.get(ip, 0)
            rb = host_recv_bytes.get(ip, 0)
            host.send_bps = round(sb / duration, 1)
            host.recv_bps = round(rb / duration, 1)
            host.total_bps = round((sb + rb) / duration, 1)

        # Update protocol rates
        for proto, pbw in self.protocols.items():
            pb = proto_bytes.get(proto, 0)
            pp = proto_packets.get(proto, 0)
            pbw.bps = round(pb / duration, 1)
            pbw.pps = round(pp / duration, 1)

    def get_top_host_bandwidth(self, limit: int = 10) -> List[HostBandwidth]:
        """Return top hosts by total bandwidth/rate."""
        return sorted(self.hosts.values(), key=lambda h: h.total_bytes, reverse=True)[:limit]

    def get_protocol_bandwidth(self) -> List[ProtocolBandwidth]:
        """Return list of protocol bandwidth metrics."""
        return sorted(self.protocols.values(), key=lambda p: p.total_bytes, reverse=True)
