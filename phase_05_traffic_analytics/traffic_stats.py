"""
Phase 5: Traffic Statistics & Matrix Aggregator
Computes Top Talkers, host conversations (Traffic Matrix), and protocol distribution.
"""

from typing import Dict, List, Tuple
from pydantic import BaseModel, Field

from phase_03_packet_parser.models import ParsedPacket


class TrafficMatrixEntry(BaseModel):
    """Represents communications between two specific IP endpoints."""
    src_ip: str
    dst_ip: str
    packet_count: int = 0
    total_bytes: int = 0
    primary_protocol: str = "OTHER"
    proto_counts: Dict[str, int] = Field(default_factory=dict)


class TopTalker(BaseModel):
    """Represents a top bandwidth-consuming host."""
    ip: str
    bytes_sent: int = 0
    bytes_received: int = 0
    total_bytes: int = 0
    packet_count: int = 0
    share_pct: float = 0.0


class TrafficStatsAggregator:
    """Aggregates conversation traffic matrices and Top Talker metrics."""

    def __init__(self):
        # Key: (src_ip, dst_ip)
        self.conversations: Dict[Tuple[str, str], TrafficMatrixEntry] = {}
        self.total_traffic_bytes: int = 0

    def process_packet(self, parsed: ParsedPacket):
        """Aggregate packet into conversation pairs and total traffic counter."""
        src_ip = parsed.flow_key.src_ip
        dst_ip = parsed.flow_key.dst_ip
        proto = parsed.protocol
        blen = parsed.length_bytes

        self.total_traffic_bytes += blen

        if src_ip and dst_ip and src_ip != "0.0.0.0" and dst_ip != "0.0.0.0":
            pair = (src_ip, dst_ip)
            if pair not in self.conversations:
                self.conversations[pair] = TrafficMatrixEntry(src_ip=src_ip, dst_ip=dst_ip)

            entry = self.conversations[pair]
            entry.packet_count += 1
            entry.total_bytes += blen
            entry.proto_counts[proto] = entry.proto_counts.get(proto, 0) + 1

            # Update primary protocol
            entry.primary_protocol = max(entry.proto_counts.items(), key=lambda x: x[1])[0]

    def get_traffic_matrix(self, limit: int = 20) -> List[TrafficMatrixEntry]:
        """Return top host-to-host conversation pairs sorted by volume."""
        return sorted(self.conversations.values(), key=lambda c: c.total_bytes, reverse=True)[:limit]

    def get_top_talkers(self, limit: int = 10) -> List[TopTalker]:
        """Calculate Top Talkers across sent & received traffic."""
        host_sent = {}
        host_recv = {}
        host_pkts = {}

        for entry in self.conversations.values():
            host_sent[entry.src_ip] = host_sent.get(entry.src_ip, 0) + entry.total_bytes
            host_recv[entry.dst_ip] = host_recv.get(entry.dst_ip, 0) + entry.total_bytes
            host_pkts[entry.src_ip] = host_pkts.get(entry.src_ip, 0) + entry.packet_count
            host_pkts[entry.dst_ip] = host_pkts.get(entry.dst_ip, 0) + entry.packet_count

        all_ips = set(host_sent.keys()).union(host_recv.keys())
        total_b = max(1, self.total_traffic_bytes)
        top_list = []

        for ip in all_ips:
            sent = host_sent.get(ip, 0)
            recv = host_recv.get(ip, 0)
            tot = sent + recv
            pkts = host_pkts.get(ip, 0)
            pct = round((tot / total_b) * 100, 1)

            top_list.append(
                TopTalker(
                    ip=ip,
                    bytes_sent=sent,
                    bytes_received=recv,
                    total_bytes=tot,
                    packet_count=pkts,
                    share_pct=pct,
                )
            )

        return sorted(top_list, key=lambda t: t.total_bytes, reverse=True)[:limit]
