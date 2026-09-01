"""
Phase 3: Packet Parser Models
Pydantic schemas representing extracted Layer 2 through Layer 7 network protocol data.
"""

from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class FlowKey(BaseModel):
    """5-Tuple network flow identifier."""
    src_ip: str
    src_port: int = 0
    dst_ip: str
    dst_port: int = 0
    protocol: str

    def to_string(self) -> str:
        return f"{self.protocol}:{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}"


class L2Header(BaseModel):
    """Layer 2 (Ethernet) Header Metadata."""
    src_mac: str = "00:00:00:00:00:00"
    dst_mac: str = "00:00:00:00:00:00"
    ethertype: int = 0x0800


class L3Header(BaseModel):
    """Layer 3 (IP / IPv6) Header Metadata."""
    version: int = 4
    src_ip: str
    dst_ip: str
    ttl: int = 64
    protocol_num: int = 6
    header_length: int = 20


class L4Header(BaseModel):
    """Layer 4 (TCP / UDP) Header Metadata."""
    src_port: int
    dst_port: int
    seq: Optional[int] = None
    ack: Optional[int] = None
    window: Optional[int] = None
    tcp_flags_raw: Optional[str] = None
    tcp_flags_dict: Dict[str, bool] = Field(default_factory=dict)
    tcp_flags_summary: Optional[str] = None


class DNSMetadata(BaseModel):
    """Domain Name System (DNS) Protocol Metadata."""
    id: int = 0
    is_response: bool = False
    qname: Optional[str] = None
    qtype: Optional[str] = None
    rcode: int = 0
    answers: List[str] = []


class HTTPMetadata(BaseModel):
    """HyperText Transfer Protocol (HTTP) Metadata."""
    is_request: bool = True
    method: Optional[str] = None
    path: Optional[str] = None
    host: Optional[str] = None
    user_agent: Optional[str] = None
    status_code: Optional[int] = None


class ICMPMetadata(BaseModel):
    """Internet Control Message Protocol (ICMP) Metadata."""
    type: int
    code: int
    type_name: str


class ARPMetadata(BaseModel):
    """Address Resolution Protocol (ARP) Metadata."""
    operation: str  # "request" or "reply"
    src_mac: str
    src_ip: str
    dst_mac: str
    dst_ip: str


class ParsedPacket(BaseModel):
    """Complete unified parsed representation of a captured network packet."""
    packet_id: int
    timestamp: float
    length_bytes: int
    protocol: str
    direction: str  # "INCOMING", "OUTGOING", "LOCAL"
    flow_key: FlowKey

    # Headers
    l2: Optional[L2Header] = None
    l3: Optional[L3Header] = None
    l4: Optional[L4Header] = None

    # Protocol specific metadata
    dns: Optional[DNSMetadata] = None
    http: Optional[HTTPMetadata] = None
    icmp: Optional[ICMPMetadata] = None
    arp: Optional[ARPMetadata] = None

    # Payload & Inspection
    payload_size: int = 0
    payload_hex: Optional[str] = None
    payload_ascii: Optional[str] = None

    # Anomaly tag from analyzer
    anomaly_tag: Optional[str] = None

    def summary_line(self) -> str:
        """Single-line summary for logging and displays."""
        return (
            f"[{self.packet_id}] {self.timestamp:.3f}s | {self.direction:<8} | "
            f"{self.flow_key.to_string():<38} | {self.length_bytes:>4} B | "
            f"Flags: {self.l4.tcp_flags_summary if self.l4 else '-':<7} | "
            f"Alert: {self.anomaly_tag or 'NORMAL'}"
        )
