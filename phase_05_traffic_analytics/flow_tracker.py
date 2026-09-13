"""
Phase 5: Stateful Network Flow Tracker
Reconstructs 5-tuple bidirectional network flows and tracks TCP connection state transitions.
"""

import time
from enum import Enum
from typing import Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from phase_03_packet_parser.models import ParsedPacket, FlowKey


class FlowState(str, Enum):
    NEW = "NEW"
    SYN_SENT = "SYN_SENT"
    SYN_ACK_REC = "SYN_ACK_REC"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT = "FIN_WAIT"
    CLOSED = "CLOSED"
    RESET = "RESET"
    UDP_ACTIVE = "UDP_ACTIVE"
    ICMP_ACTIVE = "ICMP_ACTIVE"
    OTHER_ACTIVE = "OTHER_ACTIVE"


class NetworkFlow(BaseModel):
    """Represents a stateful bidirectional 5-tuple network flow."""
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str

    start_time: float
    last_seen_time: float
    duration_seconds: float = 0.0

    packets_forward: int = 0
    packets_reverse: int = 0
    total_packets: int = 0

    bytes_forward: int = 0
    bytes_reverse: int = 0
    total_bytes: int = 0

    state: FlowState = FlowState.NEW
    is_active: bool = True
    anomaly_flags: List[str] = Field(default_factory=list)

    def update_duration(self, current_time: float):
        self.last_seen_time = current_time
        self.duration_seconds = round(self.last_seen_time - self.start_time, 2)


class FlowTracker:
    """Stateful engine tracking active and closed 5-tuple network flows."""

    def __init__(self, inactivity_timeout_seconds: float = 60.0):
        self.inactivity_timeout = inactivity_timeout_seconds
        self.active_flows: Dict[str, NetworkFlow] = {}
        self.closed_flows: List[NetworkFlow] = []

    def get_canonical_flow_ids(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> Tuple[str, str]:
        """Generate forward and reverse flow key strings."""
        fwd_id = f"{protocol}:{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        rev_id = f"{protocol}:{dst_ip}:{dst_port}->{src_ip}:{src_port}"
        return fwd_id, rev_id

    def process_packet(self, parsed: ParsedPacket) -> NetworkFlow:
        """Process a ParsedPacket and update or create its corresponding stateful NetworkFlow."""
        now = parsed.timestamp or time.time()
        fk = parsed.flow_key

        fwd_id, rev_id = self.get_canonical_flow_ids(
            fk.src_ip, fk.src_port, fk.dst_ip, fk.dst_port, fk.protocol
        )

        flow = None
        is_reverse = False

        if fwd_id in self.active_flows:
            flow = self.active_flows[fwd_id]
            is_reverse = False
        elif rev_id in self.active_flows:
            flow = self.active_flows[rev_id]
            is_reverse = True
        else:
            # Create new flow entry
            initial_state = FlowState.NEW
            if fk.protocol == "TCP":
                initial_state = FlowState.SYN_SENT if (parsed.l4 and parsed.l4.tcp_flags_dict.get("SYN")) else FlowState.ESTABLISHED
            elif fk.protocol == "UDP" or fk.protocol in ["DNS", "HTTP", "HTTPS"]:
                initial_state = FlowState.UDP_ACTIVE if fk.protocol == "UDP" else FlowState.OTHER_ACTIVE
            elif fk.protocol == "ICMP":
                initial_state = FlowState.ICMP_ACTIVE

            flow = NetworkFlow(
                flow_id=fwd_id,
                src_ip=fk.src_ip,
                src_port=fk.src_port,
                dst_ip=fk.dst_ip,
                dst_port=fk.dst_port,
                protocol=fk.protocol,
                start_time=now,
                last_seen_time=now,
                state=initial_state,
            )
            self.active_flows[fwd_id] = flow

        # Update metrics
        if is_reverse:
            flow.packets_reverse += 1
            flow.bytes_reverse += parsed.length_bytes
        else:
            flow.packets_forward += 1
            flow.bytes_forward += parsed.length_bytes

        flow.total_packets = flow.packets_forward + flow.packets_reverse
        flow.total_bytes = flow.bytes_forward + flow.bytes_reverse
        flow.update_duration(now)

        # Update TCP state machine if TCP
        if parsed.l4 and parsed.l4.tcp_flags_dict:
            flags = parsed.l4.tcp_flags_dict
            if flags.get("RST"):
                flow.state = FlowState.RESET
                flow.is_active = False
            elif flags.get("FIN"):
                flow.state = FlowState.FIN_WAIT
            elif flags.get("SYN") and flags.get("ACK"):
                flow.state = FlowState.SYN_ACK_REC
            elif flags.get("ACK") and flow.state in [FlowState.SYN_SENT, FlowState.SYN_ACK_REC, FlowState.NEW]:
                flow.state = FlowState.ESTABLISHED

        # Preserve anomaly tags
        if parsed.anomaly_tag and parsed.anomaly_tag not in flow.anomaly_flags:
            flow.anomaly_flags.append(parsed.anomaly_tag)

        return flow

    def prune_stale_flows(self, current_time: Optional[float] = None) -> int:
        """Move flows inactive longer than timeout to closed_flows."""
        now = current_time or time.time()
        stale_keys = []

        for flow_id, flow in self.active_flows.items():
            if (now - flow.last_seen_time) >= self.inactivity_timeout or not flow.is_active:
                flow.is_active = False
                stale_keys.append(flow_id)

        for key in stale_keys:
            stale_flow = self.active_flows.pop(key)
            self.closed_flows.append(stale_flow)

        return len(stale_keys)

    def get_all_active_flows(self) -> List[NetworkFlow]:
        """Return list of all currently active flows."""
        return list(self.active_flows.values())


    def get_flow_summary_list(self, limit: int = 50) -> List[NetworkFlow]:
        """Return list of active flows sorted by most recently active."""
        return sorted(self.active_flows.values(), key=lambda f: f.last_seen_time, reverse=True)[:limit]
