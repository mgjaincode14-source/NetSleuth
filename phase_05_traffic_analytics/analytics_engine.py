"""
Phase 5: Master Analytics Engine
Combines FlowTracker, BandwidthCalculator, and TrafficStatsAggregator into a unified analytics suite.
"""

from typing import Dict, List, Optional, Any
from pydantic import BaseModel

from phase_03_packet_parser.models import ParsedPacket
from phase_05_traffic_analytics.flow_tracker import FlowTracker, NetworkFlow
from phase_05_traffic_analytics.bandwidth_calculator import BandwidthCalculator, HostBandwidth, ProtocolBandwidth
from phase_05_traffic_analytics.traffic_stats import TrafficStatsAggregator, TopTalker, TrafficMatrixEntry


class AnalyticsSnapshot(BaseModel):
    """Unified snapshot of traffic analytics."""
    active_flow_count: int
    closed_flow_count: int
    total_volume_bytes: int
    top_talkers: List[TopTalker]
    traffic_matrix: List[TrafficMatrixEntry]
    protocol_bandwidth: List[ProtocolBandwidth]
    active_flows_sample: List[NetworkFlow]


class AnalyticsEngine:
    """Master Traffic Analytics Engine orchestrating flow tracking, bandwidth, and top talkers."""

    def __init__(self, local_ips: Optional[List[str]] = None, flow_inactivity_timeout: float = 60.0):
        self.flow_tracker = FlowTracker(inactivity_timeout_seconds=flow_inactivity_timeout)
        self.bandwidth_calc = BandwidthCalculator(window_seconds=2.0)
        self.stats_aggregator = TrafficStatsAggregator()
        self.total_packets_processed = 0

    def process_packet(self, parsed: ParsedPacket) -> NetworkFlow:
        """Process a single parsed packet across all analytics components."""
        self.total_packets_processed += 1

        # 1. Update stateful flow tracker
        flow = self.flow_tracker.process_packet(parsed)

        # 2. Update real-time bandwidth calculator
        self.bandwidth_calc.process_packet(parsed)

        # 3. Update top talkers and traffic matrix
        self.stats_aggregator.process_packet(parsed)

        return flow

    def get_snapshot(self, current_time: Optional[float] = None) -> AnalyticsSnapshot:
        """Recompute rates, prune stale flows, and return unified AnalyticsSnapshot."""
        # Recompute rates & prune
        self.bandwidth_calc.compute_rates(current_time=current_time)
        self.flow_tracker.prune_stale_flows(current_time=current_time)

        return AnalyticsSnapshot(
            active_flow_count=len(self.flow_tracker.active_flows),
            closed_flow_count=len(self.flow_tracker.closed_flows),
            total_volume_bytes=self.stats_aggregator.total_traffic_bytes,
            top_talkers=self.stats_aggregator.get_top_talkers(limit=8),
            traffic_matrix=self.stats_aggregator.get_traffic_matrix(limit=8),
            protocol_bandwidth=self.bandwidth_calc.get_protocol_bandwidth(),
            active_flows_sample=self.flow_tracker.get_flow_summary_list(limit=10),
        )
