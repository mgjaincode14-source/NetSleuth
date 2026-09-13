"""
Unit tests for Phase 5 Stateful Flow Tracker and TCP State Machine
"""

import time
from scapy.all import IP, TCP, UDP
from phase_03_packet_parser.parser import PacketParser
from phase_05_traffic_analytics.flow_tracker import FlowTracker, FlowState


def test_flow_reconstruction_bidirectional():
    tracker = FlowTracker()
    parser = PacketParser(local_ips=["192.168.1.10"])

    # Packet 1: Forward SYN
    pkt1 = IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=54321, dport=80, flags="S")
    parsed1 = parser.parse(pkt1)
    flow1 = tracker.process_packet(parsed1)

    assert flow1.packets_forward == 1
    assert flow1.packets_reverse == 0
    assert flow1.state == FlowState.SYN_SENT

    # Packet 2: Reverse SYN-ACK
    pkt2 = IP(src="93.184.216.34", dst="192.168.1.10") / TCP(sport=80, dport=54321, flags="SA")
    parsed2 = parser.parse(pkt2)
    flow2 = tracker.process_packet(parsed2)

    # Should map to the SAME flow object
    assert flow2.flow_id == flow1.flow_id
    assert flow2.packets_forward == 1
    assert flow2.packets_reverse == 1
    assert flow2.total_packets == 2
    assert flow2.state == FlowState.SYN_ACK_REC

    # Packet 3: Forward ACK -> ESTABLISHED
    pkt3 = IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=54321, dport=80, flags="A")
    parsed3 = parser.parse(pkt3)
    flow3 = tracker.process_packet(parsed3)

    assert flow3.state == FlowState.ESTABLISHED


def test_flow_pruning():
    tracker = FlowTracker(inactivity_timeout_seconds=2.0)
    parser = PacketParser()

    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1000, dport=2000)
    parsed = parser.parse(pkt)
    tracker.process_packet(parsed)

    assert len(tracker.active_flows) == 1

    # Prune with current_time 5 seconds later
    pruned = tracker.prune_stale_flows(current_time=time.time() + 5.0)
    assert pruned == 1
    assert len(tracker.active_flows) == 0
    assert len(tracker.closed_flows) == 1
