"""
Unit tests for BandwidthCalculator and rate estimations
"""

from scapy.all import IP, TCP, UDP
from phase_03_packet_parser.parser import PacketParser
from phase_05_traffic_analytics.bandwidth_calculator import BandwidthCalculator


def test_bandwidth_calculator_host_totals():
    calc = BandwidthCalculator(window_seconds=2.0)
    parser = PacketParser()

    pkt1 = IP(src="192.168.1.5", dst="8.8.8.8") / UDP(sport=1234, dport=53)
    pkt2 = IP(src="192.168.1.5", dst="8.8.8.8") / UDP(sport=1234, dport=53)

    parsed1 = parser.parse(pkt1)
    parsed2 = parser.parse(pkt2)

    calc.process_packet(parsed1)
    calc.process_packet(parsed2)

    assert "192.168.1.5" in calc.hosts
    assert calc.hosts["192.168.1.5"].bytes_sent == (len(pkt1) + len(pkt2))
    assert calc.hosts["8.8.8.8"].bytes_received == (len(pkt1) + len(pkt2))

    calc.compute_rates()
    top_hosts = calc.get_top_host_bandwidth(limit=2)
    assert len(top_hosts) == 2
