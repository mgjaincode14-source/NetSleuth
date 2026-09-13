"""
Unit tests for TrafficStatsAggregator and Top Talkers
"""

from scapy.all import IP, TCP
from phase_03_packet_parser.parser import PacketParser
from phase_05_traffic_analytics.traffic_stats import TrafficStatsAggregator


def test_top_talkers_and_traffic_matrix():
    agg = TrafficStatsAggregator()
    parser = PacketParser()

    pkt1 = IP(src="192.168.1.50", dst="140.82.121.3") / TCP(sport=50000, dport=443)
    pkt2 = IP(src="192.168.1.50", dst="140.82.121.3") / TCP(sport=50000, dport=443)

    agg.process_packet(parser.parse(pkt1))
    agg.process_packet(parser.parse(pkt2))

    matrix = agg.get_traffic_matrix()
    assert len(matrix) == 1
    assert matrix[0].src_ip == "192.168.1.50"
    assert matrix[0].dst_ip == "140.82.121.3"
    assert matrix[0].packet_count == 2

    talkers = agg.get_top_talkers()
    assert len(talkers) == 2
    assert talkers[0].ip in ["192.168.1.50", "140.82.121.3"]
