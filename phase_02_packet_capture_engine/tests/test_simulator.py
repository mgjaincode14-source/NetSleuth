"""
Unit tests for Phase 2: Traffic Simulator
"""

import time
from scapy.all import IP, TCP, UDP, ICMP, DNS
from phase_02_packet_capture_engine.traffic_simulator import TrafficSimulator


def test_generate_http_packet():
    sim = TrafficSimulator()
    pkt = sim.generate_http_packet()
    assert pkt.haslayer(IP)
    assert pkt.haslayer(TCP)
    assert pkt[TCP].dport == 80


def test_generate_https_packet():
    sim = TrafficSimulator()
    pkt = sim.generate_https_packet()
    assert pkt.haslayer(IP)
    assert pkt.haslayer(TCP)
    assert pkt[TCP].dport == 443


def test_generate_dns_packet():
    sim = TrafficSimulator()
    pkt = sim.generate_dns_packet()
    assert pkt.haslayer(IP)
    assert pkt.haslayer(UDP)
    assert pkt.haslayer(DNS)


def test_generate_icmp_packet():
    sim = TrafficSimulator()
    pkt = sim.generate_icmp_packet()
    assert pkt.haslayer(IP)
    assert pkt.haslayer(ICMP)


def test_generate_threat_packets():
    sim = TrafficSimulator()
    port_scan = sim.generate_port_scan_packet(port=22)
    assert port_scan.haslayer(TCP)
    assert port_scan[TCP].dport == 22
    assert "S" in port_scan[TCP].flags

    syn_flood = sim.generate_syn_flood_packet(target_port=80)
    assert syn_flood.haslayer(TCP)
    assert syn_flood[TCP].dport == 80
    assert "S" in syn_flood[TCP].flags


def test_traffic_simulator_stream():
    captured = []

    def on_packet(pkt):
        captured.append(pkt)

    sim = TrafficSimulator(packet_callback=on_packet)
    sim.start_simulation(packets_per_second=50.0, total_packets=10)

    # Wait up to 1 second for 10 packets to be generated
    time.sleep(0.4)
    sim.stop_simulation()

    assert len(captured) >= 5
