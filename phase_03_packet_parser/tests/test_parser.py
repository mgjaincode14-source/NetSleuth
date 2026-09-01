"""
Unit tests for Phase 3: Packet Parser Engine
"""

from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, Ether
from phase_03_packet_parser.parser import PacketParser
from phase_03_packet_parser.models import ParsedPacket, FlowKey


def test_parse_http_packet():
    parser = PacketParser(local_ips=["192.168.1.10"])
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="192.168.1.10", dst="93.184.216.34")
        / TCP(sport=51234, dport=80, flags="PA", seq=100, ack=200)
        / Raw(load=b"GET /api/v1/status HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )

    parsed = parser.parse(pkt)
    assert isinstance(parsed, ParsedPacket)
    assert parsed.protocol == "HTTP"
    assert parsed.direction == "OUTGOING"
    assert parsed.flow_key.src_ip == "192.168.1.10"
    assert parsed.flow_key.dst_ip == "93.184.216.34"
    assert parsed.flow_key.src_port == 51234
    assert parsed.flow_key.dst_port == 80

    assert parsed.l2 is not None
    assert parsed.l2.src_mac == "00:11:22:33:44:55"
    assert parsed.l3 is not None
    assert parsed.l3.src_ip == "192.168.1.10"

    assert parsed.l4 is not None
    assert parsed.l4.tcp_flags_dict["PSH"] is True
    assert parsed.l4.tcp_flags_dict["ACK"] is True
    assert parsed.l4.tcp_flags_dict["SYN"] is False

    assert parsed.http is not None
    assert parsed.http.method == "GET"
    assert parsed.http.path == "/api/v1/status"
    assert parsed.http.host == "example.com"


def test_parse_dns_query_packet():
    parser = PacketParser(local_ips=["192.168.1.10"])
    pkt = (
        IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=43210, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="cloudflare.com", qtype="A"))
    )

    parsed = parser.parse(pkt)
    assert parsed.protocol == "DNS"
    assert parsed.dns is not None
    assert parsed.dns.qname == "cloudflare.com."
    assert parsed.dns.qtype == "A"


def test_parse_icmp_ping():
    parser = PacketParser(local_ips=["192.168.1.10"])
    pkt = IP(src="8.8.8.8", dst="192.168.1.10") / ICMP(type=8, code=0) / Raw(load=b"PingTest")

    parsed = parser.parse(pkt)
    assert parsed.protocol == "ICMP"
    assert parsed.direction == "INCOMING"
    assert parsed.icmp is not None
    assert parsed.icmp.type == 8
    assert parsed.icmp.type_name == "Echo Request"


def test_flow_key_string():
    fk = FlowKey(src_ip="10.0.0.1", src_port=1234, dst_ip="10.0.0.2", dst_port=80, protocol="TCP")
    assert fk.to_string() == "TCP:10.0.0.1:1234->10.0.0.2:80"
