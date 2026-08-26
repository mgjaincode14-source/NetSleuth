"""
Unit tests for ProtocolAnalyzer (TCP flags, direction tracking, and anomaly detection)
"""

from scapy .all import IP ,TCP ,UDP ,ICMP ,DNS ,DNSQR 
from phase_02_packet_capture_engine .protocol_analyzer import ProtocolAnalyzer 


def test_determine_direction ():
    analyzer =ProtocolAnalyzer (local_ips =["192.168.1.50"])

    assert analyzer .determine_direction ("192.168.1.50","8.8.8.8")=="OUTGOING"
    assert analyzer .determine_direction ("8.8.8.8","192.168.1.50")=="INCOMING"
    assert analyzer .determine_direction ("127.0.0.1","127.0.0.1")=="LOCAL"


def test_tcp_flags_parsing ():
    analyzer =ProtocolAnalyzer ()

    _ ,name1 =analyzer .parse_tcp_flags ("S")
    assert name1 =="SYN"

    _ ,name2 =analyzer .parse_tcp_flags ("SA")
    assert name2 =="SYN-ACK"

    _ ,name3 =analyzer .parse_tcp_flags ("RA")
    assert name3 =="RST"


def test_analyze_tcp_syn_scan ():
    analyzer =ProtocolAnalyzer (local_ips =["192.168.1.50"])
    pkt =IP (src ="10.0.0.99",dst ="192.168.1.50")/TCP (sport =54321 ,dport =22 ,flags ="S")

    result =analyzer .analyze (pkt )
    assert result .protocol =="TCP"
    assert result .direction =="INCOMING"
    assert result .tcp_flags_str =="SYN"
    assert result .anomaly_flag is not None 
    assert "POSSIBLE_SYN_SCAN"in result .anomaly_flag 


def test_analyze_xmas_scan ():
    analyzer =ProtocolAnalyzer (local_ips =["192.168.1.50"])
    pkt =IP (src ="10.0.0.99",dst ="192.168.1.50")/TCP (sport =54321 ,dport =80 ,flags ="FPU")

    result =analyzer .analyze (pkt )
    assert result .anomaly_flag is not None 
    assert "Xmas Scan"in result .anomaly_flag 
