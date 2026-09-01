"""
Phase 3: Deep Packet Parser Engine
Decodes raw Scapy packets into structured, typed ParsedPacket models.
"""

import string
import time
from typing import Dict, List, Optional
from scapy.all import Packet, Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw

from phase_02_packet_capture_engine.protocol_analyzer import ProtocolAnalyzer
from phase_03_packet_parser.models import (
    ParsedPacket, FlowKey, L2Header, L3Header, L4Header,
    DNSMetadata, HTTPMetadata, ICMPMetadata, ARPMetadata
)


class PacketParser:
    """Decodes raw Scapy packets into structured Pydantic ParsedPacket objects."""

    ICMP_TYPE_NAMES = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        5: "Redirect",
        8: "Echo Request",
        11: "Time Exceeded",
    }

    DNS_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}

    def __init__(self, local_ips: Optional[List[str]] = None):
        self.analyzer = ProtocolAnalyzer(local_ips=local_ips)
        self.packet_counter = 0

    def set_local_ips(self, local_ips: List[str]):
        """Update local IP list for packet direction tracking."""
        self.analyzer.set_local_ips(local_ips)

    def extract_tcp_flags_dict(self, flags_val) -> Dict[str, bool]:
        """Convert TCP flags into a dictionary of boolean state flags."""
        flags_str = str(flags_val)
        return {
            "SYN": "S" in flags_str,
            "ACK": "A" in flags_str,
            "FIN": "F" in flags_str,
            "RST": "R" in flags_str,
            "PSH": "P" in flags_str,
            "URG": "U" in flags_str,
            "ECE": "E" in flags_str,
            "CWR": "C" in flags_str,
        }

    def sanitize_ascii(self, payload_bytes: bytes, max_len: int = 120) -> str:
        """Convert raw payload bytes into printable ASCII string."""
        printable = set(string.printable.encode()) - set(b"\r\n\t\x0b\x0c")
        sanitized = "".join(chr(b) if b in printable else "." for b in payload_bytes[:max_len])
        return sanitized

    def parse(self, pkt: Packet) -> ParsedPacket:
        """Perform deep packet decoding layer by layer."""
        self.packet_counter += 1
        pkt_id = self.packet_counter
        timestamp = float(getattr(pkt, "time", time.time()))
        length_bytes = len(pkt)

        # 1. Analyze basic protocol & direction using ProtocolAnalyzer
        analyzed_info = self.analyzer.analyze(pkt)

        src_ip = analyzed_info.src_ip
        dst_ip = analyzed_info.dst_ip
        src_port = analyzed_info.src_port or 0
        dst_port = analyzed_info.dst_port or 0
        protocol = analyzed_info.protocol
        direction = analyzed_info.direction
        anomaly_tag = analyzed_info.anomaly_flag

        flow_key = FlowKey(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
        )

        # 2. Layer 2 Ethernet Parsing
        l2_hdr = None
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            l2_hdr = L2Header(
                src_mac=eth.src,
                dst_mac=eth.dst,
                ethertype=eth.type,
            )

        # 3. Layer 3 IP Parsing
        l3_hdr = None
        if pkt.haslayer(IP):
            ip = pkt[IP]
            l3_hdr = L3Header(
                version=ip.version if ip.version is not None else 4,
                src_ip=ip.src,
                dst_ip=ip.dst,
                ttl=ip.ttl if ip.ttl is not None else 64,
                protocol_num=ip.proto if ip.proto is not None else 6,
                header_length=(ip.ihl * 4) if ip.ihl is not None else 20,
            )

        elif pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            l3_hdr = L3Header(
                version=6,
                src_ip=ip6.src,
                dst_ip=ip6.dst,
                ttl=ip6.hlim,
                protocol_num=ip6.nh,
                header_length=40,
            )

        # 4. Layer 4 Transport Parsing (TCP / UDP)
        l4_hdr = None
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags_raw, flags_summary = self.analyzer.parse_tcp_flags(tcp.flags)
            flags_dict = self.extract_tcp_flags_dict(tcp.flags)

            l4_hdr = L4Header(
                src_port=tcp.sport,
                dst_port=tcp.dport,
                seq=tcp.seq,
                ack=tcp.ack,
                window=tcp.window,
                tcp_flags_raw=flags_raw,
                tcp_flags_dict=flags_dict,
                tcp_flags_summary=flags_summary,
            )
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            l4_hdr = L4Header(
                src_port=udp.sport,
                dst_port=udp.dport,
            )

        # 5. Application Layer Metadata Extraction
        dns_meta = None
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            qname = None
            qtype_str = None
            if dns.haslayer(DNSQR):
                qn = dns[DNSQR].qname
                qname = qn.decode(errors="ignore") if isinstance(qn, bytes) else str(qn)
                qtype_int = dns[DNSQR].qtype
                qtype_str = self.DNS_QTYPES.get(qtype_int, str(qtype_int))

            answers = []
            if (dns.ancount or 0) > 0 and dns.haslayer(DNSRR):
                rr = dns[DNSRR]

                while rr:
                    if hasattr(rr, "rdata"):
                        rdata = rr.rdata
                        answers.append(str(rdata))
                    rr = rr.payload if hasattr(rr, "payload") and isinstance(rr.payload, DNSRR) else None

            dns_meta = DNSMetadata(
                id=dns.id,
                is_response=bool(dns.qr),
                qname=qname,
                qtype=qtype_str,
                rcode=dns.rcode,
                answers=answers[:5],
            )

        http_meta = None
        if pkt.haslayer(Raw):
            payload_data = pkt[Raw].load
            if payload_data.startswith((b"GET ", b"POST ", b"HTTP/", b"PUT ", b"DELETE ", b"HEAD ")):
                try:
                    text = payload_data.decode("latin1", errors="ignore")
                    lines = text.split("\r\n")
                    first_line = lines[0]
                    headers = {}
                    for line in lines[1:]:
                        if ":" in line:
                            k, v = line.split(":", 1)
                            headers[k.strip().lower()] = v.strip()

                    parts = first_line.split(" ")
                    if len(parts) >= 2 and parts[0] in ["GET", "POST", "PUT", "DELETE", "HEAD"]:
                        http_meta = HTTPMetadata(
                            is_request=True,
                            method=parts[0],
                            path=parts[1],
                            host=headers.get("host"),
                            user_agent=headers.get("user-agent"),
                        )
                    elif len(parts) >= 2 and parts[0].startswith("HTTP/"):
                        status_code = int(parts[1]) if parts[1].isdigit() else None
                        http_meta = HTTPMetadata(
                            is_request=False,
                            status_code=status_code,
                        )
                except Exception:
                    pass

        icmp_meta = None
        if pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            type_name = self.ICMP_TYPE_NAMES.get(icmp.type, f"ICMP Type {icmp.type}")
            icmp_meta = ICMPMetadata(
                type=icmp.type,
                code=icmp.code,
                type_name=type_name,
            )

        arp_meta = None
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            op_name = "request" if arp.op == 1 else ("reply" if arp.op == 2 else f"op-{arp.op}")
            arp_meta = ARPMetadata(
                operation=op_name,
                src_mac=arp.hwsrc,
                src_ip=arp.psrc,
                dst_mac=arp.hwdst,
                dst_ip=arp.pdst,
            )

        # 6. Payload Inspection
        payload_size = 0
        payload_hex = None
        payload_ascii = None
        if pkt.haslayer(Raw):
            raw_bytes = pkt[Raw].load
            payload_size = len(raw_bytes)
            payload_hex = raw_bytes[:32].hex(" ")
            payload_ascii = self.sanitize_ascii(raw_bytes, max_len=60)

        return ParsedPacket(
            packet_id=pkt_id,
            timestamp=timestamp,
            length_bytes=length_bytes,
            protocol=protocol,
            direction=direction,
            flow_key=flow_key,
            l2=l2_hdr,
            l3=l3_hdr,
            l4=l4_hdr,
            dns=dns_meta,
            http=http_meta,
            icmp=icmp_meta,
            arp=arp_meta,
            payload_size=payload_size,
            payload_hex=payload_hex,
            payload_ascii=payload_ascii,
            anomaly_tag=anomaly_tag,
        )
