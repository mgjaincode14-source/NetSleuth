"""
Phase 2: Protocol Analyzer
Analyzes network packets to extract protocol fields, TCP flag combinations, packet directions,
and flags abnormal TCP behaviors or potential port scans.
"""

from typing import Dict ,List ,Optional ,Any 
from pydantic import BaseModel ,Field 
from scapy .all import Packet ,IP ,IPv6 ,TCP ,UDP ,ICMP ,ARP ,DNS ,DNSQR ,Raw 


class AnalyzedPacket (BaseModel ):
    """Structured result of analyzing a single packet."""
    timestamp :float 
    src_ip :str 
    dst_ip :str 
    src_port :Optional [int ]=None 
    dst_port :Optional [int ]=None 
    protocol :str 
    direction :str 
    length :int 
    tcp_flags_str :Optional [str ]=None 
    details :str 
    anomaly_flag :Optional [str ]=None 


class ProtocolAnalyzer :
    """Analyzes raw Scapy packets for protocol details, directions, and abnormalities."""

    SUSPICIOUS_PORTS ={21 :"FTP",22 :"SSH",23 :"TELNET",445 :"SMB",1433 :"MSSQL",3306 :"MYSQL",3389 :"RDP"}

    def __init__ (self ,local_ips :Optional [List [str ]]=None ):
        self .local_ips =set (local_ips or ["127.0.0.1","::1"])

    def set_local_ips (self ,local_ips :List [str ]):
        """Update the set of local IP addresses for direction classification."""
        self .local_ips =set (local_ips )

    def determine_direction (self ,src_ip :str ,dst_ip :str )->str :
        """Classify packet direction based on local IP addresses."""
        src_is_local =src_ip in self .local_ips or src_ip .startswith ("127.")
        dst_is_local =dst_ip in self .local_ips or dst_ip .startswith ("127.")

        if src_is_local and dst_is_local :
            return "LOCAL"
        elif src_is_local :
            return "OUTGOING"
        elif dst_is_local :
            return "INCOMING"
        return "INCOMING"

    def parse_tcp_flags (self ,flags_val )->tuple [str ,str ]:
        """
        Parse TCP flag combination and return (flag_name_str, handshake_state).
        Flags string can contain F(FIN), S(SYN), R(RST), P(PSH), A(ACK), U(URG), E(ECE), C(CWR).
        """
        flags_str =str (flags_val )
        flag_names =[]

        if "S"in flags_str and "A"in flags_str :
            flag_names .append ("SYN-ACK")
        elif "S"in flags_str :
            flag_names .append ("SYN")
        elif "F"in flags_str and "A"in flags_str :
            flag_names .append ("FIN-ACK")
        elif "F"in flags_str :
            flag_names .append ("FIN")
        elif "R"in flags_str :
            flag_names .append ("RST")
        elif "P"in flags_str and "A"in flags_str :
            flag_names .append ("PSH-ACK")
        elif "A"in flags_str :
            flag_names .append ("ACK")
        else :
            flag_names .append (flags_str if flags_str else "NONE")

        combined ="-".join (flag_names )
        return flags_str ,combined 

    def analyze (self ,pkt :Packet )->AnalyzedPacket :
        """Perform deep inspection of a packet and return an AnalyzedPacket object."""
        src_ip ="0.0.0.0"
        dst_ip ="0.0.0.0"
        src_port =None 
        dst_port =None 
        protocol ="OTHER"
        details =pkt .summary ()
        anomaly_flag =None 
        tcp_flags_str =None 


        if pkt .haslayer (IP ):
            src_ip =pkt [IP ].src 
            dst_ip =pkt [IP ].dst 
        elif pkt .haslayer (IPv6 ):
            src_ip =pkt [IPv6 ].src 
            dst_ip =pkt [IPv6 ].dst 
        elif pkt .haslayer (ARP ):
            src_ip =pkt [ARP ].psrc 
            dst_ip =pkt [ARP ].pdst 
            protocol ="ARP"
            details =f"ARP Request/Reply: {src_ip } -> {dst_ip }"

        direction =self .determine_direction (src_ip ,dst_ip )


        if pkt .haslayer (TCP ):
            src_port =pkt [TCP ].sport 
            dst_port =pkt [TCP ].dport 
            raw_flags ,flag_name =self .parse_tcp_flags (pkt [TCP ].flags )
            tcp_flags_str =flag_name 

            if src_port ==80 or dst_port ==80 :
                protocol ="HTTP"
            elif src_port ==443 or dst_port ==443 :
                protocol ="HTTPS"
            else :
                protocol ="TCP"

            details =f"TCP {src_ip }:{src_port } -> {dst_ip }:{dst_port } [{flag_name }]"


            if raw_flags ==""or raw_flags =="0":
                anomaly_flag ="ABNORMAL_TCP_FLAGS (NULL Scan)"
            elif "F"in raw_flags and "P"in raw_flags and "U"in raw_flags :
                anomaly_flag ="ABNORMAL_TCP_FLAGS (Xmas Scan)"
            elif "S"in raw_flags and "F"in raw_flags :
                anomaly_flag ="ABNORMAL_TCP_FLAGS (SYN-FIN)"
            elif raw_flags =="S":
                if dst_port in self .SUSPICIOUS_PORTS :
                    service =self .SUSPICIOUS_PORTS [dst_port ]
                    anomaly_flag =f"POSSIBLE_SYN_SCAN (Port {dst_port }/{service })"
                elif direction =="INCOMING":
                    anomaly_flag ="POSSIBLE_SYN_SCAN"

        elif pkt .haslayer (UDP ):
            src_port =pkt [UDP ].sport 
            dst_port =pkt [UDP ].dport 
            if src_port ==53 or dst_port ==53 or pkt .haslayer (DNS ):
                protocol ="DNS"
                if pkt .haslayer (DNSQR ):
                    qname =pkt [DNSQR ].qname .decode (errors ="ignore")
                    details =f"DNS Query for '{qname }'"
                else :
                    details =f"DNS Response {src_ip } -> {dst_ip }"
            else :
                protocol ="UDP"
                details =f"UDP {src_ip }:{src_port } -> {dst_ip }:{dst_port }"

        elif pkt .haslayer (ICMP ):
            protocol ="ICMP"
            icmp_type =pkt [ICMP ].type 
            icmp_code =pkt [ICMP ].code 
            if icmp_type ==8 :
                details =f"ICMP Echo Request (Ping) {src_ip } -> {dst_ip }"
                if len (pkt )>200 :
                    anomaly_flag ="LARGE_ICMP_PAYLOAD"
            elif icmp_type ==0 :
                details =f"ICMP Echo Reply (Pong) {src_ip } -> {dst_ip }"
            else :
                details =f"ICMP Type {icmp_type } Code {icmp_code }: {src_ip } -> {dst_ip }"

        return AnalyzedPacket (
        timestamp =getattr (pkt ,"time",0.0 ),
        src_ip =src_ip ,
        dst_ip =dst_ip ,
        src_port =src_port ,
        dst_port =dst_port ,
        protocol =protocol ,
        direction =direction ,
        length =len (pkt ),
        tcp_flags_str =tcp_flags_str ,
        details =details ,
        anomaly_flag =anomaly_flag ,
        )
