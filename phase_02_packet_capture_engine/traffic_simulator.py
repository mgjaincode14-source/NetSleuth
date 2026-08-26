"""
Phase 2: Traffic Simulator & Packet Generator
Generates realistic network packets and attack simulations for testing and development.
"""

import random 
import time 
import threading 
from typing import Callable ,Optional 
from scapy .all import IP ,IPv6 ,TCP ,UDP ,ICMP ,DNS ,DNSQR ,DNSRR ,Ether ,Raw 


class TrafficSimulator :
    """Generates synthetic network packets for normal traffic and threat scenarios."""

    COMMON_DOMAINS =[
    "google.com","github.com","cloudflare.com","openai.com",
    "api.netsleuth.ai","netflix.com","aws.amazon.com","wikipedia.org"
    ]

    INTERNAL_SUBNET ="192.168.1."
    EXTERNAL_IPS =[
    "8.8.8.8","1.1.1.1","142.250.190.46","140.82.121.3",
    "104.16.132.229","185.199.108.153"
    ]

    def __init__ (self ,packet_callback :Optional [Callable ]=None ):
        self .packet_callback =packet_callback 
        self .is_running =False 
        self ._thread :Optional [threading .Thread ]=None 
        self .packets_generated =0 

    def generate_random_ip (self ,internal :bool =False )->str :
        if internal :
            return f"{self .INTERNAL_SUBNET }{random .randint (10 ,250 )}"
        return f"{random .randint (11 ,220 )}.{random .randint (1 ,254 )}.{random .randint (1 ,254 )}.{random .randint (1 ,254 )}"

    def generate_http_packet (self )->IP :
        """Simulate an HTTP request or response packet."""
        src_ip =self .generate_random_ip (internal =True )
        dst_ip =random .choice (self .EXTERNAL_IPS )
        src_port =random .randint (30000 ,65000 )
        dst_port =80 

        method =random .choice (["GET","POST","HEAD"])
        domain =random .choice (self .COMMON_DOMAINS )
        path =random .choice (["/","/index.html","/api/v1/status","/login","/search?q=packet"])
        http_payload =f"{method } {path } HTTP/1.1\r\nHost: {domain }\r\nUser-Agent: NetSleuth/1.0\r\n\r\n"

        pkt =(
        IP (src =src_ip ,dst =dst_ip )
        /TCP (sport =src_port ,dport =dst_port ,flags ="PA",seq =random .randint (1000 ,99999 ))
        /Raw (load =http_payload .encode ())
        )
        return pkt 

    def generate_https_packet (self )->IP :
        """Simulate an HTTPS / TLS encrypted packet."""
        src_ip =self .generate_random_ip (internal =True )
        dst_ip =random .choice (self .EXTERNAL_IPS )
        src_port =random .randint (30000 ,65000 )
        dst_port =443 

        flags =random .choice (["A","PA","FA"])
        pkt =(
        IP (src =src_ip ,dst =dst_ip )
        /TCP (sport =src_port ,dport =dst_port ,flags =flags )
        /Raw (load =b"\x16\x03\x01\x00\xa0"+random .randbytes (random .randint (40 ,200 )))
        )
        return pkt 

    def generate_dns_packet (self )->IP :
        """Simulate a DNS query or response."""
        src_ip =self .generate_random_ip (internal =True )
        dst_ip ="8.8.8.8"
        src_port =random .randint (30000 ,65000 )
        domain =random .choice (self .COMMON_DOMAINS )

        if random .random ()>0.4 :

            pkt =(
            IP (src =src_ip ,dst =dst_ip )
            /UDP (sport =src_port ,dport =53 )
            /DNS (rd =1 ,qd =DNSQR (qname =domain ,qtype ="A"))
            )
        else :

            pkt =(
            IP (src =dst_ip ,dst =src_ip )
            /UDP (sport =53 ,dport =src_port )
            /DNS (
            qr =1 ,
            aa =1 ,
            qd =DNSQR (qname =domain ,qtype ="A"),
            an =DNSRR (rrname =domain ,rdata =random .choice (self .EXTERNAL_IPS )),
            )
            )
        return pkt 

    def generate_icmp_packet (self )->IP :
        """Simulate an ICMP Ping Echo Request or Reply."""
        src_ip =self .generate_random_ip (internal =True )
        dst_ip =random .choice (self .EXTERNAL_IPS )
        is_request =random .choice ([True ,False ])

        if is_request :
            pkt =IP (src =src_ip ,dst =dst_ip )/ICMP (type =8 ,code =0 )/Raw (load =b"NetSleuth Ping Test")
        else :
            pkt =IP (src =dst_ip ,dst =src_ip )/ICMP (type =0 ,code =0 )/Raw (load =b"NetSleuth Ping Reply")
        return pkt 

    def generate_port_scan_packet (self ,attacker_ip :str ="192.168.1.188",target_ip :str ="192.168.1.50",port :int =80 )->IP :
        """Simulate a TCP SYN Port Scan probe."""
        return IP (src =attacker_ip ,dst =target_ip )/TCP (sport =random .randint (40000 ,65000 ),dport =port ,flags ="S")

    def generate_syn_flood_packet (self ,target_ip :str ="192.168.1.50",target_port :int =80 )->IP :
        """Simulate a SYN Flood attack packet with spoofed source IP."""
        spoofed_src =self .generate_random_ip (internal =False )
        return IP (src =spoofed_src ,dst =target_ip )/TCP (sport =random .randint (1024 ,65535 ),dport =target_port ,flags ="S")

    def generate_random_packet (self )->IP :
        """Generate a random normal or attack packet based on weighted probabilities."""
        r =random .random ()
        if r <0.35 :
            return self .generate_https_packet ()
        elif r <0.60 :
            return self .generate_http_packet ()
        elif r <0.80 :
            return self .generate_dns_packet ()
        elif r <0.90 :
            return self .generate_icmp_packet ()
        elif r <0.96 :
            return self .generate_port_scan_packet (port =random .randint (20 ,1024 ))
        else :
            return self .generate_syn_flood_packet ()

    def start_simulation (self ,packets_per_second :float =20.0 ,total_packets :Optional [int ]=None ):
        """Start generating packets in a background thread."""
        if self .is_running :
            return 

        self .is_running =True 
        self .packets_generated =0 

        def _worker ():
            interval =1.0 /max (1.0 ,packets_per_second )
            while self .is_running :
                pkt =self .generate_random_packet ()
                self .packets_generated +=1 

                if self .packet_callback :
                    try :
                        self .packet_callback (pkt )
                    except Exception :
                        pass 

                if total_packets and self .packets_generated >=total_packets :
                    self .is_running =False 
                    break 

                time .sleep (interval )

        self ._thread =threading .Thread (target =_worker ,daemon =True )
        self ._thread .start ()

    def stop_simulation (self ):
        """Stop packet generation."""
        self .is_running =False 
        if self ._thread and self ._thread .is_alive ():
            self ._thread .join (timeout =1.0 )


if __name__ =="__main__":
    from rich .console import Console 
    console =Console ()

    sim =TrafficSimulator ()
    console .print ("[bold cyan]Simulating 5 Sample Packets:[/bold cyan]\n")

    for i in range (5 ):
        pkt =sim .generate_random_packet ()
        console .print (f"[{i +1 }] {pkt .summary ()}")
