"""
Phase 2: Packet Capture Engine
Provides live asynchronous packet capture via Scapy with direction tracking and simulator fallback.
"""

import time 
import threading 
from collections import deque ,Counter 
from typing import Callable ,List ,Dict ,Optional ,Any 
from pydantic import BaseModel ,Field 
from scapy .all import AsyncSniffer ,Packet ,IP ,IPv6 ,TCP ,UDP ,ICMP ,ARP ,DNS 

from phase_02_packet_capture_engine .interface_manager import InterfaceManager 
from phase_02_packet_capture_engine .traffic_simulator import TrafficSimulator 
from phase_02_packet_capture_engine .protocol_analyzer import ProtocolAnalyzer ,AnalyzedPacket 


class CaptureStats (BaseModel ):
    """Real-time capture metrics and statistics."""
    total_packets :int =0 
    total_bytes :int =0 
    incoming_packets :int =0 
    outgoing_packets :int =0 
    local_packets :int =0 
    incoming_bytes :int =0 
    outgoing_bytes :int =0 
    packets_per_second :float =0.0 
    bytes_per_second :float =0.0 
    protocol_counts :Dict [str ,int ]=Field (default_factory =dict )
    is_running :bool =False 
    is_paused :bool =False 
    active_interface :Optional [str ]=None 
    bpf_filter :Optional [str ]=None 
    elapsed_seconds :float =0.0 
    simulation_mode :bool =False 


class PacketCaptureEngine :
    """
    High-performance, thread-safe network packet capture engine.
    Tracks packet directions (Incoming/Outgoing), TCP flag patterns, and supports live sniffing & simulation.
    """

    def __init__ (
    self ,
    interface :Optional [str ]=None ,
    bpf_filter :Optional [str ]=None ,
    max_buffer_size :int =10000 ,
    simulation_mode :bool =False ,
    ):
        self .interface =interface 
        self .bpf_filter =bpf_filter 
        self .max_buffer_size =max_buffer_size 
        self .simulation_mode =simulation_mode 


        self .local_ips :List [str ]=self ._discover_local_ips ()
        self .analyzer =ProtocolAnalyzer (local_ips =self .local_ips )


        self ._buffer :deque =deque (maxlen =max_buffer_size )
        self ._analyzed_buffer :deque =deque (maxlen =max_buffer_size )
        self ._lock =threading .Lock ()


        self ._subscribers :List [Callable [[Packet ],None ]]=[]


        self ._sniffer :Optional [AsyncSniffer ]=None 
        self ._simulator :Optional [TrafficSimulator ]=None 
        self .is_running :bool =False 
        self .is_paused :bool =False 
        self .start_time :Optional [float ]=None 
        self .total_packets :int =0 
        self .total_bytes :int =0 
        self .incoming_packets :int =0 
        self .outgoing_packets :int =0 
        self .local_packets :int =0 
        self .incoming_bytes :int =0 
        self .outgoing_bytes :int =0 
        self .protocol_counts :Counter =Counter ()


        self ._rate_window :deque =deque (maxlen =1000 )

    def _discover_local_ips (self )->List [str ]:
        """Collect IPv4 and IPv6 addresses belonging to local interfaces."""
        ips =["127.0.0.1","::1"]
        try :
            for iface in InterfaceManager .get_all_interfaces ():
                ips .extend (iface .ipv4_addresses )
                ips .extend (iface .ipv6_addresses )
        except Exception :
            pass 
        return list (set (ips ))

    def add_subscriber (self ,callback :Callable [[Packet ],None ]):
        """Subscribe a callback to be called on every captured packet."""
        if callback not in self ._subscribers :
            self ._subscribers .append (callback )

    def remove_subscriber (self ,callback :Callable [[Packet ],None ]):
        """Remove a subscriber callback."""
        if callback in self ._subscribers :
            self ._subscribers .remove (callback )

    def _on_packet_received (self ,pkt :Packet ):
        """Internal callback invoked for each packet captured."""
        if not self .is_running or self .is_paused :
            return 

        now =time .time ()
        pkt_len =len (pkt )


        analyzed =self .analyzer .analyze (pkt )

        with self ._lock :
            self .total_packets +=1 
            self .total_bytes +=pkt_len 
            self .protocol_counts [analyzed .protocol ]+=1 

            if analyzed .direction =="INCOMING":
                self .incoming_packets +=1 
                self .incoming_bytes +=pkt_len 
            elif analyzed .direction =="OUTGOING":
                self .outgoing_packets +=1 
                self .outgoing_bytes +=pkt_len 
            else :
                self .local_packets +=1 

            self ._buffer .append (pkt )
            self ._analyzed_buffer .append (analyzed )
            self ._rate_window .append ((now ,pkt_len ))


        for subscriber in self ._subscribers :
            try :
                subscriber (pkt )
            except Exception :
                pass 

    def start (
    self ,
    interface :Optional [str ]=None ,
    bpf_filter :Optional [str ]=None ,
    packet_limit :Optional [int ]=None ,
    promiscuous :bool =True ,
    simulate_if_permission_denied :bool =False ,
    ):
        """
        Start capturing packets asynchronously.
        Attempts live real-time network sniffing by default.
        """
        if self .is_running :
            return 

        if interface :
            self .interface =interface 
        if bpf_filter is not None :
            self .bpf_filter =bpf_filter 

        if not self .interface and not self .simulation_mode :
            default_iface =InterfaceManager .get_default_interface ()
            self .interface =default_iface .name if default_iface else "lo"

        self .is_running =True 
        self .is_paused =False 
        self .start_time =time .time ()

        if self .simulation_mode :
            self ._start_simulation (packet_limit )
            return 


        try :
            kwargs :Dict [str ,Any ]={
            "prn":self ._on_packet_received ,
            "store":False ,
            "promisc":promiscuous ,
            }
            if self .interface :
                kwargs ["iface"]=self .interface 
            if self .bpf_filter :
                kwargs ["filter"]=self .bpf_filter 
            if packet_limit :
                kwargs ["count"]=packet_limit 

            self ._sniffer =AsyncSniffer (**kwargs )
            self ._sniffer .start ()
        except (PermissionError ,OSError )as e :
            if simulate_if_permission_denied :
                self .simulation_mode =True 
                self ._start_simulation (packet_limit )
            else :
                self .is_running =False 
                raise PermissionError (
                f"Real-time packet capture on interface '{self .interface }' failed: {e }.\n"
                f"Raw socket sniffing requires root privileges on Linux.\n"
                f"Run with sudo: sudo ./venv/bin/python phase_02_packet_capture_engine/run_capture.py\n"
                f"Or pass --simulate to run synthetic traffic generator."
                )

    def _start_simulation (self ,packet_limit :Optional [int ]=None ):
        """Start the synthetic traffic simulator."""
        self ._simulator =TrafficSimulator (packet_callback =self ._on_packet_received )
        self ._simulator .start_simulation (packets_per_second =25.0 ,total_packets =packet_limit )

    def pause (self ):
        """Pause packet intake."""
        self .is_paused =True 

    def resume (self ):
        """Resume packet intake."""
        self .is_paused =False 

    def stop (self ):
        """Stop capture engine and cleanup background threads."""
        self .is_running =False 
        self .is_paused =False 

        if self ._sniffer and self ._sniffer .running :
            try :
                self ._sniffer .stop ()
            except Exception :
                pass 
            self ._sniffer =None 

        if self ._simulator :
            self ._simulator .stop_simulation ()
            self ._simulator =None 

    def get_stats (self )->CaptureStats :
        """Calculate and return real-time capture metrics including directions."""
        now =time .time ()
        elapsed =(now -self .start_time )if self .start_time else 0.0 

        window_cutoff =now -1.5 
        with self ._lock :
            recent_entries =[entry for entry in self ._rate_window if entry [0 ]>=window_cutoff ]
            while self ._rate_window and self ._rate_window [0 ][0 ]<(now -5.0 ):
                self ._rate_window .popleft ()

            window_duration =max (0.5 ,(now -recent_entries [0 ][0 ]))if recent_entries else 1.0 
            pps =len (recent_entries )/window_duration if recent_entries else 0.0 
            bps =sum (entry [1 ]for entry in recent_entries )/window_duration if recent_entries else 0.0 

            stats =CaptureStats (
            total_packets =self .total_packets ,
            total_bytes =self .total_bytes ,
            incoming_packets =self .incoming_packets ,
            outgoing_packets =self .outgoing_packets ,
            local_packets =self .local_packets ,
            incoming_bytes =self .incoming_bytes ,
            outgoing_bytes =self .outgoing_bytes ,
            packets_per_second =round (pps ,2 ),
            bytes_per_second =round (bps ,2 ),
            protocol_counts =dict (self .protocol_counts ),
            is_running =self .is_running ,
            is_paused =self .is_paused ,
            active_interface =self .interface ,
            bpf_filter =self .bpf_filter ,
            elapsed_seconds =round (elapsed ,1 ),
            simulation_mode =self .simulation_mode ,
            )
        return stats 

    def get_buffered_packets (self ,limit :int =100 )->List [Packet ]:
        """Return the latest N raw packets."""
        with self ._lock :
            if limit >=len (self ._buffer ):
                return list (self ._buffer )
            return list (self ._buffer )[-limit :]

    def get_analyzed_packets (self ,limit :int =100 )->List [AnalyzedPacket ]:
        """Return the latest N analyzed packets with directions, flags, and anomaly flags."""
        with self ._lock :
            if limit >=len (self ._analyzed_buffer ):
                return list (self ._analyzed_buffer )
            return list (self ._analyzed_buffer )[-limit :]

    def clear_buffer (self ):
        """Reset captured buffer and counters."""
        with self ._lock :
            self ._buffer .clear ()
            self ._analyzed_buffer .clear ()
            self ._rate_window .clear ()
            self .total_packets =0 
            self .total_bytes =0 
            self .incoming_packets =0 
            self .outgoing_packets =0 
            self .local_packets =0 
            self .incoming_bytes =0 
            self .outgoing_bytes =0 
            self .protocol_counts .clear ()
            self .start_time =time .time ()if self .is_running else None 
