"""
Phase 2: Terminal UI & Capture Monitor
Provides plain-text output displaying live metrics, packet directions (Incoming/Outgoing),
protocol breakdown, and Protocol Analyzer details with TCP flags & anomaly detection.
"""

import os 
import sys 
import time 
import argparse 
from typing import Optional 

from phase_02_packet_capture_engine .capture_engine import PacketCaptureEngine 


def format_bytes (bytes_val :float )->str :
    """Format bytes per second into human-readable B/s, KB/s, or MB/s."""
    if bytes_val <1024 :
        return f"{bytes_val :.1f} B/s"
    elif bytes_val <1024 *1024 :
        return f"{bytes_val /1024 :.1f} KB/s"
    else :
        return f"{bytes_val /(1024 *1024 ):.2f} MB/s"


def format_total_bytes (bytes_val :int )->str :
    """Format total volume."""
    if bytes_val <1024 :
        return f"{bytes_val } B"
    elif bytes_val <1024 *1024 :
        return f"{bytes_val /1024 :.1f} KB"
    else :
        return f"{bytes_val /(1024 *1024 ):.2f} MB"


def render_plain_dashboard (engine :PacketCaptureEngine ,max_packets_to_show :int =8 )->str :
    """Render full metrics, packet directions, protocol breakdown, and Protocol Analyzer in plain text."""
    stats =engine .get_stats ()
    status_str ="PAUSED"if stats .is_paused else "RUNNING"
    mode_str ="Simulation"if stats .simulation_mode else "Live Real-Time"

    lines =[]
    lines .append ("="*95 )
    lines .append ("NetSleuth AI - Phase 2: Packet Capture Engine & Protocol Analyzer")
    lines .append (f"Interface: {stats .active_interface or 'Auto-Detect'} | Mode: {mode_str } | Filter: {stats .bpf_filter or 'None'}")
    lines .append ("="*95 )


    total_p =max (1 ,stats .total_packets )
    in_pct =(stats .incoming_packets /total_p )*100 
    out_pct =(stats .outgoing_packets /total_p )*100 

    lines .append ("[TRAFFIC METRICS & PACKET DIRECTIONS]")
    lines .append (
    f"  Status:            {status_str :<12}  Elapsed Time:     {stats .elapsed_seconds :.1f}s\n"
    f"  Total Packets:     {stats .total_packets :<12}  Packet Rate:      {stats .packets_per_second :.1f} pkts/s\n"
    f"  Incoming Packets:  {stats .incoming_packets :<12} ({in_pct :.1f}%)        Incoming Volume:  {format_total_bytes (stats .incoming_bytes )}\n"
    f"  Outgoing Packets:  {stats .outgoing_packets :<12} ({out_pct :.1f}%)        Outgoing Volume:  {format_total_bytes (stats .outgoing_bytes )}\n"
    f"  Total Volume:      {format_total_bytes (stats .total_bytes ):<12}  Bandwidth:        {format_bytes (stats .bytes_per_second )}"
    )
    lines .append ("")


    lines .append ("[PROTOCOL BREAKDOWN]")
    lines .append (f"  {'Protocol':<12} {'Count':<10} {'Share'}")
    lines .append ("  "+"-"*32 )
    if stats .protocol_counts :
        for proto ,count in sorted (stats .protocol_counts .items (),key =lambda x :x [1 ],reverse =True ):
            pct =(count /total_p )*100 
            lines .append (f"  {proto :<12} {count :<10} {pct :.1f}%")
    else :
        lines .append ("  (No packets captured yet)")
    lines .append ("")


    lines .append ("[PROTOCOL ANALYZER & ANOMALY FLAGS]")
    lines .append (
    f"  {'Direction':<10} {'Source IP:Port':<24} {'Dest IP:Port':<24} {'Proto':<8} {'Flags/State':<12} {'Behavior / Anomaly Flag'}"
    )
    lines .append ("  "+"-"*90 )

    analyzed_list =engine .get_analyzed_packets (limit =max_packets_to_show )
    if analyzed_list :
        for item in analyzed_list [-max_packets_to_show :]:
            src_str =f"{item .src_ip }:{item .src_port }"if item .src_port else item .src_ip 
            dst_str =f"{item .dst_ip }:{item .dst_port }"if item .dst_port else item .dst_ip 
            flags_str =item .tcp_flags_str or "-"
            flag_alert =f"[{item .anomaly_flag }]"if item .anomaly_flag else "NORMAL"


            if len (src_str )>23 :
                src_str =src_str [:20 ]+"..."
            if len (dst_str )>23 :
                dst_str =dst_str [:20 ]+"..."

            lines .append (
            f"  {item .direction :<10} {src_str :<24} {dst_str :<24} {item .protocol :<8} {flags_str :<12} {flag_alert }"
            )
    else :
        lines .append ("  Listening for packets...")

    lines .append ("="*95 )
    return "\n".join (lines )


def run_cli (
interface :Optional [str ]=None ,
bpf_filter :Optional [str ]=None ,
simulation_mode :bool =False ,
duration :Optional [float ]=None ,
packet_limit :Optional [int ]=None ,
refresh_rate :float =0.5 ,
clear_screen :bool =True ,
fallback_on_permission_error :bool =False ,
):
    """Run real-time capture monitor in the terminal."""
    engine =PacketCaptureEngine (
    interface =interface ,
    bpf_filter =bpf_filter ,
    simulation_mode =simulation_mode ,
    )

    print ("Starting NetSleuth AI Capture Engine...")

    try :
        engine .start (
        interface =interface ,
        bpf_filter =bpf_filter ,
        packet_limit =packet_limit ,
        simulate_if_permission_denied =fallback_on_permission_error ,
        )
    except PermissionError as err :
        print ("\n"+"!"*80 )
        print ("REAL-TIME CAPTURE PERMISSION ERROR:")
        print (str (err ))
        print ("!"*80 +"\n")
        sys .exit (1 )

    start_time =time .time ()
    try :
        while engine .is_running :
            dashboard =render_plain_dashboard (engine )
            if clear_screen and sys .stdout .isatty ():
                print ("\033[2J\033[H"+dashboard ,flush =True )
            else :
                print (dashboard ,flush =True )

            time .sleep (refresh_rate )

            if duration and (time .time ()-start_time )>=duration :
                break 
            if packet_limit and engine .total_packets >=packet_limit :
                break 
    except KeyboardInterrupt :
        print ("\nStopping capture...")
    finally :
        engine .stop ()
        final_dashboard =render_plain_dashboard (engine )
        print ("\n"+final_dashboard )
        print ("Capture complete.")


if __name__ =="__main__":
    parser =argparse .ArgumentParser (description ="NetSleuth AI - Phase 2 Packet Capture CLI")
    parser .add_argument ("-i","--interface",type =str ,help ="Network interface (e.g. wlp8s0, lo)")
    parser .add_argument ("-f","--filter",type =str ,help ="BPF filter string (e.g. 'tcp port 80')")
    parser .add_argument ("-s","--simulate",action ="store_true",help ="Run in simulation mode")
    parser .add_argument ("-d","--duration",type =float ,help ="Duration to capture in seconds")
    parser .add_argument ("-c","--count",type =int ,help ="Maximum packet count to capture")
    parser .add_argument ("--no-clear",action ="store_true",help ="Do not clear screen between updates")
    parser .add_argument ("--auto-fallback",action ="store_true",help ="Automatically fallback to simulation if permission denied")
    args =parser .parse_args ()

    run_cli (
    interface =args .interface ,
    bpf_filter =args .filter ,
    simulation_mode =args .simulate ,
    duration =args .duration ,
    packet_limit =args .count ,
    clear_screen =not args .no_clear ,
    fallback_on_permission_error =args .auto_fallback ,
    )
