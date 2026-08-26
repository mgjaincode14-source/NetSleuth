"""
Unit tests for Phase 2: Packet Capture Engine
"""

import time 
import pytest 
from phase_02_packet_capture_engine .capture_engine import PacketCaptureEngine 


def test_capture_engine_initial_state ():
    engine =PacketCaptureEngine (interface ="lo")
    stats =engine .get_stats ()
    assert stats .total_packets ==0 
    assert stats .is_running is False 
    assert stats .is_paused is False 
    assert stats .active_interface =="lo"


def test_capture_engine_simulation_start_stop ():
    engine =PacketCaptureEngine (simulation_mode =True )
    engine .start (packet_limit =20 )
    assert engine .is_running is True 


    time .sleep (0.5 )

    stats =engine .get_stats ()
    assert stats .total_packets >0 
    assert stats .total_bytes >0 
    assert stats .packets_per_second >=0.0 

    buffered =engine .get_buffered_packets (limit =10 )
    assert len (buffered )>0 

    engine .stop ()
    assert engine .is_running is False 


def test_capture_engine_pause_resume ():
    engine =PacketCaptureEngine (simulation_mode =True )
    engine .start ()

    time .sleep (0.2 )
    engine .pause ()
    assert engine .is_paused is True 

    count_after_pause =engine .total_packets 
    time .sleep (0.2 )

    assert engine .total_packets ==count_after_pause 

    engine .resume ()
    assert engine .is_paused is False 
    time .sleep (0.2 )
    assert engine .total_packets >=count_after_pause 

    engine .stop ()


def test_capture_engine_subscriber ():
    received_packets =[]

    def subscriber (pkt ):
        received_packets .append (pkt )

    engine =PacketCaptureEngine (simulation_mode =True )
    engine .add_subscriber (subscriber )
    engine .start (packet_limit =5 )

    time .sleep (0.3 )
    engine .stop ()

    assert len (received_packets )>0 


def test_capture_engine_clear_buffer ():
    engine =PacketCaptureEngine (simulation_mode =True )
    engine .start ()
    time .sleep (0.2 )
    engine .stop ()

    assert engine .total_packets >0 
    engine .clear_buffer ()
    assert engine .total_packets ==0 
    assert len (engine .get_buffered_packets ())==0 
