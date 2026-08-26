"""
Unit tests for Phase 2: Network Interface Manager
"""

import pytest 
from phase_02_packet_capture_engine .interface_manager import InterfaceManager ,InterfaceInfo 


def test_get_all_interfaces ():
    interfaces =InterfaceManager .get_all_interfaces ()
    assert isinstance (interfaces ,list )
    assert len (interfaces )>0 


    for iface in interfaces :
        assert isinstance (iface ,InterfaceInfo )
        assert isinstance (iface .name ,str )
        assert len (iface .name )>0 
        assert isinstance (iface .is_up ,bool )
        assert isinstance (iface .ipv4_addresses ,list )
        assert isinstance (iface .ipv6_addresses ,list )


def test_default_interface ():
    default_iface =InterfaceManager .get_default_interface ()
    assert default_iface is not None 
    assert isinstance (default_iface ,InterfaceInfo )
    assert default_iface .name in [i .name for i in InterfaceManager .get_all_interfaces ()]


def test_loopback_detection ():
    interfaces =InterfaceManager .get_all_interfaces ()
    loopback_found =any (iface .is_loopback for iface in interfaces )
    assert loopback_found ,"Loopback interface 'lo' should be detected."
