"""
Phase 2: Network Interface Manager
Discovers and inspects all available physical and virtual network interfaces.
"""

import socket 
import psutil 
from typing import List ,Dict ,Optional 
from pydantic import BaseModel 
from scapy .all import get_if_list ,conf 


class InterfaceInfo (BaseModel ):
    name :str 
    description :Optional [str ]=None 
    mac_address :Optional [str ]=None 
    ipv4_addresses :List [str ]=[]
    ipv6_addresses :List [str ]=[]
    is_up :bool =False 
    speed_mbps :int =0 
    mtu :int =1500 
    is_loopback :bool =False 


class InterfaceManager :
    """Manages discovery and inspection of network interfaces."""

    @staticmethod 
    def get_all_interfaces ()->List [InterfaceInfo ]:
        """Retrieve comprehensive metadata for all detected network interfaces."""
        interfaces :Dict [str ,InterfaceInfo ]={}


        scapy_ifaces =set ()
        try :
            scapy_ifaces =set (get_if_list ())
        except Exception :
            pass 


        net_addrs =psutil .net_if_addrs ()
        net_stats =psutil .net_if_stats ()


        all_iface_names =set (net_addrs .keys ()).union (scapy_ifaces )

        for iface_name in sorted (all_iface_names ):
            is_up =False 
            speed =0 
            mtu =1500 

            if iface_name in net_stats :
                stat =net_stats [iface_name ]
                is_up =stat .isup 
                speed =stat .speed 
                mtu =stat .mtu 

            is_loopback =(
            iface_name =="lo"
            or iface_name .startswith ("loopback")
            or "127.0.0.1"in [s .address for s in net_addrs .get (iface_name ,[])]
            )

            ipv4_list =[]
            ipv6_list =[]
            mac_addr =None 

            if iface_name in net_addrs :
                for snic in net_addrs [iface_name ]:
                    if snic .family ==socket .AF_INET :
                        ipv4_list .append (snic .address )
                    elif snic .family ==socket .AF_INET6 :

                        ipv6_clean =snic .address .split ("%")[0 ]
                        ipv6_list .append (ipv6_clean )
                    elif hasattr (psutil ,"AF_LINK")and snic .family ==psutil .AF_LINK :
                        mac_addr =snic .address 

            info =InterfaceInfo (
            name =iface_name ,
            description =f"Interface {iface_name } ({'UP'if is_up else 'DOWN'})",
            mac_address =mac_addr ,
            ipv4_addresses =ipv4_list ,
            ipv6_addresses =ipv6_list ,
            is_up =is_up ,
            speed_mbps =speed ,
            mtu =mtu ,
            is_loopback =is_loopback ,
            )
            interfaces [iface_name ]=info 

        return list (interfaces .values ())

    @classmethod 
    def get_default_interface (cls )->Optional [InterfaceInfo ]:
        """Find the best active non-loopback interface with an IPv4 address, or fallback to loopback."""
        all_ifaces =cls .get_all_interfaces ()


        for iface in all_ifaces :
            if iface .is_up and not iface .is_loopback and len (iface .ipv4_addresses )>0 :
                return iface 


        for iface in all_ifaces :
            if iface .is_up and not iface .is_loopback :
                return iface 


        for iface in all_ifaces :
            if iface .is_loopback :
                return iface 

        return all_ifaces [0 ]if all_ifaces else None 


if __name__ =="__main__":
    print ("="*80 )
    print ("NetSleuth AI - Detected Network Interfaces")
    print ("="*80 )
    print (f"{'Interface':<12} | {'Status':<6} | {'MAC Address':<18} | {'IPv4 Addresses':<18} | {'Type'}")
    print ("-"*80 )

    for iface in InterfaceManager .get_all_interfaces ():
        status ="UP"if iface .is_up else "DOWN"
        ipv4s =", ".join (iface .ipv4_addresses )if iface .ipv4_addresses else "-"
        mac =iface .mac_address or "-"
        itype ="Loopback"if iface .is_loopback else "Physical/Virtual"
        print (f"{iface .name :<12} | {status :<6} | {mac :<18} | {ipv4s :<18} | {itype }")

    print ("="*80 )
    default =InterfaceManager .get_default_interface ()
    print (f"Recommended Interface for Capture: {default .name if default else 'None'}")

