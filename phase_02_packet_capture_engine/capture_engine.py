"""
Phase 2: Packet Capture Engine
Provides live asynchronous packet capture via Scapy and synthetic simulation fallback.
"""

import time
import threading
from collections import deque, Counter
from typing import Callable, List, Dict, Optional, Any
from pydantic import BaseModel, Field
from scapy.all import AsyncSniffer, Packet, IP, IPv6, TCP, UDP, ICMP, ARP, DNS

from phase_02_packet_capture_engine.interface_manager import InterfaceManager
from phase_02_packet_capture_engine.traffic_simulator import TrafficSimulator


class CaptureStats(BaseModel):
    """Real-time capture metrics and statistics."""
    total_packets: int = 0
    total_bytes: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    protocol_counts: Dict[str, int] = Field(default_factory=dict)
    is_running: bool = False
    is_paused: bool = False
    active_interface: Optional[str] = None
    bpf_filter: Optional[str] = None
    elapsed_seconds: float = 0.0
    simulation_mode: bool = False


class PacketCaptureEngine:
    """
    High-performance, thread-safe network packet capture engine.
    Supports live interface sniffing with BPF filters and seamless simulator fallback.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        max_buffer_size: int = 10000,
        simulation_mode: bool = False,
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.max_buffer_size = max_buffer_size
        self.simulation_mode = simulation_mode

        # Packet storage & sync
        self._buffer: deque = deque(maxlen=max_buffer_size)
        self._lock = threading.Lock()

        # Subscribers
        self._subscribers: List[Callable[[Packet], None]] = []

        # Internal state
        self._sniffer: Optional[AsyncSniffer] = None
        self._simulator: Optional[TrafficSimulator] = None
        self.is_running: bool = False
        self.is_paused: bool = False
        self.start_time: Optional[float] = None
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.protocol_counts: Counter = Counter()

        # Sliding window for PPS and BPS calculations
        self._rate_window: deque = deque(maxlen=1000)

    def add_subscriber(self, callback: Callable[[Packet], None]):
        """Subscribe a callback to be called on every captured packet."""
        if callback not in self._subscribers:
            self._subscribers.append(callback)

    def remove_subscriber(self, callback: Callable[[Packet], None]):
        """Remove a subscriber callback."""
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    def _classify_protocol(self, pkt: Packet) -> str:
        """Identify high-level protocol for quick stats counting."""
        if pkt.haslayer(DNS):
            return "DNS"
        elif pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            if sport == 80 or dport == 80:
                return "HTTP"
            elif sport == 443 or dport == 443:
                return "HTTPS"
            return "TCP"
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            if sport == 53 or dport == 53:
                return "DNS"
            return "UDP"
        elif pkt.haslayer(ICMP):
            return "ICMP"
        elif pkt.haslayer(ARP):
            return "ARP"
        return "OTHER"

    def _on_packet_received(self, pkt: Packet):
        """Internal callback invoked for each packet captured."""
        if not self.is_running or self.is_paused:
            return

        now = time.time()
        pkt_len = len(pkt)

        with self._lock:
            self.total_packets += 1
            self.total_bytes += pkt_len
            proto = self._classify_protocol(pkt)
            self.protocol_counts[proto] += 1
            self._buffer.append(pkt)
            self._rate_window.append((now, pkt_len))

        # Notify subscribers
        for subscriber in self._subscribers:
            try:
                subscriber(pkt)
            except Exception:
                pass

    def start(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        packet_limit: Optional[int] = None,
        promiscuous: bool = True,
        simulate_if_permission_denied: bool = True,
    ):
        """
        Start capturing packets asynchronously.
        If live sniffing fails due to socket permissions, fallback to simulation if enabled.
        """
        if self.is_running:
            return

        if interface:
            self.interface = interface
        if bpf_filter is not None:
            self.bpf_filter = bpf_filter

        if not self.interface and not self.simulation_mode:
            default_iface = InterfaceManager.get_default_interface()
            self.interface = default_iface.name if default_iface else "lo"

        self.is_running = True
        self.is_paused = False
        self.start_time = time.time()

        if self.simulation_mode:
            self._start_simulation(packet_limit)
            return

        # Attempt live Scapy capture
        try:
            kwargs: Dict[str, Any] = {
                "prn": self._on_packet_received,
                "store": False,
                "promisc": promiscuous,
            }
            if self.interface:
                kwargs["iface"] = self.interface
            if self.bpf_filter:
                kwargs["filter"] = self.bpf_filter
            if packet_limit:
                kwargs["count"] = packet_limit

            self._sniffer = AsyncSniffer(**kwargs)
            self._sniffer.start()
        except (PermissionError, OSError) as e:
            if simulate_if_permission_denied:
                self.simulation_mode = True
                self._start_simulation(packet_limit)
            else:
                self.is_running = False
                raise RuntimeError(
                    f"Live packet capture requires root/CAP_NET_RAW privileges: {e}. "
                    f"Set simulation_mode=True to test without root."
                )

    def _start_simulation(self, packet_limit: Optional[int] = None):
        """Start the synthetic traffic simulator."""
        self._simulator = TrafficSimulator(packet_callback=self._on_packet_received)
        self._simulator.start_simulation(packets_per_second=25.0, total_packets=packet_limit)

    def pause(self):
        """Temporarily pause packet intake without resetting stats."""
        self.is_paused = True

    def resume(self):
        """Resume packet intake."""
        self.is_paused = False

    def stop(self):
        """Stop packet capture engine and cleanup threads."""
        self.is_running = False
        self.is_paused = False

        if self._sniffer and self._sniffer.running:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

        if self._simulator:
            self._simulator.stop_simulation()
            self._simulator = None

    def get_stats(self) -> CaptureStats:
        """Calculate and return real-time capture metrics."""
        now = time.time()
        elapsed = (now - self.start_time) if self.start_time else 0.0

        # Calculate rate over the last 1.5 seconds from sliding window
        window_cutoff = now - 1.5
        with self._lock:
            recent_entries = [entry for entry in self._rate_window if entry[0] >= window_cutoff]
            # Prune old window entries
            while self._rate_window and self._rate_window[0][0] < (now - 5.0):
                self._rate_window.popleft()

            window_duration = max(0.5, (now - recent_entries[0][0])) if recent_entries else 1.0
            pps = len(recent_entries) / window_duration if recent_entries else 0.0
            bps = sum(entry[1] for entry in recent_entries) / window_duration if recent_entries else 0.0

            stats = CaptureStats(
                total_packets=self.total_packets,
                total_bytes=self.total_bytes,
                packets_per_second=round(pps, 2),
                bytes_per_second=round(bps, 2),
                protocol_counts=dict(self.protocol_counts),
                is_running=self.is_running,
                is_paused=self.is_paused,
                active_interface=self.interface,
                bpf_filter=self.bpf_filter,
                elapsed_seconds=round(elapsed, 1),
                simulation_mode=self.simulation_mode,
            )
        return stats

    def get_buffered_packets(self, limit: int = 100) -> List[Packet]:
        """Return the latest N raw packets from the ring buffer."""
        with self._lock:
            if limit >= len(self._buffer):
                return list(self._buffer)
            return list(self._buffer)[-limit:]

    def clear_buffer(self):
        """Reset captured buffer and counters."""
        with self._lock:
            self._buffer.clear()
            self._rate_window.clear()
            self.total_packets = 0
            self.total_bytes = 0
            self.protocol_counts.clear()
            self.start_time = time.time() if self.is_running else None
