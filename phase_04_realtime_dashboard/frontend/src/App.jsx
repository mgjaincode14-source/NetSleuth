import React, { useState, useEffect, useRef } from 'react';
import Navbar from './components/Navbar';
import MetricCards from './components/MetricCards';
import PPSChart from './components/PPSChart';
import ProtocolPie from './components/ProtocolPie';
import TopIPsTable from './components/TopIPsTable';
import PacketStream from './components/PacketStream';
import PacketModal from './components/PacketModal';

export default function App() {
  const [stats, setStats] = useState(null);
  const [packets, setPackets] = useState([]);
  const [ppsHistory, setPpsHistory] = useState([]);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const wsRef = useRef(null);

  useEffect(() => {
    connectWebSocket();
    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  const connectWebSocket = () => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/dashboard`;

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log('Connected to NetSleuth AI WebSocket');
      setIsConnected(true);
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'stats') {
          setStats(msg.data);
          // Append to PPS History
          const nowStr = new Date().toLocaleTimeString().split(' ')[0];
          setPpsHistory((prev) => {
            const next = [...prev, { time: nowStr, pps: msg.data.packets_per_second || 0 }];
            return next.slice(-30);
          });
        } else if (msg.type === 'packet') {
          setPackets((prev) => {
            const next = [...prev, msg.data];
            return next.slice(-200);
          });
        }
      } catch (e) {
        console.error('Error parsing WS message:', e);
      }
    };

    ws.onclose = () => {
      setIsConnected(false);
      // Reconnect after 3s
      setTimeout(connectWebSocket, 3000);
    };

    ws.onerror = (err) => {
      setIsConnected(false);
    };
  };

  const handleClear = async () => {
    try {
      await fetch('/api/v1/clear', { method: 'POST' });
      setPackets([]);
      setPpsHistory([]);
    } catch (e) {
      console.error('Clear failed:', e);
    }
  };

  const anomalyCount = packets.filter((p) => !!p.anomaly_tag).length;

  return (
    <div className="breeze-app">
      <Navbar
        stats={stats}
        isConnected={isConnected}
        onClear={handleClear}
      />

      <main className="breeze-container">
        {/* KPI Infographic Cards */}
        <MetricCards stats={stats} anomalyCount={anomalyCount} />

        {/* Real-time Charts Row */}
        <div className="breeze-dashboard-row">
          <PPSChart ppsHistory={ppsHistory} />
          <ProtocolPie protocolCounts={stats?.protocol_counts || {}} />
        </div>

        {/* Top Talkers & Live Stream Grid */}
        <div className="breeze-table-grid">
          <TopIPsTable packets={packets} />
          <PacketStream packets={packets} onSelectPacket={(p) => setSelectedPacket(p)} />
        </div>
      </main>

      {/* Packet Inspector Modal */}
      {selectedPacket && (
        <PacketModal packet={selectedPacket} onClose={() => setSelectedPacket(null)} />
      )}
    </div>
  );
}
