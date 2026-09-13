import React, { useState, useEffect } from 'react';
import { Shield, Play, Square, Activity, RefreshCw, Layers } from 'lucide-react';

export default function Navbar({ stats, onStart, onStop, onClear, isConnected }) {
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [simulationMode, setSimulationMode] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchInterfaces();
  }, []);

  const fetchInterfaces = async () => {
    try {
      const res = await fetch('/api/v1/interfaces');
      const data = await res.json();
      setInterfaces(data.interfaces || []);
      if (data.default) {
        setSelectedInterface(data.default);
      }
    } catch (e) {
      console.error('Failed to fetch interfaces:', e);
    }
  };

  const handleToggleCapture = async () => {
    setLoading(true);
    try {
      if (stats?.is_running) {
        await fetch('/api/v1/stop', { method: 'POST' });
        if (onStop) onStop();
      } else {
        await fetch('/api/v1/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            interface: selectedInterface,
            simulation_mode: simulationMode,
            auto_fallback: true,
          }),
        });
        if (onStart) onStart();
      }
    } catch (e) {
      alert('Capture control failed: ' + e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <header className="breeze-navbar">
      <div className="breeze-brand">
        <div className="breeze-brand-icon">
          <Shield size={24} />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="breeze-brand-title">NetSleuth AI</span>
            <span className="breeze-brand-tag">Phase 4 Dashboard</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--breeze-text-secondary)' }}>
            AI-Powered Real-Time Threat Detection & Network Engine
          </div>
        </div>
      </div>

      <div className="breeze-controls">
        {/* Connection status badge */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', fontWeight: 600 }}>
          <span className={isConnected ? "breeze-pulse" : ""} style={{ background: isConnected ? "var(--breeze-teal)" : "#9ca3af" }}></span>
          <span style={{ color: isConnected ? "var(--breeze-teal)" : "var(--breeze-text-muted)" }}>
            {isConnected ? "WS CONNECTED" : "RECONNECTING..."}
          </span>
        </div>

        {/* Interface Dropdown */}
        <select
          className="breeze-select"
          value={selectedInterface}
          onChange={(e) => setSelectedInterface(e.target.value)}
          disabled={stats?.is_running}
        >
          {interfaces.map((iface) => (
            <option key={iface.name} value={iface.name}>
              {iface.name} ({iface.is_up ? 'UP' : 'DOWN'}) {iface.ipv4_addresses.length ? `[${iface.ipv4_addresses[0]}]` : ''}
            </option>
          ))}
        </select>

        {/* Mode Toggle */}
        <button
          className="breeze-btn breeze-btn-secondary"
          onClick={() => setSimulationMode(!simulationMode)}
          disabled={stats?.is_running}
          title="Toggle between Live Real-Time Network Socket and Synthetic Simulator"
        >
          <Layers size={16} />
          {simulationMode ? "Mode: Simulation" : "Mode: Live Socket"}
        </button>

        {/* Clear Buffer */}
        <button className="breeze-btn breeze-btn-secondary" onClick={onClear} title="Clear buffer and reset stats">
          <RefreshCw size={16} />
          Clear
        </button>

        {/* Start / Stop Capture Button */}
        <button
          className={`breeze-btn ${stats?.is_running ? 'breeze-btn-stop' : 'breeze-btn-start'}`}
          onClick={handleToggleCapture}
          disabled={loading}
        >
          {stats?.is_running ? (
            <>
              <Square size={16} /> Stop Capture
            </>
          ) : (
            <>
              <Play size={16} /> Start Capture
            </>
          )}
        </button>
      </div>
    </header>
  );
}
