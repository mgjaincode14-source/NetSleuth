import React from 'react';
import { Activity, Zap, HardDrive, ArrowDownLeft, AlertTriangle } from 'lucide-react';

function formatTotalBytes(bytes) {
  if (!bytes) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatRate(bps) {
  if (!bps) return '0 B/s';
  if (bps < 1024) return `${bps.toFixed(1)} B/s`;
  if (bps < 1024 * 1024) return `${(bps / 1024).toFixed(1)} KB/s`;
  return `${(bps / (1024 * 1024)).toFixed(2)} MB/s`;
}

export default function MetricCards({ stats, anomalyCount }) {
  const total = stats?.total_packets || 0;
  const incoming = stats?.incoming_packets || 0;
  const outgoing = stats?.outgoing_packets || 0;

  const inPct = total ? ((incoming / total) * 100).toFixed(1) : '0';
  const outPct = total ? ((outgoing / total) * 100).toFixed(1) : '0';

  return (
    <div className="breeze-kpi-grid">
      {/* 1. Total Packets (Teal Accent) */}
      <div className="breeze-card breeze-kpi-card breeze-kpi-teal">
        <div className="breeze-kpi-info">
          <span className="breeze-kpi-label">Total Packets</span>
          <span className="breeze-kpi-value">{total.toLocaleString()}</span>
          <span className="breeze-kpi-sub">Volume: {formatTotalBytes(stats?.total_bytes)}</span>
        </div>
        <div className="breeze-kpi-icon">
          <Activity size={24} />
        </div>
      </div>

      {/* 2. Packet Rate PPS (Green Accent) */}
      <div className="breeze-card breeze-kpi-card breeze-kpi-green">
        <div className="breeze-kpi-info">
          <span className="breeze-kpi-label">Packet Rate</span>
          <span className="breeze-kpi-value">{stats?.packets_per_second || 0} <span style={{ fontSize: '1rem' }}>pps</span></span>
          <span className="breeze-kpi-sub">Elapsed: {stats?.elapsed_seconds || 0}s</span>
        </div>
        <div className="breeze-kpi-icon">
          <Zap size={24} />
        </div>
      </div>

      {/* 3. Bandwidth (Amber Accent) */}
      <div className="breeze-card breeze-kpi-card breeze-kpi-amber">
        <div className="breeze-kpi-info">
          <span className="breeze-kpi-label">Bandwidth</span>
          <span className="breeze-kpi-value" style={{ fontSize: '1.35rem' }}>{formatRate(stats?.bytes_per_second)}</span>
          <span className="breeze-kpi-sub">Real-Time Throughput</span>
        </div>
        <div className="breeze-kpi-icon">
          <HardDrive size={24} />
        </div>
      </div>

      {/* 4. Direction Ratio (Purple Accent) */}
      <div className="breeze-card breeze-kpi-card breeze-kpi-purple">
        <div className="breeze-kpi-info">
          <span className="breeze-kpi-label">Directions</span>
          <span className="breeze-kpi-value" style={{ fontSize: '1.25rem' }}>
            In {inPct}% / Out {outPct}%
          </span>
          <span className="breeze-kpi-sub">Incoming {incoming} | Outgoing {outgoing}</span>
        </div>
        <div className="breeze-kpi-icon">
          <ArrowDownLeft size={24} />
        </div>
      </div>

      {/* 5. Threat Flags / Anomalies (Pink Accent) */}
      <div className="breeze-card breeze-kpi-card breeze-kpi-pink">
        <div className="breeze-kpi-info">
          <span className="breeze-kpi-label">Threat Flags</span>
          <span className="breeze-kpi-value" style={{ color: anomalyCount > 0 ? "var(--breeze-pink)" : "inherit" }}>
            {anomalyCount}
          </span>
          <span className="breeze-kpi-sub">{anomalyCount > 0 ? 'SYN Scans / Abnormal Flags' : 'No Anomalies Detected'}</span>
        </div>
        <div className="breeze-kpi-icon">
          <AlertTriangle size={24} />
        </div>
      </div>
    </div>
  );
}
