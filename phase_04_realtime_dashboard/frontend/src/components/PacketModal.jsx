import React from 'react';
import { X, Layers, Code, ShieldAlert, Cpu } from 'lucide-react';

export default function PacketModal({ packet, onClose }) {
  if (!packet) return null;

  return (
    <div className="breeze-modal-overlay" onClick={onClose}>
      <div className="breeze-modal" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
          <div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--breeze-text-primary)' }}>
              Packet #{packet.packet_id} Inspector
            </h2>
            <p style={{ fontSize: '0.8rem', color: 'var(--breeze-text-secondary)' }}>
              Protocol: {packet.protocol} | Direction: {packet.direction} | Length: {packet.length_bytes} Bytes
            </p>
          </div>
          <button
            onClick={onClose}
            style={{ border: 'none', background: 'none', cursor: 'pointer', color: 'var(--breeze-text-muted)' }}
          >
            <X size={24} />
          </button>
        </div>

        {/* Anomaly Banner if present */}
        {packet.anomaly_tag && (
          <div
            style={{
              background: 'var(--breeze-pink-light)',
              border: '1px solid var(--breeze-pink)',
              color: 'var(--breeze-pink)',
              padding: '12px 16px',
              borderRadius: '8px',
              fontWeight: 700,
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              marginBottom: '20px',
            }}
          >
            <ShieldAlert size={20} />
            <span>Alert Flagged: {packet.anomaly_tag}</span>
          </div>
        )}

        {/* 5-Tuple & Flow Key */}
        <div className="breeze-card" style={{ marginBottom: '16px', background: '#f8fafc' }}>
          <div style={{ fontWeight: 700, fontSize: '0.85rem', color: 'var(--breeze-text-secondary)', marginBottom: '8px' }}>
            5-TUPLE FLOW KEY
          </div>
          <div className="breeze-mono" style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--breeze-purple)' }}>
            {packet.flow_key?.protocol}:{packet.flow_key?.src_ip}:{packet.flow_key?.src_port} &rarr; {packet.flow_key?.dst_ip}:{packet.flow_key?.dst_port}
          </div>
        </div>

        {/* Protocol Layers */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '20px' }}>
          {/* L2 / L3 Header */}
          <div className="breeze-card">
            <div className="breeze-card-title" style={{ marginBottom: '10px' }}>
              <Layers size={16} /> Layer 2 / 3 Headers
            </div>
            <ul style={{ listStyle: 'none', fontSize: '0.82rem', display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <li><strong>Src MAC:</strong> <span className="breeze-mono">{packet.l2?.src_mac || '-'}</span></li>
              <li><strong>Dst MAC:</strong> <span className="breeze-mono">{packet.l2?.dst_mac || '-'}</span></li>
              <li><strong>IP Version:</strong> IPv{packet.l3?.version || 4}</li>
              <li><strong>TTL:</strong> {packet.l3?.ttl || '-'}</li>
              <li><strong>Header Len:</strong> {packet.l3?.header_length || '-'} Bytes</li>
            </ul>
          </div>

          {/* L4 Header & TCP Flags */}
          <div className="breeze-card">
            <div className="breeze-card-title" style={{ marginBottom: '10px' }}>
              <Cpu size={16} /> Layer 4 Transport Flags
            </div>
            <ul style={{ listStyle: 'none', fontSize: '0.82rem', display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <li><strong>Ports:</strong> {packet.l4?.src_port} &rarr; {packet.l4?.dst_port}</li>
              <li><strong>Seq #:</strong> {packet.l4?.seq ?? '-'}</li>
              <li><strong>Ack #:</strong> {packet.l4?.ack ?? '-'}</li>
              <li><strong>TCP Flags Summary:</strong> <span className="breeze-mono" style={{ color: 'var(--breeze-purple)', fontWeight: 700 }}>{packet.l4?.tcp_flags_summary || '-'}</span></li>
              <li>
                <strong>Flags Dict:</strong>{' '}
                {packet.l4?.tcp_flags_dict
                  ? Object.entries(packet.l4.tcp_flags_dict)
                      .filter(([, v]) => v)
                      .map(([k]) => k)
                      .join(', ')
                  : '-'}
              </li>
            </ul>
          </div>
        </div>

        {/* Payload View (Hex & ASCII) */}
        {packet.payload_size > 0 && (
          <div className="breeze-card">
            <div className="breeze-card-title" style={{ marginBottom: '10px' }}>
              <Code size={16} /> Payload Inspection ({packet.payload_size} Bytes)
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <div>
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--breeze-text-secondary)' }}>
                  HEX PREVIEW:
                </span>
                <div className="breeze-mono" style={{ background: '#1e293b', color: '#38bdf8', padding: '10px', borderRadius: '6px', fontSize: '0.8rem', overflowX: 'auto', marginTop: '4px' }}>
                  {packet.payload_hex || 'None'}
                </div>
              </div>
              <div>
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--breeze-text-secondary)' }}>
                  PRINTABLE ASCII PREVIEW:
                </span>
                <div className="breeze-mono" style={{ background: '#1e293b', color: '#4ade80', padding: '10px', borderRadius: '6px', fontSize: '0.8rem', overflowX: 'auto', marginTop: '4px' }}>
                  {packet.payload_ascii || 'None'}
                </div>
              </div>
            </div>
          </div>
        )}

        <div style={{ marginTop: '20px', textAlign: 'right' }}>
          <button className="breeze-btn breeze-btn-secondary" onClick={onClose}>
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
}
