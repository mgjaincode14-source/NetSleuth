import React, { useState } from 'react';
import { Radio, Search, Filter, Eye } from 'lucide-react';

export default function PacketStream({ packets, onSelectPacket }) {
  const [search, setSearch] = useState('');
  const [filterProto, setFilterProto] = useState('ALL');
  const [filterAnomaly, setFilterAnomaly] = useState(false);

  const filtered = packets.filter((p) => {
    const protoMatch = filterProto === 'ALL' || p.protocol === filterProto;
    const anomalyMatch = !filterAnomaly || !!p.anomaly_tag;

    const flowStr = `${p.flow_key?.src_ip}:${p.flow_key?.src_port}->${p.flow_key?.dst_ip}:${p.flow_key?.dst_port}`;
    const searchMatch =
      !search ||
      p.protocol?.toLowerCase().includes(search.toLowerCase()) ||
      flowStr.toLowerCase().includes(search.toLowerCase()) ||
      (p.anomaly_tag && p.anomaly_tag.toLowerCase().includes(search.toLowerCase()));

    return protoMatch && anomalyMatch && searchMatch;
  });

  return (
    <div className="breeze-card">
      <div className="breeze-card-header" style={{ flexWrap: 'wrap', gap: '12px' }}>
        <div className="breeze-card-title">
          <Radio size={18} style={{ color: 'var(--breeze-pink)' }} />
          Live Parsed Packet Stream
        </div>

        {/* Filters & Search */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          {/* Anomaly Filter Toggle */}
          <button
            className={`breeze-btn ${filterAnomaly ? 'breeze-btn-stop' : 'breeze-btn-secondary'}`}
            style={{ padding: '6px 12px', fontSize: '0.78rem' }}
            onClick={() => setFilterAnomaly(!filterAnomaly)}
          >
            <Filter size={14} />
            {filterAnomaly ? 'Anomalies Only' : 'Show All Alerts'}
          </button>

          {/* Protocol Filter */}
          <select
            className="breeze-select"
            style={{ padding: '6px 10px', fontSize: '0.78rem' }}
            value={filterProto}
            onChange={(e) => setFilterProto(e.target.value)}
          >
            <option value="ALL">All Protocols</option>
            <option value="HTTP">HTTP</option>
            <option value="HTTPS">HTTPS</option>
            <option value="DNS">DNS</option>
            <option value="TCP">TCP</option>
            <option value="ICMP">ICMP</option>
          </select>

          {/* Search Box */}
          <div style={{ position: 'relative' }}>
            <input
              type="text"
              placeholder="Search IP, Port, Flag..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="breeze-select"
              style={{ paddingLeft: '30px', padding: '6px 10px 6px 30px', fontSize: '0.78rem', width: '180px' }}
            />
            <Search size={14} style={{ position: 'absolute', left: '10px', top: '8px', color: '#9ca3af' }} />
          </div>
        </div>
      </div>

      <div className="breeze-table-wrapper" style={{ maxHeight: '440px', overflowY: 'auto' }}>
        <table className="breeze-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Direction</th>
              <th>Proto</th>
              <th>Flow 5-Tuple (Src -&gt; Dst)</th>
              <th>TCP Flags</th>
              <th>Metadata / Payload</th>
              <th>Behavior Flag</th>
              <th>Inspect</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length ? (
              filtered.slice().reverse().map((p) => {
                const isIncoming = p.direction === 'INCOMING';
                const isOutgoing = p.direction === 'OUTGOING';

                let metaText = '';
                if (p.dns) {
                  metaText = `DNS ${p.dns.qtype || 'A'} '${p.dns.qname || ''}'`;
                } else if (p.http) {
                  metaText = `HTTP ${p.http.method || ''} ${p.http.path || ''}`;
                } else if (p.icmp) {
                  metaText = `ICMP ${p.icmp.type_name}`;
                } else if (p.payload_ascii) {
                  metaText = `Payload: ${p.payload_ascii.slice(0, 24)}`;
                } else {
                  metaText = `${p.length_bytes} Bytes`;
                }

                return (
                  <tr key={p.packet_id}>
                    <td style={{ fontWeight: 600, color: 'var(--breeze-text-secondary)' }}>{p.packet_id}</td>

                    {/* Direction Badge */}
                    <td>
                      <span
                        className={`breeze-badge ${
                          isIncoming
                            ? 'breeze-badge-incoming'
                            : isOutgoing
                            ? 'breeze-badge-outgoing'
                            : 'breeze-badge-local'
                        }`}
                      >
                        {p.direction}
                      </span>
                    </td>

                    {/* Protocol */}
                    <td style={{ fontWeight: 700 }}>{p.protocol}</td>

                    {/* Flow Key */}
                    <td className="breeze-mono">
                      {p.flow_key?.src_ip}:{p.flow_key?.src_port} &rarr; {p.flow_key?.dst_ip}:{p.flow_key?.dst_port}
                    </td>

                    {/* TCP Flags */}
                    <td className="breeze-mono" style={{ color: 'var(--breeze-purple)' }}>
                      {p.l4?.tcp_flags_summary || '-'}
                    </td>

                    {/* Metadata */}
                    <td style={{ maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {metaText}
                    </td>

                    {/* Behavior / Anomaly Badge */}
                    <td>
                      <span className={`breeze-badge ${p.anomaly_tag ? 'breeze-badge-alert' : 'breeze-badge-normal'}`}>
                        {p.anomaly_tag || 'NORMAL'}
                      </span>
                    </td>

                    {/* Inspect Button */}
                    <td>
                      <button
                        className="breeze-btn breeze-btn-secondary"
                        style={{ padding: '4px 8px', fontSize: '0.72rem' }}
                        onClick={() => onSelectPacket(p)}
                      >
                        <Eye size={12} /> Inspect
                      </button>
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan="8" style={{ textAlign: 'center', padding: '24px', color: 'var(--breeze-text-muted)' }}>
                  Listening for packets matching filters...
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
