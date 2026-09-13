import React from 'react';
import { Globe } from 'lucide-react';

export default function TopIPsTable({ packets }) {
  // Aggregate IP activity
  const ipCounts = {};
  packets.forEach((p) => {
    const src = p.flow_key?.src_ip;
    const dst = p.flow_key?.dst_ip;
    if (src && src !== '0.0.0.0') {
      ipCounts[src] = (ipCounts[src] || 0) + 1;
    }
    if (dst && dst !== '0.0.0.0') {
      ipCounts[dst] = (ipCounts[dst] || 0) + 1;
    }
  });

  const sortedIPs = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 7);

  return (
    <div className="breeze-card">
      <div className="breeze-card-header">
        <div className="breeze-card-title">
          <Globe size={18} style={{ color: 'var(--breeze-teal)' }} />
          Top Active IPs
        </div>
        <span style={{ fontSize: '0.78rem', color: 'var(--breeze-text-secondary)', fontWeight: 600 }}>
          Top Talkers
        </span>
      </div>

      <div className="breeze-table-wrapper">
        <table className="breeze-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Packets Seen</th>
              <th>Share</th>
            </tr>
          </thead>
          <tbody>
            {sortedIPs.length ? (
              sortedIPs.map(([ip, count]) => (
                <tr key={ip}>
                  <td className="breeze-mono" style={{ fontWeight: 600 }}>
                    {ip}
                  </td>
                  <td>{count}</td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <div
                        style={{
                          height: '6px',
                          width: `${Math.min(100, (count / packets.length) * 100 * 2)}px`,
                          background: 'var(--breeze-teal)',
                          borderRadius: '3px',
                        }}
                      ></div>
                      <span style={{ fontSize: '0.75rem', color: 'var(--breeze-text-secondary)' }}>
                        {((count / packets.length) * 100).toFixed(1)}%
                      </span>
                    </div>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="3" style={{ textAlign: 'center', color: 'var(--breeze-text-muted)' }}>
                  Listening for network traffic...
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
