import React from 'react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';
import { PieChart } from 'lucide-react';

ChartJS.register(ArcElement, Tooltip, Legend);

const BREEZE_COLORS = [
  '#7367f0', // Purple
  '#00c292', // Teal
  '#e83e8c', // Pink
  '#ff9f43', // Amber
  '#10b981', // Green
  '#00b5b5', // Cyan
  '#6b7280', // Grey
];

export default function ProtocolPie({ protocolCounts }) {
  const labels = Object.keys(protocolCounts || {});
  const dataValues = Object.values(protocolCounts || {});

  const chartData = {
    labels: labels.length ? labels : ['No Traffic'],
    datasets: [
      {
        data: dataValues.length ? dataValues : [1],
        backgroundColor: labels.length ? BREEZE_COLORS.slice(0, labels.length) : ['#e5e7eb'],
        borderWidth: 2,
        borderColor: '#ffffff',
        hoverOffset: 6,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right',
        labels: {
          font: { family: 'Inter', size: 12, weight: '600' },
          color: '#374151',
          padding: 14,
          usePointStyle: true,
          pointStyle: 'circle',
        },
      },
      tooltip: {
        backgroundColor: '#1f2937',
        borderRadius: 8,
        padding: 10,
      },
    },
    cutout: '68%',
  };

  return (
    <div className="breeze-card" style={{ height: '320px', display: 'flex', flexDirection: 'column' }}>
      <div className="breeze-card-header">
        <div className="breeze-card-title">
          <PieChart size={18} style={{ color: 'var(--breeze-purple)' }} />
          Protocol Share
        </div>
        <span style={{ fontSize: '0.78rem', color: 'var(--breeze-text-secondary)', fontWeight: 600 }}>
          Distribution
        </span>
      </div>
      <div style={{ flex: 1, position: 'relative', width: '100%' }}>
        <Doughnut data={chartData} options={options} />
      </div>
    </div>
  );
}
