import React, { useEffect, useRef } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Filler,
  Legend,
} from 'chart.js';
import { Line } from 'react-chartjs-2';
import { TrendingUp } from 'lucide-react';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Filler,
  Legend
);

export default function PPSChart({ ppsHistory }) {
  const chartData = {
    labels: ppsHistory.map((item) => item.time),
    datasets: [
      {
        fill: true,
        label: 'Packets / Sec (PPS)',
        data: ppsHistory.map((item) => item.pps),
        borderColor: '#10b981',
        backgroundColor: 'rgba(16, 185, 129, 0.08)',
        tension: 0.35,
        borderWidth: 2,
        pointRadius: 0,
        pointHoverRadius: 4,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        mode: 'index',
        intersect: false,
        backgroundColor: '#1f2937',
        titleFont: { family: 'Inter', size: 12 },
        bodyFont: { family: 'Inter', size: 12 },
        padding: 10,
        borderRadius: 8,
      },
    },
    scales: {
      x: {
        grid: { display: false },
        ticks: { color: '#9ca3af', font: { family: 'Inter', size: 11 } },
      },
      y: {
        beginAtZero: true,
        grid: { color: '#f3f4f6' },
        ticks: { color: '#9ca3af', font: { family: 'Inter', size: 11 } },
      },
    },
  };

  return (
    <div className="breeze-card" style={{ height: '320px', display: 'flex', flexDirection: 'column' }}>
      <div className="breeze-card-header">
        <div className="breeze-card-title">
          <TrendingUp size={18} style={{ color: 'var(--breeze-green)' }} />
          Real-Time Throughput (PPS)
        </div>
        <span style={{ fontSize: '0.78rem', color: 'var(--breeze-text-secondary)', fontWeight: 600 }}>
          Live Rate History
        </span>
      </div>
      <div style={{ flex: 1, position: 'relative', width: '100%' }}>
        <Line data={chartData} options={options} />
      </div>
    </div>
  );
}
