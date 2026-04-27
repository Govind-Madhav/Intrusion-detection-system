import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts'

const SEV_COLORS = {
  CRITICAL: '#ff2d55',
  HIGH:     '#ff6b35',
  MEDIUM:   '#ffd60a',
  LOW:      '#30d158',
}
const TYPE_COLORS = {
  SYN_SCAN:         '#7b2ff7',
  ICMP_FLOOD:       '#00d4ff',
  RISKY_PORT_ACCESS:'#ffd60a',
}

const tooltipStyle = {
  background: '#0d1526',
  border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: 8,
  color: '#e8f0fe',
  fontSize: 12,
}

export default function ChartsRow({ stats, alerts }) {
  // Donut data
  const pieData = Object.entries(stats.bySeverity)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))

  // Bar data — last 20 alerts bucketed by type
  const typeCounts = { SYN_SCAN: 0, ICMP_FLOOD: 0, RISKY_PORT_ACCESS: 0 }
  alerts.forEach(a => { if (typeCounts[a.alertType] !== undefined) typeCounts[a.alertType]++ })
  const barData = Object.entries(typeCounts).map(([name, count]) => ({ name, count }))

  return (
    <div className="charts-row">
      {/* Donut — severity split */}
      <div className="card chart-card">
        <div className="chart-title">Severity Distribution</div>
        <ResponsiveContainer width="100%" height={220}>
          <PieChart>
            <Pie
              data={pieData}
              cx="50%" cy="50%"
              innerRadius={55} outerRadius={85}
              paddingAngle={3}
              dataKey="value"
            >
              {pieData.map((entry) => (
                <Cell key={entry.name} fill={SEV_COLORS[entry.name]} />
              ))}
            </Pie>
            <Tooltip contentStyle={tooltipStyle} />
            <Legend
              formatter={(v) => <span style={{ color: '#8892b0', fontSize: 12 }}>{v}</span>}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>

      {/* Bar — alert type counts */}
      <div className="card chart-card">
        <div className="chart-title">Alerts by Type</div>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={barData} barSize={36}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
            <XAxis dataKey="name" tick={{ fill: '#8892b0', fontSize: 11 }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fill: '#8892b0', fontSize: 11 }} axisLine={false} tickLine={false} />
            <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
            <Bar dataKey="count" radius={[6, 6, 0, 0]}>
              {barData.map((entry) => (
                <Cell key={entry.name} fill={TYPE_COLORS[entry.name]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
