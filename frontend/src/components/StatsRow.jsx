import { useEffect, useRef, useState } from 'react'

function useCountUp(target, duration = 600) {
  const [count, setCount] = useState(0)
  const prev = useRef(0)
  useEffect(() => {
    const start = prev.current
    const diff  = target - start
    if (diff === 0) return
    const steps = Math.max(1, Math.round(duration / 16))
    let step = 0
    const id = setInterval(() => {
      step++
      setCount(Math.round(start + diff * (step / steps)))
      if (step >= steps) { clearInterval(id); prev.current = target }
    }, 16)
    return () => clearInterval(id)
  }, [target, duration])
  return count
}

function StatCard({ icon, label, value, accent }) {
  const display = useCountUp(value)
  return (
    <div className="card stat-card">
      <div className="stat-icon" style={{ background: accent + '22', border: `1px solid ${accent}44` }}>
        <span style={{ fontSize: '1.4rem' }}>{icon}</span>
      </div>
      <div>
        <div className="stat-label">{label}</div>
        <div className="stat-value" style={{ color: accent }}>{display}</div>
      </div>
    </div>
  )
}

export default function StatsRow({ stats }) {
  return (
    <div className="stats-row">
      <StatCard icon="🛡️" label="Total Alerts"  value={stats.total}     accent="#00d4ff" />
      <StatCard icon="🔍" label="SYN Scan"      value={stats.synScan}   accent="#7b2ff7" />
      <StatCard icon="🌊" label="ICMP Flood"    value={stats.icmpFlood} accent="#00d4ff" />
      <StatCard icon="⚠️" label="Risky Port"    value={stats.riskyPort} accent="#ffd60a" />
    </div>
  )
}
