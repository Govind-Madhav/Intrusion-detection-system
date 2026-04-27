import { useState } from 'react'
import { http } from '../services/api'

const SCENARIOS = [
  {
    id: 'ddos',
    label: 'DDoS Attack',
    icon: '💥',
    desc: '5 IPs flood target with ICMP packets',
    color: '#ff2d55',
  },
  {
    id: 'port-scan',
    label: 'Port Scan',
    icon: '🔍',
    desc: 'SYN sweep across 15 ports',
    color: '#ff6b35',
  },
  {
    id: 'xmas-scan',
    label: 'Xmas / Stealth',
    icon: '🎄',
    desc: 'Xmas + NULL + FIN scan combo',
    color: '#bf5af2',
  },
  {
    id: 'db-breach',
    label: 'DB Breach',
    icon: '🗄️',
    desc: 'Hits MySQL, Postgres, MongoDB, Redis',
    color: '#ff9f0a',
  },
  {
    id: 'brute-force',
    label: 'Brute Force',
    icon: '🔨',
    desc: '12 repeated RDP/SSH auth attempts',
    color: '#ffd60a',
  },
  {
    id: 'coordinated',
    label: 'Coordinated',
    icon: '⚡',
    desc: 'All attack types simultaneously',
    color: '#00d4ff',
    highlight: true,
  },
]

export default function SimulatePanel() {
  const [running, setRunning] = useState(null)
  const [lastResult, setLastResult] = useState(null)

  const launch = async (id) => {
    setRunning(id)
    setLastResult(null)
    try {
      const res = await http.post(`/simulate/${id}`)
      setLastResult(res.data)
    } catch {
      setLastResult({ error: true })
    } finally {
      setRunning(null)
    }
  }

  return (
    <div className="card simulate-panel">
      <div className="simulate-header">
        <span className="simulate-title">⚔️ Attack Simulator</span>
        <span className="simulate-sub">Inject realistic attack patterns into the live feed</span>
      </div>

      <div className="simulate-grid">
        {SCENARIOS.map(s => (
          <button
            key={s.id}
            className={`sim-btn ${s.highlight ? 'sim-btn-highlight' : ''} ${running === s.id ? 'sim-btn-loading' : ''}`}
            style={{ '--accent': s.color }}
            onClick={() => launch(s.id)}
            disabled={running !== null}
          >
            <span className="sim-icon">{s.icon}</span>
            <span className="sim-label">{s.label}</span>
            <span className="sim-desc">{s.desc}</span>
            {running === s.id && <span className="sim-spinner" />}
          </button>
        ))}
      </div>

      {lastResult && (
        <div className={`sim-result ${lastResult.error ? 'sim-error' : 'sim-success'}`}>
          {lastResult.error
            ? '❌ Simulation failed — is the backend running?'
            : `✅ ${lastResult.scenario} launched — ${lastResult.alerts} alert(s) incoming`}
        </div>
      )}
    </div>
  )
}
