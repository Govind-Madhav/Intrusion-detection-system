import { useState, useEffect } from 'react'
import { http } from '../services/api'

export default function Header({ connected }) {
  const [time, setTime] = useState(new Date())

  // Live capture state
  const [capturing,   setCapturing]   = useState(false)
  const [capIface,    setCapIface]    = useState('Ethernet')
  const [interfaces,  setInterfaces]  = useState([])
  const [capStats,    setCapStats]    = useState({ packets: 0, alerts: 0 })
  const [capError,    setCapError]    = useState('')
  const [showIfacePicker, setShowIfacePicker] = useState(false)

  // Clock
  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(id)
  }, [])

  // Load interface list once
  useEffect(() => {
    http.get('/capture/interfaces')
      .then(r => setInterfaces(r.data.interfaces ?? []))
      .catch(() => {})
  }, [])

  // Poll capture stats every 2s while capturing
  useEffect(() => {
    if (!capturing) return
    const id = setInterval(() => {
      http.get('/capture/status')
        .then(r => setCapStats({ packets: r.data.packets, alerts: r.data.alerts }))
        .catch(() => {})
    }, 2000)
    return () => clearInterval(id)
  }, [capturing])

  const toggleCapture = async () => {
    setCapError('')
    if (capturing) {
      await http.post('/capture/stop').catch(() => {})
      setCapturing(false)
      setCapStats({ packets: 0, alerts: 0 })
    } else {
      setShowIfacePicker(false)
      try {
        const res = await http.post(`/capture/start?iface=${encodeURIComponent(capIface)}`)
        if (res.data.status === 'started') {
          setCapturing(true)
        } else {
          setCapError(res.data.error || 'Failed to start')
        }
      } catch {
        setCapError('Backend unreachable — is Spring Boot running as admin?')
      }
    }
  }

  const fmt  = time.toLocaleTimeString('en-US', { hour12: false })
  const date = time.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' })

  return (
    <header className="card header">
      {/* Brand */}
      <div className="header-brand">
        <div className="header-logo"><ShieldIcon /></div>
        <div>
          <div className="header-title">IDS Dashboard</div>
          <div className="header-sub">Intrusion Detection System — Real-time Monitor</div>
        </div>
      </div>

      {/* Right side */}
      <div className="header-right">
        <div className="header-clock">{date} &nbsp; {fmt}</div>

        {/* Live capture controls */}
        <div className="capture-wrap">
          {/* Interface picker */}
          <button
            className="iface-btn"
            title="Select network interface"
            onClick={() => setShowIfacePicker(p => !p)}
            disabled={capturing}
          >
            🔌 {capIface}
          </button>

          {showIfacePicker && interfaces.length > 0 && (
            <div className="iface-dropdown">
              {interfaces.map(iface => (
                <button
                  key={iface}
                  className={`iface-opt ${iface === capIface ? 'active' : ''}`}
                  onClick={() => { setCapIface(iface); setShowIfacePicker(false) }}
                >
                  {iface}
                </button>
              ))}
            </div>
          )}

          {/* Start / Stop button */}
          <button
            className={`capture-btn ${capturing ? 'capture-btn-stop' : 'capture-btn-start'}`}
            onClick={toggleCapture}
            title={capturing ? 'Stop live capture' : 'Start live packet capture'}
          >
            {capturing
              ? <><span className="rec-dot" /> Stop Capture</>
              : <>▶ Live Capture</>}
          </button>

          {/* Live stats */}
          {capturing && (
            <span className="cap-stats">
              📦 {capStats.packets.toLocaleString()} pkts &nbsp;|&nbsp; 🚨 {capStats.alerts} alerts
            </span>
          )}

          {/* Error */}
          {capError && (
            <span className="cap-error" title={capError}>⚠ Capture error</span>
          )}
        </div>

        {/* WS connection pill */}
        <div className={`conn-pill ${connected ? 'connected' : 'disconnected'}`}>
          <span className={`conn-dot ${connected ? 'pulse' : ''}`} />
          {connected ? 'Live' : 'Connecting…'}
        </div>
      </div>
    </header>
  )
}

function ShieldIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  )
}
