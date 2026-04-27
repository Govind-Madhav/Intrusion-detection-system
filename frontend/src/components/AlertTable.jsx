import React, { useState } from 'react'

const SEV_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }

function relativeTime(ts) {
  const diff = Date.now() - ts
  if (diff < 60000)  return `${Math.floor(diff / 1000)}s ago`
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  return new Date(ts).toLocaleTimeString()
}

function ExpandedRow({ alert, colSpan }) {
  return (
    <tr className="expand-row">
      <td colSpan={colSpan}>
        <div className="expand-inner">
          <div className="expand-field"><span>Alert ID</span><span>{alert.alertId}</span></div>
          <div className="expand-field"><span>Detector</span><span>{alert.detectorName}</span></div>
          <div className="expand-field"><span>Protocol</span><span>{alert.protocol}</span></div>
          <div className="expand-field"><span>Src Port</span><span>{alert.sourcePort || '—'}</span></div>
          <div className="expand-field"><span>Dst Port</span><span>{alert.destinationPort || '—'}</span></div>
          <div className="expand-field"><span>Timestamp</span><span>{new Date(alert.timestamp).toISOString()}</span></div>
          <div className="expand-field" style={{ gridColumn: '1/-1' }}><span>Message</span><span>{alert.message}</span></div>
        </div>
      </td>
    </tr>
  )
}

export default function AlertTable({ alerts, filters }) {
  const [expanded, setExpanded] = useState(null)
  const [sortCol,  setSortCol]  = useState(null)

  const toggle = (id) => setExpanded(prev => prev === id ? null : id)

  // Apply filters
  const q = filters.q.toLowerCase()
  let rows = alerts.filter(a => {
    if (filters.type     && a.alertType !== filters.type)     return false
    if (filters.severity && a.severity  !== filters.severity) return false
    if (q && !a.sourceIP?.includes(q) && !a.destinationIP?.includes(q)
           && !a.message?.toLowerCase().includes(q)
           && !a.alertId?.toLowerCase().includes(q)) return false
    return true
  })

  // Sort
  const sort = sortCol ?? filters.sort
  if (sort === 'oldest')   rows = [...rows].reverse()
  if (sort === 'severity') rows = [...rows].sort((a, b) => (SEV_ORDER[b.severity] ?? 0) - (SEV_ORDER[a.severity] ?? 0))

  const cols = ['Time', 'Alert ID', 'Source', 'Destination', 'Protocol', 'Type', 'Severity', 'Message']

  return (
    <div className="card table-wrap">
      <table>
        <thead>
          <tr>
            {cols.map(c => (
              <th key={c} onClick={() => setSortCol(c === 'Time' ? 'newest' : c === 'Severity' ? 'severity' : null)}>
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr><td colSpan={cols.length} className="empty-state">No alerts match the current filters.</td></tr>
          )}
          {rows.map(a => (
            <React.Fragment key={a.alertId}>
              <tr
                className={`alert-row ${a.severity}`}
                onClick={() => toggle(a.alertId)}
              >
                <td className="mono">{relativeTime(a.timestamp)}</td>
                <td className="mono" style={{ color: '#8892b0' }}>{a.alertId}</td>
                <td className="mono">{a.sourceIP}{a.sourcePort ? `:${a.sourcePort}` : ''}</td>
                <td className="mono">{a.destinationIP}{a.destinationPort ? `:${a.destinationPort}` : ''}</td>
                <td><span className="proto-pill">{a.protocol}</span></td>
                <td><span className={`type-chip type-${a.alertType}`}>{a.alertType}</span></td>
                <td><span className={`badge badge-${a.severity}`}>{a.severity}</span></td>
                <td style={{ maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: '#8892b0' }}>
                  {a.message}
                </td>
              </tr>
              {expanded === a.alertId && <ExpandedRow alert={a} colSpan={cols.length} />}
            </React.Fragment>
          ))}
        </tbody>
      </table>
    </div>
  )
}
