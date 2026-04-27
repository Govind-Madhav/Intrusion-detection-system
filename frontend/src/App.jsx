import { useState } from 'react'
import Header        from './components/Header'
import StatsRow     from './components/StatsRow'
import ChartsRow    from './components/ChartsRow'
import FiltersBar   from './components/FiltersBar'
import AlertTable   from './components/AlertTable'
import ExportButton from './components/ExportButton'
import SimulatePanel from './components/SimulatePanel'
import { useAlerts } from './hooks/useAlerts'
import { useStats }  from './hooks/useStats'

const DEFAULT_FILTERS = { q: '', type: '', severity: '', sort: 'newest' }

export default function App() {
  const { alerts, connected, loading } = useAlerts()
  const stats = useStats(alerts)
  const [filters, setFilters] = useState(DEFAULT_FILTERS)

  return (
    <main className="page">
      <Header connected={connected} />
      <StatsRow stats={stats} />
      <ChartsRow stats={stats} alerts={alerts} />
      <SimulatePanel />
      <div style={{ display: 'flex', gap: 10, alignItems: 'stretch' }}>
        <FiltersBar
          filters={filters}
          onChange={setFilters}
          total={alerts.length}
          shown={alerts.filter(a => {
            const q = filters.q.toLowerCase()
            if (filters.type     && a.alertType !== filters.type)     return false
            if (filters.severity && a.severity  !== filters.severity) return false
            if (q && !a.sourceIP?.includes(q) && !a.destinationIP?.includes(q)
                   && !a.message?.toLowerCase().includes(q)
                   && !a.alertId?.toLowerCase().includes(q)) return false
            return true
          }).length}
        />
        <ExportButton alerts={alerts} />
      </div>
      <AlertTable alerts={alerts} filters={filters} />
    </main>
  )
}
