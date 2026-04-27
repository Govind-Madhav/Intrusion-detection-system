import { useState, useEffect, useCallback } from 'react'
import { http, createWsClient } from '../services/api'

const MAX_ALERTS = 500

export function useAlerts() {
  const [alerts,    setAlerts]    = useState([])
  const [connected, setConnected] = useState(false)
  const [loading,   setLoading]   = useState(true)

  // Load full history on mount
  useEffect(() => {
    http.get('/alerts?size=200')
      .then(r => setAlerts(r.data.alerts ?? []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  // Real-time WebSocket stream
  useEffect(() => {
    const client = createWsClient(
      (alert) => setAlerts(prev => [alert, ...prev].slice(0, MAX_ALERTS)),
      setConnected
    )
    return () => client.deactivate()
  }, [])

  const clearAlerts = useCallback(() => setAlerts([]), [])

  return { alerts, connected, loading, clearAlerts }
}
