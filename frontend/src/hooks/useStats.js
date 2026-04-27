import { useState, useEffect } from 'react'
import { http } from '../services/api'

export function useStats(alerts) {
  // Derive stats locally from the live alerts array (instant, no extra request)
  const total     = alerts.length
  const synScan   = alerts.filter(a => a.alertType === 'SYN_SCAN').length
  const icmpFlood = alerts.filter(a => a.alertType === 'ICMP_FLOOD').length
  const riskyPort = alerts.filter(a => a.alertType === 'RISKY_PORT_ACCESS').length
  const bySeverity = {
    CRITICAL: alerts.filter(a => a.severity === 'CRITICAL').length,
    HIGH:     alerts.filter(a => a.severity === 'HIGH').length,
    MEDIUM:   alerts.filter(a => a.severity === 'MEDIUM').length,
    LOW:      alerts.filter(a => a.severity === 'LOW').length,
  }
  return { total, synScan, icmpFlood, riskyPort, bySeverity }
}
