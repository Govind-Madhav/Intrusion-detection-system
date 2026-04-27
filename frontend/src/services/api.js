import { Client } from '@stomp/stompjs'
import axios from 'axios'

export const http = axios.create({ baseURL: '/api' })

/**
 * Create and activate a STOMP client over native WebSocket.
 * Uses /ws-native (no SockJS) so there are no Node.js polyfill issues in Vite.
 *
 * @param {(alert: object) => void} onAlert   called for each new alert
 * @param {(connected: boolean) => void} onStatus  called on connect/disconnect
 * @returns STOMP Client instance (call .deactivate() to clean up)
 */
export function createWsClient(onAlert, onStatus) {
  // In dev: Vite proxies /ws-native → ws://localhost:8080/ws-native
  // In prod: connect directly to the backend
  const wsUrl = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws-native`

  const client = new Client({
    brokerURL: wsUrl,
    reconnectDelay: 5000,
    onConnect: () => {
      onStatus(true)
      client.subscribe('/topic/alerts', (frame) => {
        try {
          onAlert(JSON.parse(frame.body))
        } catch (e) {
          console.error('Failed to parse alert:', e)
        }
      })
    },
    onDisconnect:  () => onStatus(false),
    onStompError:  () => onStatus(false),
    onWebSocketError: () => onStatus(false),
  })

  client.activate()
  return client
}
