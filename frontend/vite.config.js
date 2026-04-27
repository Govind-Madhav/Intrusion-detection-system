import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      // Native STOMP WebSocket endpoint (no SockJS)
      '/ws-native': {
        target: 'http://localhost:8080',
        ws: true,
        changeOrigin: true,
      },
      // Keep SockJS proxy for any legacy usage
      '/ws': {
        target: 'http://localhost:8080',
        ws: true,
        changeOrigin: true,
      },
    },
  },
})
