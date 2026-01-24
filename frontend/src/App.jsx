import React, { useEffect, useMemo, useState } from 'react'
import PacketTable from './components/PacketTable'
import ProtocolFilterBar from './components/ProtocolFilterBar'
import TrafficChart from './components/TrafficChart'
import AlertPanel from './components/AlertPanel'

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws/packets'
const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000'

const MAX_PACKETS = 500

function App() {
  const [packets, setPackets] = useState([])
  const [protocolFilter, setProtocolFilter] = useState('ALL')
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState({ total_packets: 0, protocol_counts: {} })
  const [connected, setConnected] = useState(false)

  useEffect(() => {
    const ws = new WebSocket(WS_URL)

    ws.onopen = () => setConnected(true)
    ws.onclose = () => setConnected(false)
    ws.onerror = () => setConnected(false)

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        if (msg.type === 'packet') {
          setPackets((prev) => {
            const next = [msg.data, ...prev]
            return next.slice(0, MAX_PACKETS)
          })
        } else if (msg.type === 'anomaly') {
          setAlerts((prev) => [msg.data, ...prev])
        }
      } catch (e) {
        console.error('Bad WebSocket message', e)
      }
    }

    return () => ws.close()
  }, [])

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/stats`)
        if (!res.ok) return
        const data = await res.json()
        setStats({
          total_packets: data.total_packets,
          protocol_counts: data.protocol_counts || {},
        })
      } catch (e) {
        // ignore polling errors in UI
      }
    }

    fetchStats()
    const id = setInterval(fetchStats, 5000)
    return () => clearInterval(id)
  }, [])

  const filteredPackets = useMemo(() => {
    if (protocolFilter === 'ALL') return packets
    if (protocolFilter === 'HTTP') {
      return packets.filter((p) => {
        if (p.protocol !== 'TCP') return false
        const ports = [p.src_port, p.dst_port].filter(Boolean)
        return ports.some((port) => [80, 443, 8080, 8000].includes(port))
      })
    }
    return packets.filter((p) => p.protocol === protocolFilter)
  }, [packets, protocolFilter])

  return (
    <div className="app-root">
      <header className="app-header">
        <h1>Network Packet Analyzer</h1>
        <p>Educational, real-time view of network metadata only.</p>
        <div className="status-bar">
          <span className={connected ? 'status-dot online' : 'status-dot offline'} />
          <span>{connected ? 'Live stream connected' : 'Disconnected'}</span>
          <span className="stat-pill">Total packets: {stats.total_packets}</span>
        </div>
      </header>

      <main className="layout-grid">
        <section className="panel wide">
          <ProtocolFilterBar value={protocolFilter} onChange={setProtocolFilter} />
          <PacketTable packets={filteredPackets} />
        </section>

        <section className="panel">
          <h2>Traffic by Protocol</h2>
          <TrafficChart protocolCounts={stats.protocol_counts} />
        </section>

        <section className="panel">
          <h2>Alerts</h2>
          <AlertPanel alerts={alerts} />
        </section>
      </main>

      <footer className="app-footer">
        <p>
          Use only on networks you own or are explicitly authorized to monitor.
          This dashboard visualizes packet headers only, never payload contents.
        </p>
      </footer>
    </div>
  )
}

export default App
