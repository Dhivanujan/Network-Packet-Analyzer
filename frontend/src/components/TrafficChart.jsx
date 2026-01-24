import React from 'react'

function TrafficChart({ protocolCounts }) {
  const entries = Object.entries(protocolCounts || {})

  if (entries.length === 0) {
    return <p className="muted">No traffic yet.</p>
  }

  const max = Math.max(...entries.map(([, count]) => count)) || 1

  return (
    <div className="chart-bars">
      {entries.map(([proto, count]) => {
        const width = `${(count / max) * 100}%`
        return (
          <div key={proto} className="chart-row">
            <span className="chart-label">{proto}</span>
            <div className="chart-bar-bg">
              <div className="chart-bar-fill" style={{ width }} />
            </div>
            <span className="chart-value">{count}</span>
          </div>
        )
      })}
    </div>
  )
}

export default TrafficChart
