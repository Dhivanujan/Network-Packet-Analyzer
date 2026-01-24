import React from 'react'

function formatTime(iso) {
  try {
    return new Date(iso).toLocaleTimeString()
  } catch {
    return ''
  }
}

function AlertPanel({ alerts }) {
  if (!alerts || alerts.length === 0) {
    return <p className="muted">No anomalies detected yet.</p>
  }

  return (
    <div className="alert-list">
      {alerts.map((a, idx) => (
        <div key={idx} className="alert-item">
          <div className="alert-time">{formatTime(a.timestamp)}</div>
          <div className="alert-text">{a.description}</div>
        </div>
      ))}
    </div>
  )
}

export default AlertPanel
