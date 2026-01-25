import React from 'react'

function formatTime(iso) {
  try {
    return new Date(iso).toLocaleTimeString()
  } catch {
    return ''
  }
}

function AlertPanel({ alerts, onClear }) {
  if (!alerts || alerts.length === 0) {
    return <p className="muted">No anomalies detected yet.</p>
  }

  return (
    <>
      <div className="alerts-header-row">
        <span className="muted small">Recent alerts: {alerts.length}</span>
        {onClear && (
          <button type="button" className="pill-button secondary" onClick={onClear}>
            Clear alerts
          </button>
        )}
      </div>
      <div className="alert-list">
        {alerts.map((a, idx) => (
          <div key={idx} className="alert-item">
            <div className="alert-time">{formatTime(a.timestamp)}</div>
            <div className="alert-text">{a.description}</div>
          </div>
        ))}
      </div>
    </>
  )
}

export default AlertPanel
