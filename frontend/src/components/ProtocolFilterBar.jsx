import React from 'react'

const FILTERS = ['ALL', 'TCP', 'UDP', 'ICMP', 'HTTP']

function ProtocolFilterBar({ value, onChange }) {
  return (
    <div className="filter-bar">
      {FILTERS.map((f) => (
        <button
          key={f}
          type="button"
          className={value === f ? 'filter-btn active' : 'filter-btn'}
          onClick={() => onChange(f)}
        >
          {f}
        </button>
      ))}
    </div>
  )
}

export default ProtocolFilterBar
