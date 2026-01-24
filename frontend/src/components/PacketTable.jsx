import React from 'react'

function formatTime(iso) {
  try {
    return new Date(iso).toLocaleTimeString()
  } catch {
    return ''
  }
}

function PacketTable({ packets }) {
  return (
    <div className="table-wrapper">
      <table className="packet-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Protocol</th>
            <th>Length (bytes)</th>
          </tr>
        </thead>
        <tbody>
          {packets.length === 0 ? (
            <tr>
              <td colSpan={5} className="empty-cell">
                Waiting for packets...
              </td>
            </tr>
          ) : (
            packets.map((p, idx) => (
              <tr key={idx}>
                <td>{formatTime(p.timestamp)}</td>
                <td>
                  {p.src_ip}
                  {p.src_port ? `:${p.src_port}` : ''}
                </td>
                <td>
                  {p.dst_ip}
                  {p.dst_port ? `:${p.dst_port}` : ''}
                </td>
                <td className={`proto proto-${String(p.protocol).toLowerCase()}`}>{p.protocol}</td>
                <td>{p.length}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  )
}

export default PacketTable
