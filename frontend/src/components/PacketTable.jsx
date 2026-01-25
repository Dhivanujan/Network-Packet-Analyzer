import React from 'react'

function formatTime(iso) {
  try {
    return new Date(iso).toLocaleTimeString()
  } catch {
    return ''
  }
}

function downloadCsv(rows) {
  if (!rows || rows.length === 0) return

  const header = ['timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'length']
  const escape = (value) => {
    if (value == null) return ''
    const str = String(value)
    if (/[",\n]/.test(str)) {
      return '"' + str.replace(/"/g, '""') + '"'
    }
    return str
  }

  const lines = [header.join(',')]
  for (const p of rows) {
    lines.push(
      [
        p.timestamp,
        p.src_ip,
        p.src_port,
        p.dst_ip,
        p.dst_port,
        p.protocol,
        p.length,
      ]
        .map(escape)
        .join(','),
    )
  }

  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'packets.csv'
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

function PacketTable({ packets }) {
  return (
    <div className="table-wrapper">
      <div className="table-toolbar">
        <span className="muted small">Showing {packets.length} packets</span>
        <button
          type="button"
          className="pill-button secondary"
          onClick={() => downloadCsv(packets)}
          disabled={packets.length === 0}
        >
          Export CSV
        </button>
      </div>
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
