export default function FiltersBar({ filters, onChange, total, shown }) {
  const set = (key) => (e) => onChange({ ...filters, [key]: e.target.value })

  return (
    <div className="card filters-bar">
      <input
        id="filter-search"
        type="search"
        placeholder="🔍  Search by IP, message, alert ID…"
        value={filters.q}
        onChange={set('q')}
      />

      <select id="filter-type" value={filters.type} onChange={set('type')}>
        <option value="">All Types</option>
        <option value="SYN_SCAN">SYN Scan</option>
        <option value="ICMP_FLOOD">ICMP Flood</option>
        <option value="RISKY_PORT">Risky Port</option>
      </select>

      <select id="filter-severity" value={filters.severity} onChange={set('severity')}>
        <option value="">All Severities</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
      </select>

      <select id="filter-sort" value={filters.sort} onChange={set('sort')}>
        <option value="newest">Newest First</option>
        <option value="oldest">Oldest First</option>
        <option value="severity">Severity ↓</option>
      </select>

      <span className="filters-count">{shown} / {total} alerts</span>
    </div>
  )
}
