export default function ExportButton({ alerts }) {
  const handleExport = () => {
    const blob = new Blob([JSON.stringify(alerts, null, 2)], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = `ids-alerts-${new Date().toISOString().slice(0,19).replace(/:/g,'-')}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <button id="btn-export" className="btn-export" onClick={handleExport} title="Download all alerts as JSON">
      ⬇ Export JSON
    </button>
  )
}
