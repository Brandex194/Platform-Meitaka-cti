import type { QuickReport } from '@/api/types'

const cell = (v: unknown) => {
  let s = v == null ? '' : String(v)
  // A cell starting with = + - @ would be run as a formula by Excel: neutralise it.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

/** The quick report as one CSV: summary figures, top assets, top vulnerabilities, trend. */
export function quickReportCsv(r: QuickReport): string {
  const rows: unknown[][] = [
    ['Meitaka CTI quick report'],
    ['Generated', r.generated_at],
    [],
    ['Summary'],
    ['Total assets', r.total_assets],
    ['Unscored assets', r.unscored_assets],
    ['Critical assets', r.assets_by_level.critical],
    ['High assets', r.assets_by_level.high],
    ['Medium assets', r.assets_by_level.medium],
    ['Low assets', r.assets_by_level.low],
    ['Open cases', r.open_cases],
    ['Cases past SLA', r.sla_breached_cases],
    ['Cases SLA at risk', r.sla_at_risk_cases],
    ['Vulnerabilities in CISA KEV', r.kev_vulnerabilities],
    ['Leaked emails', r.leaks_total],
    ['New dark web findings', r.darkweb_findings_new],
    [],
    ['Top assets at risk'],
    ['Asset', 'IP', 'Score', 'Level'],
    ...r.top_assets.map((a) => [a.hostname ?? a.asset_id, a.ip, a.value, a.level]),
    [],
    ['Top vulnerabilities'],
    ['CVE', 'CVSS', 'EPSS', 'KEV date'],
    ...r.top_vulnerabilities.map((v) => [v.cve_id, v.cvss_score, v.epss_score, v.kev_date_added]),
    [],
    ['Risk trend (30 days)'],
    ['Date', 'Average score'],
    ...r.risk_trend.map((t) => [t.date, t.avg_score]),
  ]
  return rows.map((row) => row.map(cell).join(',')).join('\r\n') + '\r\n'
}

export function downloadCsv(name: string, csv: string) {
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  URL.revokeObjectURL(url)
}
