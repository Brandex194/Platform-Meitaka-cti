import { quickReportCsv } from '@/api/reportCsv'
import type { QuickReport } from '@/api/types'

const base: QuickReport = {
  tenant_id: 't', generated_at: '2026-11-10T10:00:00Z', total_assets: 2, critical_assets: 1, open_cases: 0,
  assets_by_level: { critical: 1, high: 0, medium: 0, low: 0 }, unscored_assets: 1,
  top_assets: [{ asset_id: 'a1', hostname: '=cmd|calc', ip: '10.0.0.1', value: 0.9, level: 'critical' }],
  sla_breached_cases: 0, sla_at_risk_cases: 0, kev_vulnerabilities: 0, leaks_total: 0, darkweb_findings_new: 0,
  top_vulnerabilities: [], risk_trend: [{ date: '2026-11-09', avg_score: 0.5 }],
}

test('csv has the summary and neutralises spreadsheet formulas', () => {
  const csv = quickReportCsv(base)
  expect(csv).toContain('Total assets,2')
  expect(csv).toContain("'=cmd|calc,10.0.0.1,0.9,critical")
  expect(csv).toContain('2026-11-09,0.5')
})

test('csv quotes cells with commas and quotes', () => {
  const csv = quickReportCsv({ ...base, top_assets: [{ ...base.top_assets[0], hostname: 'a,"b"' }] })
  expect(csv).toContain('"a,""b"""')
})
