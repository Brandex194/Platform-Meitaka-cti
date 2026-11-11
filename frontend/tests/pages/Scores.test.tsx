import { render, screen, fireEvent } from '@testing-library/react'
import { vi } from 'vitest'

const EXPL = {
  asset_id: 'a1aaaaaa-0000-0000-0000-000000000000', hostname: 'web-01', ip: null,
  formula: 'architettura-5-moltiplicativa-v3', rule_id: null, rule_version: 3,
  exposure: 'internet', exposure_factor: 1, impact: 'critical', impact_factor: 1, context_factor: 1,
  aggregation: 'decay', decay: 0.5, kev_floor: 0.25,
  thresholds: { low: 0.2, medium: 0.4, high: 0.7 }, total: 0.62, level: 'high',
  findings: [
    { event_id: 'e1', rule_name: 'vuln_software', cve_id: 'CVE-2024-0001', cvss: 9.8, epss: 0.5, in_kev: true,
      f_severity: 0.98, f_confidence: 1, f_recency: 1, s_base: 0.8, s_context: 0.8, kev_floor_applied: false,
      alpha: 1, contribution: 0.8, rank: 0, weight: 1, counted: 0.8 },
  ],
}
vi.mock('@/api/hooks/useScores', () => ({
  useScores: () => ({
    isLoading: false,
    data: { items: [{ id: 's1', tenant_id: 't1', asset_id: 'a1aaaaaa-0000-0000-0000-000000000000', score_type: 'asset', value: 0.62, level: 'high', epss_score: null, computed_at: '2026-11-10', score_rule_version: 3 }] },
  }),
  useScoreExplanation: () => ({ data: EXPL, isLoading: false, error: null }),
}))

import { Scores } from '@/pages/Scores'

test('Explain opens the breakdown with context and findings', () => {
  render(<Scores tenantId="t1" />)
  expect(screen.queryByLabelText('Score explanation')).toBeNull()
  fireEvent.click(screen.getByRole('button', { name: 'Explain' }))
  const panel = screen.getByLabelText('Score explanation')
  expect(panel).toHaveTextContent('web-01')
  expect(panel).toHaveTextContent('CVE-2024-0001')
  expect(panel).toHaveTextContent('context factor')
  expect(panel).toHaveTextContent('0.620')
  fireEvent.click(screen.getByRole('button', { name: 'Close' }))
  expect(screen.queryByLabelText('Score explanation')).toBeNull()
})
