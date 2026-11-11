import { RiskLevelBadge } from '@/components/RiskLevelBadge'
import { useScoreExplanation } from '@/api/hooks/useScores'

const f = (n: number | null | undefined, d = 2) => (n == null ? '—' : n.toFixed(d))

/** Why an asset has its score: context factors, then every finding and how much it counted. */
export function ScoreExplanationPanel({
  tenantId,
  assetId,
  onClose,
}: {
  tenantId: string
  assetId: string
  onClose: () => void
}) {
  const { data, isLoading, error } = useScoreExplanation(tenantId, assetId)

  return (
    <section className="card space-y-3" aria-label="Score explanation">
      <div className="flex items-start justify-between gap-3">
        <h3 className="text-base font-semibold">
          Why this score{data ? ` — ${data.hostname ?? data.ip ?? data.asset_id.slice(0, 8)}` : ''}
        </h3>
        <button className="btn btn-ghost" onClick={onClose}>Close</button>
      </div>
      {isLoading && <p className="muted">Loading…</p>}
      {error && <p role="alert" className="text-red-600">Could not load the explanation.</p>}
      {data && (
        <>
          <p className="text-sm">
            Total <strong>{f(data.total, 3)}</strong> → <RiskLevelBadge level={data.level} />{' '}
            <span className="muted">
              (medium from {data.thresholds.low}, high from {data.thresholds.medium}, critical from{' '}
              {data.thresholds.high}) · formula {data.formula}
              {data.rule_version != null ? ` · rule v${data.rule_version}` : ''}
            </span>
          </p>
          <p className="text-sm">
            Asset context: exposure <strong>{data.exposure ?? 'not set'}</strong> × {f(data.exposure_factor)}, impact{' '}
            <strong>{data.impact ?? 'not set'}</strong> × {f(data.impact_factor)} = context factor{' '}
            <strong>{f(data.context_factor)}</strong>. Each finding's base score is multiplied by it
            {data.exposure == null || data.impact == null ? ' (unclassified assets are assumed worst case)' : ''}.
          </p>
          {data.findings.length === 0 ? (
            <p className="muted">No active findings: score is 0.</p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>#</th><th>Finding</th><th>CVSS</th><th>EPSS</th><th>KEV</th>
                    <th>Base</th><th>× context</th><th>α</th><th>Contribution</th>
                    <th>{data.aggregation === 'decay' ? `Weight (×${data.decay} per rank)` : 'Weight'}</th>
                    <th>Counted</th>
                  </tr>
                </thead>
                <tbody>
                  {data.findings.map((x) => (
                    <tr key={x.event_id}>
                      <td>{x.rank + 1}</td>
                      <td>{x.cve_id ?? x.rule_name}<div className="muted text-xs">{x.rule_name}</div></td>
                      <td>{f(x.cvss, 1)}</td>
                      <td>{f(x.epss, 3)}</td>
                      <td>{x.in_kev ? (x.kev_floor_applied ? `Yes (floor ${data.kev_floor})` : 'Yes') : 'No'}</td>
                      <td>{f(x.s_base, 3)}</td>
                      <td>{f(x.s_context, 3)}</td>
                      <td>{f(x.alpha, 1)}</td>
                      <td>{f(x.contribution, 3)}</td>
                      <td>{f(x.weight, 3)}</td>
                      <td>{f(x.counted, 3)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {data.findings.length > 0 && (
            <p className="text-sm">
              Sum of the “Counted” column = <strong>{f(data.raw_sum, 3)}</strong>
              {data.raw_sum > 1 ? <> → capped at 1, so the score is <strong>{f(data.total, 3)}</strong></> : null}.
            </p>
          )}
          <p className="muted text-xs">
            {data.aggregation === 'decay'
              ? 'Findings are sorted by contribution; each one counts less than the previous (decay), so many medium findings add up without exceeding the cap.'
              : 'Findings are simply summed (older formula).'}{' '}
            The explanation is recomputed now; the stored score may be slightly older.
          </p>
        </>
      )}
    </section>
  )
}
