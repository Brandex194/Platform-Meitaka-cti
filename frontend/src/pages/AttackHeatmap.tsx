import { ErrorMessage } from '@/components/ErrorMessage'
import { useAttackTechniques } from '@/api/hooks/useAttack'

const TACTIC_ORDER = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
]

const TACTIC_SHORT: Record<string, string> = {
  'Reconnaissance': 'Recon', 'Resource Development': 'Res Dev', 'Initial Access': 'Init',
  'Execution': 'Exec', 'Persistence': 'Persist', 'Privilege Escalation': 'PrivEsc',
  'Defense Evasion': 'Def Eva', 'Credential Access': 'Creds', 'Discovery': 'Discov',
  'Lateral Movement': 'Lat Mov', 'Collection': 'Collect', 'Command and Control': 'C2',
  'Exfiltration': 'Exfil', 'Impact': 'Impact',
}

export function AttackHeatmap({ tenantId }: { tenantId: string }) {
  const { data, isLoading, error } = useAttackTechniques()

  if (error) return <ErrorMessage error={error as Error} />

  const byTactic: Record<string, typeof data> = {}
  for (const t of data ?? []) {
    const tactic = t.tactic ?? 'Other'
    if (!byTactic[tactic]) byTactic[tactic] = []
    byTactic[tactic]!.push(t)
  }

  const tactics = TACTIC_ORDER.filter((t) => byTactic[t]?.length)
  const other = byTactic['Other'] ?? []
  const maxRows = Math.max(...tactics.map((t) => byTactic[t]!.length), other.length, 1)

  return (
    <div className="space-y-3">
      <p className="text-sm muted">
        MITRE ATT&amp;CK Enterprise technique catalog. {data?.length ?? 0} techniques loaded.
      </p>
      {isLoading ? (
        <div className="muted text-sm">Loading techniques…</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="text-xs border-collapse" style={{ minWidth: `${(tactics.length + (other.length ? 1 : 0)) * 112}px` }}>
            <thead>
              <tr>
                {tactics.map((tactic) => (
                  <th
                    key={tactic}
                    className="text-left font-semibold px-2 py-1.5 whitespace-nowrap"
                    style={{
                      width: 112, minWidth: 112,
                      background: 'rgba(82,182,255,.08)',
                      border: '1px solid var(--border2)',
                      color: 'var(--accent)',
                      fontSize: '0.65rem',
                      letterSpacing: '.04em',
                    }}
                    title={tactic}
                  >
                    {TACTIC_SHORT[tactic] ?? tactic}
                  </th>
                ))}
                {other.length > 0 && (
                  <th
                    className="text-left font-semibold px-2 py-1.5"
                    style={{ width: 112, minWidth: 112, background: 'rgba(255,255,255,.03)', border: '1px solid var(--border)', color: 'var(--text3)', fontSize: '0.65rem' }}
                  >
                    Other
                  </th>
                )}
              </tr>
            </thead>
            <tbody>
              {Array.from({ length: maxRows }, (_, i) => (
                <tr key={i}>
                  {tactics.map((tactic) => {
                    const technique = byTactic[tactic]?.[i]
                    return (
                      <td
                        key={tactic}
                        style={{ border: '1px solid var(--border)', padding: '3px 6px', verticalAlign: 'top', background: technique ? 'rgba(82,182,255,.05)' : 'transparent' }}
                      >
                        {technique && (
                          <span title={technique.name} style={{ cursor: 'default' }}>
                            <span style={{ color: 'var(--text3)', fontFamily: 'var(--mono)' }}>{technique.mitre_id}</span>
                            {' '}
                            <span style={{ color: 'var(--text)' }}>{technique.name.length > 22 ? technique.name.slice(0, 20) + '…' : technique.name}</span>
                          </span>
                        )}
                      </td>
                    )
                  })}
                  {other.length > 0 && (
                    <td style={{ border: '1px solid var(--border)', padding: '3px 6px', verticalAlign: 'top' }}>
                      {other[i] && (
                        <span>
                          <span style={{ color: 'var(--text3)', fontFamily: 'var(--mono)' }}>{other[i]!.mitre_id}</span>
                          {' '}{other[i]!.name.slice(0, 20)}
                        </span>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
