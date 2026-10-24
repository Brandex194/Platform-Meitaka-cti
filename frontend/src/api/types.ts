// All UUIDs are strings; timestamps are ISO 8601 strings
export interface Tenant { id: string; name: string; slug: string; sector: string | null; created_at: string }
export interface Asset { id: string; tenant_id: string; hostname: string | null; ip: string | null; created_at: string }
export interface Software { id: string; asset_id: string; tenant_id: string; name: string; version: string | null }
export interface Vulnerability { id: string; cve_id: string; cvss_score: number | null; cvss_vector: string | null; description: string | null; mitre_techniques: string[] | null; kev_date_added: string | null; epss_score: number | null }
export interface Indicator { id: string; tenant_id: string | null; ioc_type: string; value: string; confidence: number | null; created_at: string }
export interface Leak { id: string; tenant_id: string; email_hash: string; breach_name: string; pwn_count: number | null; created_at: string }
export interface CorrelationEvent { id: string; tenant_id: string | null; rule_name: string; asset_id: string | null; identity_id: string | null; vulnerability_id: string | null; indicator_id: string | null; s_context: number | null; is_active: boolean; resolved_at: string | null; created_at: string }
export interface ExposureMatch { id: string; tenant_id: string; correlation_event_id: string | null; status: string; epss_score: number | null; updated_at: string }
export interface Score { id: string; tenant_id: string; asset_id: string | null; score_type: string; value: number; level: string; epss_score: number | null; computed_at: string }
export interface ScoreRule { id: string; tenant_id: string | null; version: number; weights: { severity: number; confidence: number; recency: number; epss: number }; thresholds: { low: number; medium: number; high: number }; created_at: string; created_by: string | null }
export interface Case { id: string; tenant_id: string; title: string; description: string | null; status: string; severity: string; created_by: string | null; created_at: string; updated_at: string }
export interface Identity { id: string; tenant_id: string; email: string | null; name: string | null; created_at: string }
export interface ThreatActor { id: string; name: string; aliases: string[] | null; description: string | null; created_at: string }
export interface Campaign { id: string; tenant_id: string | null; name: string; threat_actor_id: string | null; description: string | null; created_at: string }
export interface AttackTechnique { id: string; mitre_id: string; name: string; tactic: string | null; description: string | null }
export interface Source { id: string; name: string; source_type: string; url: string | null; created_at: string }
export interface KevCatalog { id: string; cve_id: string; date_added: string | null; updated_at: string }
export interface FeedbackEvent { id: string; tenant_id: string | null; event_type: string; payload: Record<string, unknown> | null; created_at: string }
export interface AuditLog { id: string; tenant_id: string | null; actor_id: string | null; action: string; resource_type: string | null; resource_id: string | null; payload: Record<string, unknown> | null; created_at: string }
export interface PhishingDomain { id: string; tenant_id: string; domain: string; status: string; created_at: string }
export interface Observation { id: string; tenant_id: string; asset_id: string | null; event_type: string; payload: Record<string, unknown> | null; created_at: string }

// API response wrappers
export interface Paginated<T> { items: T[]; total: number; page: number; size: number }
export interface DashboardData {
  open_cases: number
  critical_scores: number
  active_exposures: number
  recent_events: CorrelationEvent[]
  scores_by_level: { level: string; count: number }[]
}
export interface QuickReport {
  tenant_id: string
  generated_at: string
  total_assets: number
  critical_assets: number
  open_cases: number
  top_vulnerabilities: Vulnerability[]
  risk_trend: { date: string; avg_score: number }[]
}
