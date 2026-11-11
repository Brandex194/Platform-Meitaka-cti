// All UUIDs are strings; timestamps are ISO 8601 strings
export interface Tenant { id: string; name: string; slug: string; sector: string | null; created_at: string }
export type AssetExposure = 'internal' | 'dmz' | 'internet'
export type AssetImpact = 'low' | 'business' | 'critical'
export interface Asset { id: string; tenant_id: string; hostname: string | null; ip: string | null; exposure: AssetExposure | null; impact: AssetImpact | null; created_at: string }
export interface Software { id: string; asset_id: string; tenant_id: string; name: string; version: string | null; cpe: string | null }
export interface Vulnerability { id: string; cve_id: string; cvss_score: number | null; cvss_vector: string | null; description: string | null; mitre_techniques: string[] | null; kev_date_added: string | null; epss_score: number | null }
export interface Indicator { id: string; tenant_id: string | null; ioc_type: string; value: string; confidence: number | null; created_at: string }
export interface Leak { id: string; tenant_id: string; email_hash: string; breach_name: string; pwn_count: number | null; created_at: string }
export interface CorrelationEvent { id: string; tenant_id: string | null; rule_name: string; asset_id: string | null; identity_id: string | null; vulnerability_id: string | null; indicator_id: string | null; s_context: number | null; is_active: boolean; resolved_at: string | null; created_at: string }
export interface ExposureMatch { id: string; tenant_id: string; correlation_event_id: string | null; status: string; epss_score: number | null; updated_at: string }
export interface Score { id: string; tenant_id: string; asset_id: string | null; score_type: string; value: number; level: string; epss_score: number | null; computed_at: string; score_rule_version: number | null }
export interface ScoreRule { id: string; tenant_id: string | null; version: number; weights: { severity: number; confidence: number; recency: number; epss: number }; thresholds: { low: number; medium: number; high: number }; parameters: Record<string, unknown> | null; created_at: string; created_by: string | null }
export type CaseStatus = 'open' | 'in_progress' | 'closed' | 'false_positive'
export type SlaStatus = 'none' | 'on_track' | 'at_risk' | 'breached' | 'met'
export interface Case { id: string; tenant_id: string; title: string; description: string | null; status: string; severity: string; created_by: string | null; created_at: string; updated_at: string; due_at: string | null; closed_at: string | null; sla_status: SlaStatus }
export interface CaseNote { id: string; case_id: string; author_id: string | null; body: string; created_at: string }
export interface CaseEvent { id: string; case_id: string; actor_id: string | null; event_type: string; payload: Record<string, unknown> | null; created_at: string }
export interface Identity { id: string; tenant_id: string; email: string | null; name: string | null; created_at: string }
export interface ThreatActor { id: string; tenant_id: string | null; name: string; aliases: string[] | null; description: string | null; created_at: string }
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
  assets_by_level: Record<'critical' | 'high' | 'medium' | 'low', number>
  unscored_assets: number
  top_assets: { asset_id: string; hostname: string | null; ip: string | null; value: number; level: string }[]
  sla_breached_cases: number
  sla_at_risk_cases: number
  kev_vulnerabilities: number
  leaks_total: number
  darkweb_findings_new: number
  top_vulnerabilities: Vulnerability[]
  risk_trend: { date: string; avg_score: number }[]
}

export type ApiKeyStatus = 'active' | 'expired' | 'revoked'
export interface ApiKey { id: string; name: string; prefix: string; created_by: string | null; created_at: string; expires_at: string | null; revoked_at: string | null; last_used_at: string | null; status: ApiKeyStatus }
export interface ApiKeyCreated extends ApiKey { key: string }
export interface AuditEntry { id: string; actor_id: string | null; action: string; resource_type: string | null; resource_id: string | null; ip: string | null; status_code: number | null; payload: Record<string, unknown> | null; created_at: string }
export interface TenantInfo { id: string; name: string; slug: string; sector: string | null; created_at: string }

export interface StixCounts { indicators: number; threat_actors: number; campaigns: number; links: number }
export interface StixImportResult { created: StixCounts; duplicates: StixCounts; skipped_total: number; skipped: { id: string; type: string; reason: string }[] }

export interface Integration { provider: string; label: string; configured: boolean; updated_at: string | null }
export interface Enrichment { indicator_id: string; provider: string; status: 'ok' | 'not_found'; malicious: number | null; suspicious: number | null; harmless: number | null; undetected: number | null; reputation: number | null; analysis_date: string | null; permalink: string | null; fetched_at: string }

export interface GraphNode { id: string; type: 'threat_actor' | 'campaign' | 'indicator'; label: string; own: boolean; detail: string | null }
export interface GraphEdge { source: string; target: string; type: 'attributed-to' | 'indicates' }
export interface KnowledgeGraph { nodes: GraphNode[]; edges: GraphEdge[]; indicators_total: number; truncated: boolean }

export interface ScoreFinding { event_id: string; rule_name: string; cve_id: string | null; cvss: number | null; epss: number | null; in_kev: boolean; f_severity: number; f_confidence: number; f_recency: number; s_base: number; s_context: number; kev_floor_applied: boolean; alpha: number; contribution: number; rank: number; weight: number; counted: number }
export interface ScoreExplanation { asset_id: string; hostname: string | null; ip: string | null; formula: string; rule_id: string | null; rule_version: number | null; exposure: string | null; exposure_factor: number; impact: string | null; impact_factor: number; context_factor: number; findings: ScoreFinding[]; aggregation: 'decay' | 'sum'; decay: number | null; kev_floor: number | null; thresholds: { low: number; medium: number; high: number }; raw_sum: number; total: number; level: string }

export interface AttackTechnique { id: string; mitre_id: string; name: string; tactic: string | null }

export interface ConnectorStatus { provider: string; label: string; configured: boolean; updated_at: string | null }
