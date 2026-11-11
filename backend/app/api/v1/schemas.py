"""Response schemas for API v1.

These match the TypeScript interfaces in frontend/src/api/types.ts: keep the two in sync.
"""
import uuid
from datetime import date, datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, computed_field

from app.cases.sla import sla_status as compute_sla_status

T = TypeVar("T")


class _Orm(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):  # noqa: UP046 - explicit Generic keeps pydantic generic models portable
    items: list[T]
    total: int
    page: int
    size: int


class AssetOut(_Orm):
    id: uuid.UUID
    tenant_id: uuid.UUID
    hostname: str | None
    ip: str | None
    exposure: str | None
    impact: str | None
    created_at: datetime


class SoftwareOut(_Orm):
    id: uuid.UUID
    asset_id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    version: str | None
    cpe: str | None


class ScoreOut(_Orm):
    id: uuid.UUID
    tenant_id: uuid.UUID
    asset_id: uuid.UUID | None
    score_type: str
    value: float
    level: str
    epss_score: float | None
    computed_at: datetime
    score_rule_version: int | None


class ExposureMatchOut(_Orm):
    id: uuid.UUID
    tenant_id: uuid.UUID
    correlation_event_id: uuid.UUID | None
    status: str
    epss_score: float | None
    updated_at: datetime


class CorrelationEventOut(_Orm):
    id: uuid.UUID
    tenant_id: uuid.UUID | None
    rule_name: str
    asset_id: uuid.UUID | None
    identity_id: uuid.UUID | None
    vulnerability_id: uuid.UUID | None
    indicator_id: uuid.UUID | None
    s_context: float | None
    is_active: bool
    resolved_at: datetime | None
    created_at: datetime


class CaseOut(_Orm):
    id: uuid.UUID
    tenant_id: uuid.UUID
    title: str
    description: str | None
    status: str
    severity: str
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    due_at: datetime | None
    closed_at: datetime | None

    @computed_field
    @property
    def sla_status(self) -> str:
        return compute_sla_status(self.status, self.created_at, self.due_at, self.closed_at)


class CaseNoteOut(_Orm):
    id: uuid.UUID
    case_id: uuid.UUID
    author_id: uuid.UUID | None
    body: str
    created_at: datetime


class CaseEventOut(_Orm):
    id: uuid.UUID
    case_id: uuid.UUID
    actor_id: uuid.UUID | None
    event_type: str
    payload: dict | None
    created_at: datetime


class IdentityOut(_Orm):
    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str | None
    name: str | None
    created_at: datetime


class ThreatActorOut(_Orm):
    id: uuid.UUID
    tenant_id: uuid.UUID | None
    name: str
    aliases: list[str] | None
    description: str | None
    created_at: datetime


class CampaignOut(_Orm):
    id: uuid.UUID
    tenant_id: uuid.UUID | None
    name: str
    threat_actor_id: uuid.UUID | None
    description: str | None
    created_at: datetime


class IndicatorOut(_Orm):
    id: uuid.UUID
    tenant_id: uuid.UUID | None
    ioc_type: str
    value: str
    confidence: float | None
    created_at: datetime


class ObservationOut(_Orm):
    id: uuid.UUID
    tenant_id: uuid.UUID
    asset_id: uuid.UUID | None
    event_type: str
    payload: dict | None
    created_at: datetime


class VulnerabilityOut(_Orm):
    id: uuid.UUID
    cve_id: str
    cvss_score: float | None
    cvss_vector: str | None
    description: str | None
    mitre_techniques: list[str] | None
    kev_date_added: date | None
    epss_score: float | None


class LevelCount(BaseModel):
    level: str
    count: int


class DashboardOut(BaseModel):
    open_cases: int
    critical_scores: int
    active_exposures: int
    recent_events: list[CorrelationEventOut]
    scores_by_level: list[LevelCount]


class TrendPoint(BaseModel):
    date: date
    avg_score: float


class TopAssetOut(BaseModel):
    asset_id: uuid.UUID
    hostname: str | None
    ip: str | None
    value: float
    level: str


class QuickReportOut(BaseModel):
    tenant_id: uuid.UUID
    generated_at: datetime
    total_assets: int
    critical_assets: int
    open_cases: int
    assets_by_level: dict[str, int] = {}
    unscored_assets: int = 0
    top_assets: list[TopAssetOut] = []
    sla_breached_cases: int = 0
    sla_at_risk_cases: int = 0
    kev_vulnerabilities: int = 0
    leaks_total: int = 0
    darkweb_findings_new: int = 0
    top_vulnerabilities: list[VulnerabilityOut]
    risk_trend: list[TrendPoint]
