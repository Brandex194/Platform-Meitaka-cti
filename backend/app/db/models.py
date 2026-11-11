"""SQLAlchemy 2.0 ORM models for Sentinel AI CTI platform."""
import uuid
from datetime import date, datetime
from typing import Optional

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func
from sqlalchemy.types import TIMESTAMP

from app.db.base import Base

# ---------------------------------------------------------------------------
# Tenant (root of multi-tenancy)
# ---------------------------------------------------------------------------


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    sector: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


# ---------------------------------------------------------------------------
# Asset
# ---------------------------------------------------------------------------


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    # Architettura §5.2 context: internal | dmz | internet, low | business | critical.
    # NULL = not classified yet; the ScoreRule decides the default factor.
    exposure: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    impact: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


# ---------------------------------------------------------------------------
# Software
# ---------------------------------------------------------------------------


class Software(Base):
    __tablename__ = "software"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    cpe: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


# ---------------------------------------------------------------------------
# Observation
# ---------------------------------------------------------------------------


class Observation(Base):
    __tablename__ = "observations"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


# ---------------------------------------------------------------------------
# Vulnerability
# ---------------------------------------------------------------------------


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    cve_id: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # shortcut: ARRAY not available in SQLite; stored as JSON for portability, upgrade to postgresql.ARRAY on Postgres-only path
    mitre_techniques: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    kev_date_added: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    epss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    # shortcut: NVD CPE configuration nodes stored as JSON; populated in Phase 2 from NVD API
    cpe_nodes: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)


# ---------------------------------------------------------------------------
# Indicator (IoC)
# ---------------------------------------------------------------------------


class Indicator(Base):
    __tablename__ = "indicators"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True
    )
    ioc_type: Mapped[str] = mapped_column(String(50), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


# ---------------------------------------------------------------------------
# Leak
# ---------------------------------------------------------------------------


class Leak(Base):
    __tablename__ = "leaks"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    email_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256
    breach_name: Mapped[str] = mapped_column(String(255), nullable=False)
    pwn_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


# ---------------------------------------------------------------------------
# PhishingDomain
# ---------------------------------------------------------------------------


class PhishingDomain(Base):
    __tablename__ = "phishing_domains"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


# ---------------------------------------------------------------------------
# CorrelationEvent
# ---------------------------------------------------------------------------


class CorrelationEvent(Base):
    __tablename__ = "correlation_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True
    )
    rule_name: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    identity_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("identities.id", ondelete="SET NULL"), nullable=True
    )
    vulnerability_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True
    )
    indicator_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("indicators.id", ondelete="SET NULL"), nullable=True
    )
    s_context: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )

    def __init__(self, **kwargs: object) -> None:
        # SA 2.0 mapped_column default= is insert-time only; set Python default here
        kwargs.setdefault("is_active", True)
        super().__init__(**kwargs)


# ---------------------------------------------------------------------------
# ExposureMatch
# ---------------------------------------------------------------------------


class ExposureMatch(Base):
    __tablename__ = "exposure_matches"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    correlation_event_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("correlation_events.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(50), default="active", server_default="active", nullable=False
    )
    epss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


# ---------------------------------------------------------------------------
# Score
# ---------------------------------------------------------------------------


class Score(Base):
    __tablename__ = "scores"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    score_type: Mapped[str] = mapped_column(String(50), nullable=False)
    value: Mapped[float] = mapped_column(Float, nullable=False)
    level: Mapped[str] = mapped_column(String(20), nullable=False)
    epss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    computed_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    # Which ScoreRule produced this value: old scores keep pointing at the old rule.
    score_rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("score_rules.id", ondelete="SET NULL"), nullable=True
    )
    score_rule_version: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)


# ---------------------------------------------------------------------------
# ScoreRule
# ---------------------------------------------------------------------------


class ScoreRule(Base):
    __tablename__ = "score_rules"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True
    )
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    weights: Mapped[dict] = mapped_column(
        JSON,
        default=lambda: {"severity": 0.5, "confidence": 0.3, "recency": 0.2, "epss": 0.0},
        server_default='{"severity": 0.5, "confidence": 0.3, "recency": 0.2, "epss": 0.0}',
    )
    thresholds: Mapped[dict] = mapped_column(
        JSON,
        default=lambda: {"low": 0.2, "medium": 0.4, "high": 0.7},
        server_default='{"low": 0.2, "medium": 0.4, "high": 0.7}',
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(nullable=True)
    # Overrides of app.risk.formulas.DEFAULT_PARAMETERS (exposure/impact factors, α, recency steps...).
    parameters: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    def __init__(self, **kwargs: object) -> None:
        # SA 2.0 mapped_column default= is insert-time only; set Python defaults here
        kwargs.setdefault("weights", {"severity": 0.5, "confidence": 0.3, "recency": 0.2, "epss": 0.0})
        kwargs.setdefault("thresholds", {"low": 0.2, "medium": 0.4, "high": 0.7})
        super().__init__(**kwargs)


# ---------------------------------------------------------------------------
# Case
# ---------------------------------------------------------------------------


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(50), default="open", server_default="open", nullable=False
    )
    severity: Mapped[str] = mapped_column(
        String(20), default="medium", server_default="medium", nullable=False
    )
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    # SLA (app/cases/sla.py): deadline from the severity, and when the case was closed.
    due_at: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    closed_at: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP(timezone=True), nullable=True)


class CaseNote(Base):
    __tablename__ = "case_notes"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    author_id: Mapped[Optional[uuid.UUID]] = mapped_column(nullable=True)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


class CaseEvent(Base):
    """One line of a case timeline: created, status or severity changed, edited, note added."""

    __tablename__ = "case_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(nullable=True)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    payload: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


class Identity(Base):
    __tablename__ = "identities"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    email: Mapped[Optional[str]] = mapped_column(String(320), nullable=True)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


# ---------------------------------------------------------------------------
# ThreatActor
# ---------------------------------------------------------------------------


class ThreatActor(Base):
    __tablename__ = "threat_actors"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    # NULL = shared catalog entry; otherwise created by that tenant. No RLS (like campaigns):
    # the routes filter explicitly.
    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    aliases: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


# ---------------------------------------------------------------------------
# Campaign
# ---------------------------------------------------------------------------


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    threat_actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("threat_actors.id", ondelete="SET NULL"), nullable=True
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


# ---------------------------------------------------------------------------
# AttackTechnique
# ---------------------------------------------------------------------------


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    mitre_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactic: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


# ---------------------------------------------------------------------------
# Source
# ---------------------------------------------------------------------------


class Source(Base):
    __tablename__ = "sources"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)
    url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


# ---------------------------------------------------------------------------
# KevCatalog
# ---------------------------------------------------------------------------


class KevCatalog(Base):
    __tablename__ = "kev_catalog"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    cve_id: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    date_added: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


# ---------------------------------------------------------------------------
# FeedbackEvent
# ---------------------------------------------------------------------------


class FeedbackEvent(Base):
    __tablename__ = "feedback_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True
    )
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


# ---------------------------------------------------------------------------
# AuditLog
# ---------------------------------------------------------------------------


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True
    )
    actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(nullable=True)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[Optional[uuid.UUID]] = mapped_column(nullable=True)
    payload: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    # Passo 8: who called from where, and what came back.
    ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    status_code: Mapped[Optional[int]] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


# ---------------------------------------------------------------------------
# ApiKey (passo 8): programmatic access, one tenant, role api_user
# ---------------------------------------------------------------------------


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    # First characters of the key, shown in the UI to recognise it. The key itself is never stored.
    prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP(timezone=True), nullable=True)


# ---------------------------------------------------------------------------
# IntegrationKey (passo 10): a tenant's API key for a third-party service, encrypted
# ---------------------------------------------------------------------------


class IntegrationKey(Base):
    __tablename__ = "integration_keys"
    __table_args__ = (UniqueConstraint("tenant_id", "provider", name="uq_integration_tenant_provider"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    # Fernet ciphertext. The plain key is never stored and never returned by any route.
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    updated_by: Mapped[Optional[uuid.UUID]] = mapped_column(nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


# ---------------------------------------------------------------------------
# IndicatorEnrichment (passo 10): what an external service says about an indicator
# ---------------------------------------------------------------------------


class IndicatorEnrichment(Base):
    __tablename__ = "indicator_enrichments"
    __table_args__ = (UniqueConstraint("indicator_id", "tenant_id", "provider", name="uq_enrichment"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    indicator_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # ok | not_found
    malicious: Mapped[Optional[int]] = mapped_column(nullable=True)
    suspicious: Mapped[Optional[int]] = mapped_column(nullable=True)
    harmless: Mapped[Optional[int]] = mapped_column(nullable=True)
    undetected: Mapped[Optional[int]] = mapped_column(nullable=True)
    reputation: Mapped[Optional[int]] = mapped_column(nullable=True)
    analysis_date: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    permalink: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


# ---------------------------------------------------------------------------
# CampaignIndicator (passo 11): "this indicator is seen in that campaign", per tenant
# ---------------------------------------------------------------------------


class CampaignIndicator(Base):
    __tablename__ = "campaign_indicators"
    __table_args__ = (UniqueConstraint("tenant_id", "campaign_id", "indicator_id", name="uq_campaign_indicator"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True
    )
    indicator_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
