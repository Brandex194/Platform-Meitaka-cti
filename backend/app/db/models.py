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
        default=lambda: {"severity": 0.45, "confidence": 0.27, "recency": 0.18, "epss": 0.10},
    )
    thresholds: Mapped[dict] = mapped_column(
        JSON,
        default=lambda: {"low": 0.2, "medium": 0.4, "high": 0.7},
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(nullable=True)

    def __init__(self, **kwargs: object) -> None:
        # SA 2.0 mapped_column default= is insert-time only; set Python defaults here
        kwargs.setdefault("weights", {"severity": 0.45, "confidence": 0.27, "recency": 0.18, "epss": 0.10})
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
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[Optional[uuid.UUID]] = mapped_column(nullable=True)
    payload: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
