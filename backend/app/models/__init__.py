"""SQLAlchemy ORM models. See docs/ARCHITECTURE.md for the entity diagram."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text,
                        UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Dataset(Base):
    __tablename__ = "datasets"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    version: Mapped[str] = mapped_column(String(50), default="1")
    description: Mapped[str] = mapped_column(Text, default="")
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    labels: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # evaluation ground truth, never read by the engine


class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id", ondelete="CASCADE"), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    sensor: Mapped[str] = mapped_column(String(20))
    file_format: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(20), default="running")
    total_records: Mapped[int] = mapped_column(Integer, default=0)
    accepted: Mapped[int] = mapped_column(Integer, default=0)
    rejected: Mapped[int] = mapped_column(Integer, default=0)
    duplicates: Mapped[int] = mapped_column(Integer, default=0)
    with_warnings: Mapped[int] = mapped_column(Integer, default=0)
    message: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    rejected_records: Mapped[list["RejectedRecord"]] = relationship(cascade="all, delete-orphan")


class RejectedRecord(Base):
    __tablename__ = "rejected_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("ingestion_jobs.id", ondelete="CASCADE"), index=True)
    line_number: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(Text)
    raw_excerpt: Mapped[str] = mapped_column(Text)


class Event(Base):
    """Normalized event (common schema v1). ``raw_payload`` keeps the original record."""
    __tablename__ = "events"
    __table_args__ = (
        UniqueConstraint("dataset_id", "content_hash", name="uq_event_dataset_hash"),
        Index("ix_events_ds_ts", "dataset_id", "timestamp_utc"),
    )
    event_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id", ondelete="CASCADE"), index=True)
    job_id: Mapped[int | None] = mapped_column(ForeignKey("ingestion_jobs.id", ondelete="SET NULL"), nullable=True)
    schema_version: Mapped[str] = mapped_column(String(10), default="1.0")
    source_sensor: Mapped[str] = mapped_column(String(20), index=True)
    source_log: Mapped[str] = mapped_column(String(30))
    source_record_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    timestamp_utc: Mapped[datetime] = mapped_column(DateTime, index=True)
    event_type: Mapped[str] = mapped_column(String(40), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    transport_protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    application_protocol: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    destination_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    user_identity: Mapped[str | None] = mapped_column(String(255), nullable=True)
    alert_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    alert_signature_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    alert_category: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sensor_severity: Mapped[int | None] = mapped_column(Integer, nullable=True)
    connection_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    bytes_sent: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes_received: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration: Mapped[float | None] = mapped_column(Float, nullable=True)
    dns_query: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_host: Mapped[str | None] = mapped_column(String(512), nullable=True)
    http_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    tls_server_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    auth_success: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    community_id: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    flow_uid: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    original_event_reference: Mapped[str] = mapped_column(String(300))
    raw_payload: Mapped[str] = mapped_column(Text)
    normalization_warnings: Mapped[list] = mapped_column(JSON, default=list)
    detector_tags: Mapped[list] = mapped_column(JSON, default=list)
    tag_evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    content_hash: Mapped[str] = mapped_column(String(64))


class EventLabel(Base):
    """Ground-truth label shipped with a labelled dataset (e.g. UWF-ZeekData24 MITRE tactic labels).

    Used ONLY by the evaluation lab and the dataset-analytics view. Detectors, the
    correlation engine, scoring and the LLM never read this table."""
    __tablename__ = "event_labels"
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    malicious: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    tactics: Mapped[list] = mapped_column(JSON, default=list)
    techniques: Mapped[list] = mapped_column(JSON, default=list)


class CorrelationRun(Base):
    __tablename__ = "correlation_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id", ondelete="CASCADE"), index=True)
    method: Mapped[str] = mapped_column(String(40), default="evidence_aware")
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="running")
    n_events: Mapped[int] = mapped_column(Integer, default=0)
    n_signal_events: Mapped[int] = mapped_column(Integer, default=0)
    n_links: Mapped[int] = mapped_column(Integer, default=0)
    n_incidents: Mapped[int] = mapped_column(Integer, default=0)
    n_unassigned: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[float] = mapped_column(Float, default=0)
    is_current: Mapped[bool] = mapped_column(Boolean, default=True)
    message: Mapped[str] = mapped_column(Text, default="")


class EventLink(Base):
    __tablename__ = "event_links"
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("correlation_runs.id", ondelete="CASCADE"), index=True)
    incident_id: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    event_a: Mapped[str] = mapped_column(String(40))
    event_b: Mapped[str] = mapped_column(String(40))
    score: Mapped[float] = mapped_column(Float)
    components: Mapped[dict] = mapped_column(JSON)
    shared_entities: Mapped[list] = mapped_column(JSON)
    dt_seconds: Mapped[float] = mapped_column(Float)
    rule: Mapped[str] = mapped_column(String(80))
    explanation: Mapped[str] = mapped_column(Text)
    uncertainty: Mapped[str] = mapped_column(Text, default="")


class Analyst(Base):
    __tablename__ = "analysts"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(20), primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("correlation_runs.id", ondelete="CASCADE"), index=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime)
    event_count: Mapped[int] = mapped_column(Integer)
    sensors: Mapped[list] = mapped_column(JSON)
    entities: Mapped[dict] = mapped_column(JSON)
    tactics: Mapped[list] = mapped_column(JSON, default=list)
    stages_present: Mapped[list] = mapped_column(JSON, default=list)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    risk_score: Mapped[float] = mapped_column(Float, index=True)
    risk_breakdown: Mapped[list] = mapped_column(JSON)
    confidence: Mapped[float] = mapped_column(Float)
    confidence_breakdown: Mapped[list] = mapped_column(JSON)
    alternative_explanations: Mapped[list] = mapped_column(JSON, default=list)
    correlation_notes: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(30), default="new", index=True)
    assignee: Mapped[str | None] = mapped_column(String(100), nullable=True)
    suspected_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    evidence_hash: Mapped[str] = mapped_column(String(64))
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    stages: Mapped[list["AttackStage"]] = relationship(cascade="all, delete-orphan", order_by="AttackStage.order")
    mappings: Mapped[list["AttackMapping"]] = relationship(cascade="all, delete-orphan")
    notes: Mapped[list["AnalystNote"]] = relationship(cascade="all, delete-orphan", order_by="AnalystNote.created_at")
    status_changes: Mapped[list["StatusChange"]] = relationship(cascade="all, delete-orphan",
                                                                order_by="StatusChange.created_at")
    summaries: Mapped[list["AISummary"]] = relationship(cascade="all, delete-orphan",
                                                        order_by="AISummary.created_at")


class IncidentEvent(Base):
    __tablename__ = "incident_events"
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.event_id", ondelete="CASCADE"), primary_key=True, index=True)
    stage: Mapped[str | None] = mapped_column(String(40), nullable=True)


class AttackStage(Base):
    __tablename__ = "attack_stages"
    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    order: Mapped[int] = mapped_column(Integer)
    stage: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20))  # OBSERVED | INFERRED | NOT_OBSERVED
    first_timestamp: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    observed_behavior: Mapped[str] = mapped_column(Text, default="")
    evidence_strength: Mapped[str] = mapped_column(String(20), default="none")
    confidence: Mapped[float] = mapped_column(Float, default=0)
    explanation: Mapped[str] = mapped_column(Text, default="")


class AttackMapping(Base):
    __tablename__ = "attack_mappings"
    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    tactic_id: Mapped[str] = mapped_column(String(10))
    tactic_name: Mapped[str] = mapped_column(String(60))
    technique_id: Mapped[str | None] = mapped_column(String(15), nullable=True)
    technique_name: Mapped[str | None] = mapped_column(String(150), nullable=True)
    method: Mapped[str] = mapped_column(String(40))  # signature | behavioral
    status: Mapped[str] = mapped_column(String(20))  # OBSERVED | INFERRED
    confidence: Mapped[float] = mapped_column(Float)
    evidence_event_ids: Mapped[list] = mapped_column(JSON)
    reason: Mapped[str] = mapped_column(Text)
    attack_version: Mapped[str] = mapped_column(String(30))


class AISummary(Base):
    __tablename__ = "ai_summaries"
    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    generator: Mapped[str] = mapped_column(String(20))  # llm | fallback
    model: Mapped[str] = mapped_column(String(120))
    model_version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    prompt_version: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20))  # valid | fallback | invalid
    content: Mapped[dict] = mapped_column(JSON)
    evidence_hash: Mapped[str] = mapped_column(String(64))
    latency_ms: Mapped[float] = mapped_column(Float, default=0)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    validation_errors: Mapped[list] = mapped_column(JSON, default=list)
    injection_flags: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AnalystNote(Base):
    __tablename__ = "analyst_notes"
    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    author: Mapped[str] = mapped_column(String(100))
    text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class StatusChange(Base):
    __tablename__ = "status_changes"
    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    from_status: Mapped[str | None] = mapped_column(String(30), nullable=True)
    to_status: Mapped[str] = mapped_column(String(30))
    actor: Mapped[str] = mapped_column(String(100))
    reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    status: Mapped[str] = mapped_column(String(20), default="running")
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    results: Mapped[dict] = mapped_column(JSON, default=dict)
    duration_ms: Mapped[float] = mapped_column(Float, default=0)
    message: Mapped[str] = mapped_column(Text, default="")


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(50), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
