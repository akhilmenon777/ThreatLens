"""API request/response models (exposed in the OpenAPI document at /docs)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer

STATUSES = ["new", "in_progress", "escalated", "resolved", "closed"]
Status = Literal["new", "in_progress", "escalated", "resolved", "closed"]


class UTCModel(BaseModel):
    """Serialise naive UTC datetimes with an explicit 'Z'."""
    model_config = ConfigDict(from_attributes=True)

    @field_serializer("*", when_used="json", check_fields=False)
    def _ser(self, v: Any):
        if isinstance(v, datetime):
            if v.tzinfo is None:
                v = v.replace(tzinfo=timezone.utc)
            return v.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        return v


class DatasetOut(UTCModel):
    id: int
    name: str
    version: str
    description: str
    synthetic: bool
    is_active: bool
    created_at: datetime
    has_labels: bool = False
    event_count: int = 0


class JobOut(UTCModel):
    id: int
    dataset_id: int
    filename: str
    sensor: str
    file_format: str
    status: str
    total_records: int
    accepted: int
    rejected: int
    duplicates: int
    with_warnings: int
    message: str
    started_at: datetime
    finished_at: datetime | None


class RejectedOut(UTCModel):
    line_number: int
    reason: str
    raw_excerpt: str


class RunOut(UTCModel):
    id: int
    dataset_id: int
    status: str
    started_at: datetime
    finished_at: datetime | None
    n_events: int
    n_signal_events: int
    n_links: int
    n_incidents: int
    n_unassigned: int
    duration_ms: float
    message: str


class IncidentListItem(UTCModel):
    id: str
    title: str
    severity: str
    risk_score: float
    confidence: float
    first_seen: datetime
    last_seen: datetime
    event_count: int
    sensors: list[str]
    entities: dict
    tactics: list[str]
    stages_present: list[str]
    status: str
    assignee: str | None
    suspected_false_positive: bool
    synthetic: bool


class StageOut(UTCModel):
    order: int
    stage: str
    status: str
    first_timestamp: datetime | None
    event_ids: list[str]
    observed_behavior: str
    evidence_strength: str
    confidence: float
    explanation: str


class MappingOut(UTCModel):
    tactic_id: str
    tactic_name: str
    technique_id: str | None
    technique_name: str | None
    method: str
    status: str
    confidence: float
    evidence_event_ids: list[str]
    reason: str
    attack_version: str
    url: str | None = None


class NoteOut(UTCModel):
    id: int
    author: str
    text: str
    created_at: datetime


class StatusChangeOut(UTCModel):
    from_status: str | None
    to_status: str
    actor: str
    reason: str
    created_at: datetime


class SummaryOut(UTCModel):
    id: int
    generator: str
    model: str
    model_version: str | None
    prompt_version: str
    status: str
    content: dict
    latency_ms: float
    attempts: int
    validation_errors: list
    injection_flags: list
    created_at: datetime
    is_current: bool = True


class IncidentDetail(IncidentListItem):
    description: str
    risk_breakdown: list[dict]
    confidence_breakdown: list[dict]
    alternative_explanations: list[str]
    correlation_notes: list[str]
    stages: list[StageOut]
    mappings: list[MappingOut]
    notes: list[NoteOut]
    status_changes: list[StatusChangeOut]
    summary: SummaryOut | None
    link_count: int
    run_id: int


class EventOut(UTCModel):
    event_id: str
    source_sensor: str
    source_log: str
    timestamp_utc: datetime
    event_type: str
    source_ip: str | None
    source_port: int | None
    destination_ip: str | None
    destination_port: int | None
    transport_protocol: str | None
    application_protocol: str | None
    destination_host: str | None
    alert_signature: str | None
    alert_signature_id: int | None
    alert_category: str | None
    sensor_severity: int | None
    connection_state: str | None
    bytes_sent: int | None
    bytes_received: int | None
    duration: float | None
    dns_query: str | None
    http_host: str | None
    http_uri: str | None
    http_user_agent: str | None
    tls_server_name: str | None
    auth_success: bool | None
    community_id: str | None
    flow_uid: str | None
    normalization_warnings: list
    detector_tags: list
    tag_evidence: dict
    original_event_reference: str
    incident_ids: list[str] = []
    ground_truth: dict | None = None  # dataset label (evaluation/display only), when the dataset has labels
    stage: str | None = None


class EventDetail(EventOut):
    raw_payload: str
    source_record_id: str | None
    schema_version: str


class LinkOut(BaseModel):
    event_a: str
    event_b: str
    score: float
    components: dict
    shared_entities: list
    dt_seconds: float
    rule: str
    explanation: str
    uncertainty: str


class Page(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[Any]


class IncidentUpdate(BaseModel):
    status: Status | None = None
    assignee: str | None = Field(None, max_length=100)
    suspected_false_positive: bool | None = None
    actor: str = Field("analyst", min_length=1, max_length=100)
    reason: str = Field("", max_length=1000)


class NoteIn(BaseModel):
    author: str = Field(..., min_length=1, max_length=100)
    text: str = Field(..., min_length=1, max_length=5000)


class SummaryRequest(BaseModel):
    mode: Literal["off", "cached", "live"] | None = None
    model: str | None = Field(None, max_length=120)


class EvaluationRequest(BaseModel):
    include_llm: bool = False
    models: list[str] | None = None
