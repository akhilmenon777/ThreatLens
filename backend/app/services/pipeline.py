"""DB orchestration of the analysis pipeline:
detectors → correlation → incident formation → attack chain → ATT&CK → scoring.

Re-running correlation is idempotent for unchanged evidence: incident IDs are
derived from the member-event fingerprint, so an analyst's status, assignee,
notes and summaries survive a re-run when the incident's membership is unchanged.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from app.attack_mapping.catalog import get_catalog
from app.core.config import AnalysisSettings
from app.correlation.detectors import run_detectors
from app.correlation.engine import correlate
from app.correlation.model import EventView, from_orm
from app.models import (AttackMapping, AttackStage, CorrelationRun, Dataset, Event, EventLink, Incident,
                        IncidentEvent)
from app.services.incident_builder import IncidentDraft, build_incident


_VIEW_COLS = (Event.event_id, Event.timestamp_utc, Event.source_sensor, Event.source_log, Event.event_type,
              Event.source_ip, Event.destination_ip, Event.source_port, Event.destination_port,
              Event.transport_protocol, Event.application_protocol, Event.alert_signature, Event.alert_signature_id,
              Event.alert_category, Event.sensor_severity, Event.connection_state, Event.bytes_sent,
              Event.bytes_received, Event.duration, Event.dns_query, Event.http_host, Event.destination_host,
              Event.tls_server_name, Event.auth_success, Event.community_id, Event.flow_uid,
              Event.normalization_warnings)


def load_views(session: Session, dataset_id: int) -> list[EventView]:
    """Column-level load (no ORM objects, no raw payload) – fast on 100k+ events."""
    rows = session.execute(select(*_VIEW_COLS).where(Event.dataset_id == dataset_id)
                           .order_by(Event.timestamp_utc)).all()
    return [from_orm(r) for r in rows]


def analyse(views: list[EventView], settings: AnalysisSettings):
    """Pure analysis used by both the API pipeline and the evaluation lab."""
    catalog = get_catalog()
    tag_counts = run_detectors(views, settings.correlation, catalog)
    result = correlate(views, settings.correlation)
    by_id = {v.event_id: v for v in views}
    drafts = [build_incident(g, by_id, catalog, settings) for g in result.groups]
    return tag_counts, result, drafts


def incident_id(fingerprint: str) -> str:
    return "INC-" + fingerprint[:8].upper()


def run_correlation(session: Session, dataset: Dataset, settings: AnalysisSettings, progress=None) -> CorrelationRun:
    t0 = time.perf_counter()
    say = progress or (lambda *_: None)
    run = CorrelationRun(dataset_id=dataset.id, params=settings.correlation.model_dump(), status="running")
    session.add(run)
    session.flush()

    say(0.70, "Loading events for analysis…")
    views = load_views(session, dataset.id)
    say(0.75, f"Running detectors and correlation on {len(views):,} events…")
    tag_counts, result, drafts = analyse(views, settings)
    say(0.88, f"Saving {len(drafts):,} incidents…")

    # persist detector tags: rows tagged now, plus rows tagged by a previous run (to clear stale tags)
    previously = set(session.scalars(select(Event.event_id).where(
        Event.dataset_id == dataset.id, func.json_array_length(Event.detector_tags) > 0)))
    session.bulk_update_mappings(Event, [
        {"event_id": v.event_id, "detector_tags": sorted(v.tags), "tag_evidence": dict(v.tag_evidence)}
        for v in views if v.tags or v.event_id in previously])

    session.execute(update(CorrelationRun).where(CorrelationRun.dataset_id == dataset.id,
                                                 CorrelationRun.id != run.id).values(is_current=False))
    old = {i.fingerprint: i for i in session.scalars(select(Incident).where(Incident.dataset_id == dataset.id))}
    new_fps = {d.fingerprint for d in drafts}
    for fp, inc in old.items():
        if fp not in new_fps:
            session.delete(inc)
    session.flush()
    old_run_ids = select(CorrelationRun.id).where(CorrelationRun.dataset_id == dataset.id, CorrelationRun.id != run.id)
    session.execute(delete(EventLink).where(EventLink.run_id.in_(old_run_ids)))

    for d in drafts:
        _persist(session, run, dataset, d, old.get(d.fingerprint))

    run.n_events = len(views)
    run.n_signal_events = len(result.signal_ids)
    run.n_links = result.n_links
    run.n_incidents = len(drafts)
    run.n_unassigned = len(result.unassigned)
    run.duration_ms = round((time.perf_counter() - t0) * 1000, 1)
    run.status = "completed"
    run.finished_at = datetime.now(timezone.utc).replace(tzinfo=None)
    run.message = (f"{len(views)} events, {len(result.signal_ids)} signal events, {result.n_candidates} candidate pairs, "
                   f"{result.n_links} links, {len(drafts)} incidents"
                   + (f"; popular entities excluded from single-IP linking: {', '.join(result.popular_entities)}"
                      if result.popular_entities else ""))
    run.params = {**settings.correlation.model_dump(), "detector_tag_counts": tag_counts}
    session.flush()
    say(0.95, "Pre-computing dashboard analytics…")
    try:  # warm the dashboard caches so the first page view after a (large) run is instant
        from app.services.analytics import analytics
        from app.services.queries import overview
        analytics(session, dataset)
        overview(session, dataset)
    except Exception:  # noqa: BLE001 - caching is best effort
        pass
    return run


def _persist(session: Session, run: CorrelationRun, dataset: Dataset, d: IncidentDraft, existing: Incident | None):
    iid = incident_id(d.fingerprint)
    if existing is not None:
        inc = existing
        session.execute(delete(AttackStage).where(AttackStage.incident_id == iid))
        session.execute(delete(AttackMapping).where(AttackMapping.incident_id == iid))
        session.execute(delete(IncidentEvent).where(IncidentEvent.incident_id == iid))
        session.expire(inc, ["stages", "mappings"])
    else:
        inc = Incident(id=iid, status="new", fingerprint=d.fingerprint)
        session.add(inc)
    inc.run_id = run.id
    inc.dataset_id = dataset.id
    inc.title = d.title
    inc.description = d.description
    inc.first_seen = d.first_seen
    inc.last_seen = d.last_seen
    inc.event_count = len(d.event_ids)
    inc.sensors = d.sensors
    inc.entities = d.entities
    inc.tactics = d.tactics
    inc.stages_present = [s.stage for s in d.stages if s.status != "NOT_OBSERVED"]
    inc.severity = d.severity
    inc.risk_score = d.risk_score
    inc.risk_breakdown = d.risk_breakdown
    inc.confidence = d.confidence
    inc.confidence_breakdown = d.confidence_breakdown
    inc.alternative_explanations = d.alternative_explanations
    inc.correlation_notes = d.notes
    inc.evidence_hash = d.evidence_hash
    inc.synthetic = dataset.synthetic
    session.flush()
    session.bulk_insert_mappings(IncidentEvent, [
        {"incident_id": iid, "event_id": eid, "stage": d.stage_of_event.get(eid)} for eid in d.event_ids])
    session.add_all(AttackStage(incident_id=iid, order=s.order, stage=s.stage, status=s.status,
                                first_timestamp=s.first_ts, event_ids=s.event_ids[:200],
                                observed_behavior=s.observed_behavior, evidence_strength=s.evidence_strength,
                                confidence=s.confidence, explanation=s.explanation) for s in d.stages)
    session.add_all(AttackMapping(incident_id=iid, tactic_id=m.tactic_id, tactic_name=m.tactic_name,
                                  technique_id=m.technique_id, technique_name=m.technique_name, method=m.method,
                                  status=m.status, confidence=m.confidence, evidence_event_ids=m.evidence_event_ids,
                                  reason=m.reason, attack_version=get_catalog().version) for m in d.mappings)
    session.bulk_insert_mappings(EventLink, [
        {"run_id": run.id, "incident_id": iid, "event_a": l.a, "event_b": l.b, "score": l.score,
         "components": l.components, "shared_entities": l.shared, "dt_seconds": l.dt_seconds, "rule": l.rule,
         "explanation": l.explanation, "uncertainty": l.uncertainty}
        for l in d.links])
