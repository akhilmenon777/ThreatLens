"""Summary orchestration: cache → live local model (validated, bounded retries) → fallback.

The model can never change correlation, risk or database records: its output is
only stored as a separate AISummary row after validation.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import AnalysisSettings
from app.llm import client
from app.llm.fallback import build_fallback
from app.llm.prompt import PROMPT_VERSION, SYSTEM_PROMPT, build_prompt
from app.llm.sanitize import build_incident_payload
from app.llm.validate import parse_and_validate
from app.models import AISummary, Event, Incident, IncidentEvent


def _members(session: Session, incident: Incident) -> list[Event]:
    return list(session.scalars(select(Event).join(IncidentEvent, IncidentEvent.event_id == Event.event_id)
                                .where(IncidentEvent.incident_id == incident.id).order_by(Event.timestamp_utc)))


def latest_valid(incident: Incident, generator: str | None = None) -> AISummary | None:
    for s in reversed(incident.summaries):
        if s.evidence_hash == incident.evidence_hash and s.status in ("valid", "fallback"):
            if generator is None or s.generator == generator:
                return s
    return None


def _store_fallback(session: Session, incident: Incident, payload: dict, flags: list, reason: str,
                    errors: list[str] | None = None, attempts: int = 0, model_tried: str | None = None) -> AISummary:
    fb = build_fallback(payload)
    row = AISummary(incident_id=incident.id, generator="fallback", model="deterministic-template",
                    model_version=PROMPT_VERSION, prompt_version=PROMPT_VERSION, status="fallback",
                    content={**fb.model_dump(), "fallback_reason": reason, "model_attempted": model_tried},
                    evidence_hash=incident.evidence_hash, latency_ms=0, attempts=attempts,
                    validation_errors=errors or [], injection_flags=flags)
    session.add(row)
    session.flush()
    return row


def summarize(session: Session, incident: Incident, settings: AnalysisSettings, mode: str | None = None,
              model: str | None = None) -> AISummary:
    llm = settings.llm
    mode = mode or llm.mode
    members = _members(session, incident)
    payload, flags = build_incident_payload(incident, members, llm.max_events_in_prompt)

    if mode == "off":
        return _store_fallback(session, incident, payload, flags, "AI mode is Off")
    if mode == "cached":
        cached = latest_valid(incident, "llm")
        if cached:
            return cached
        prev = latest_valid(incident)
        if prev:
            return prev
        return _store_fallback(session, incident, payload, flags,
                               "Cached mode: no LLM summary exists for the current evidence yet")

    model_name = model or llm.primary_model
    member_ids = {e.event_id for e in members}
    res = run_model(payload, member_ids, settings, model_name)
    if res["error"]:
        return _store_fallback(session, incident, payload, flags, res["error"], res["validation_errors"],
                               res["attempts"], model_name)
    if res["summary"] is not None:
        row = AISummary(incident_id=incident.id, generator="llm", model=res["model"], model_version=res["model_version"],
                        prompt_version=PROMPT_VERSION, status="valid", content=res["summary"].model_dump(),
                        evidence_hash=incident.evidence_hash, latency_ms=res["latency_ms"],
                        attempts=res["attempts"], validation_errors=[], injection_flags=flags)
        session.add(row)
        session.flush()
        return row
    # keep the rejected output for auditability, then fall back
    session.add(AISummary(incident_id=incident.id, generator="llm", model=model_name, prompt_version=PROMPT_VERSION,
                          status="invalid", content={"raw_excerpt": (res["raw"] or "")[:4000]},
                          evidence_hash=incident.evidence_hash, latency_ms=res["latency_ms"],
                          attempts=res["attempts"], validation_errors=res["validation_errors"], injection_flags=flags))
    return _store_fallback(session, incident, payload, flags,
                           f"Model output failed validation after {res['attempts']} attempt(s)",
                           res["validation_errors"], res["attempts"], model_name)


def run_model(payload: dict, member_ids: set[str], settings: AnalysisSettings, model_name: str) -> dict:
    """Call the local model with bounded retries; never touches the database."""
    llm = settings.llm
    errors: list[str] = []
    attempts, total_latency, raw, returned = 0, 0.0, None, model_name
    version = client.server_version(llm.ollama_base_url)
    for attempt in range(llm.max_retries + 1):
        attempts += 1
        try:
            res = client.generate(llm.ollama_base_url, model_name, SYSTEM_PROMPT,
                                  build_prompt(payload, errors if attempt else None), llm.timeout_seconds,
                                  llm.temperature)
        except client.OllamaUnavailable as exc:
            return {"summary": None, "validation_errors": errors, "attempts": attempts, "latency_ms": round(total_latency, 1),
                    "raw": raw, "error": str(exc), "model": model_name, "model_version": None}
        total_latency += res.latency_ms
        raw, returned = res.text, res.model
        summary, errors = parse_and_validate(res.text, payload, member_ids)
        if summary is not None:
            return {"summary": summary, "validation_errors": [], "attempts": attempts,
                    "latency_ms": round(total_latency, 1), "raw": raw, "error": None, "model": returned,
                    "model_version": f"ollama {version}" if version else None}
    return {"summary": None, "validation_errors": errors, "attempts": attempts, "latency_ms": round(total_latency, 1),
            "raw": raw, "error": None, "model": returned, "model_version": None}
