"""Build the minimal, sanitised, structured incident object sent to the LLM.

Every log-derived string is untrusted. Defences applied here:
* only an allow-listed set of fields is included (no raw payloads);
* control characters removed, each string capped (``MAX_STR``);
* instruction-like text (prompt-injection patterns) is replaced by a neutral
  placeholder and recorded as an injection flag – the model never sees it,
  while analysts still see the original value in the evidence panel;
* the object is serialised with ``json.dumps`` and placed inside a clearly
  delimited data block, separate from the system instructions.
"""
from __future__ import annotations

import re
from typing import Any

MAX_STR = 200
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
INJECTION_PATTERNS = [
    r"ignore (all |any )?(previous|prior|above) (instructions|prompts?)",
    r"disregard (all |any )?(previous|prior|above)",
    r"you are now",
    r"\bsystem prompt\b",
    r"maintenance mode",
    r"(classify|mark|report|label)( this| the)? (incident|alert|event)s? as (benign|false positive|safe)",
    r"set (the )?(severity|risk) to",
    r"\b(assistant|system|user)\s*:",
    r"</?(system|instructions?|prompt)>",
    r"do not (report|mention|flag)",
    r"no attack (has )?occurred",
]
_INJ = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)


def scan_injection(text: str | None) -> bool:
    return bool(text) and bool(_INJ.search(text))


def clean(value: Any, field: str, flags: list[dict], event_id: str | None = None) -> Any:
    if value is None or isinstance(value, (int, float, bool)):
        return value
    s = _CTRL.sub("", str(value))
    if scan_injection(s):
        flags.append({"event_id": event_id, "field": field, "length": len(s),
                      "excerpt": s[:120]})
        return f"[REDACTED by sanitizer: instruction-like text ({len(s)} chars) in untrusted field '{field}']"
    if len(s) > MAX_STR:
        s = s[:MAX_STR] + "…"
    return s


UNTRUSTED_EVENT_FIELDS = ["alert_signature", "alert_category", "dns_query", "http_host", "http_uri",
                          "http_user_agent", "tls_server_name"]


def build_incident_payload(incident, events: list, max_events: int) -> tuple[dict, list[dict]]:
    """``incident`` is an ORM Incident; ``events`` the ORM member events (time-ordered)."""
    flags: list[dict] = []
    stage_ids = {eid for s in incident.stages for eid in s.event_ids[:5]}
    map_ids = {eid for m in incident.mappings for eid in m.evidence_event_ids[:5]}
    priority = [e for e in events if e.event_id in stage_ids | map_ids]
    rest = [e for e in events if e.event_id not in stage_ids | map_ids and (e.detector_tags or [])]
    chosen = (priority + rest)[:max_events]
    chosen.sort(key=lambda e: e.timestamp_utc)
    ev_out = []
    for e in chosen:
        item = {
            "event_id": e.event_id,
            "time_utc": e.timestamp_utc.isoformat(timespec="seconds"),
            "sensor": e.source_sensor,
            "type": e.event_type,
            "src": e.source_ip, "src_port": e.source_port,
            "dst": e.destination_ip, "dst_port": e.destination_port,
            "transport": e.transport_protocol,
            "detector_tags": list(e.detector_tags or []),
        }
        if e.bytes_sent is not None:
            item["bytes_sent"] = e.bytes_sent
        if e.auth_success is not None:
            item["auth_success"] = e.auth_success
        for f in UNTRUSTED_EVENT_FIELDS:
            v = getattr(e, f)
            if v:
                item[f] = clean(v, f, flags, e.event_id)
        ev_out.append(item)
    # scan non-selected members too, so an injection anywhere in the incident is flagged
    for e in events:
        if e in chosen:
            continue
        for f in UNTRUSTED_EVENT_FIELDS:
            v = getattr(e, f)
            if v and scan_injection(v):
                flags.append({"event_id": e.event_id, "field": f, "length": len(v), "excerpt": v[:120]})
    payload = {
        "incident_id": incident.id,
        "title": incident.title,
        "first_seen_utc": incident.first_seen.isoformat(timespec="seconds"),
        "last_seen_utc": incident.last_seen.isoformat(timespec="seconds"),
        "event_count": incident.event_count,
        "events_included": len(ev_out),
        "sensors": incident.sensors,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "risk_top_factors": [
            {"factor": b["label"], "points": b["points"], "detail": b["explanation"]}
            for b in sorted(incident.risk_breakdown, key=lambda b: -abs(b["points"]))[:4]],
        "correlation_confidence": incident.confidence,
        "entities": {k: v for k, v in incident.entities.items() if k != "users" and v},
        "attack_stages": [
            {"stage": s.stage, "status": s.status, "first_time_utc": s.first_timestamp.isoformat(timespec="seconds") if s.first_timestamp else None,
             "observed_behavior": clean(s.observed_behavior, "observed_behavior", flags),
             "evidence_event_ids": s.event_ids[:5]}
            for s in incident.stages],
        "attack_mappings": [
            {"tactic": m.tactic_name, "technique_id": m.technique_id, "technique": m.technique_name,
             "status": m.status, "confidence": m.confidence, "evidence_event_ids": m.evidence_event_ids[:5]}
            for m in incident.mappings],
        "deterministic_alternative_explanations": incident.alternative_explanations,
        "evidence_events": ev_out,
        "prompt_injection_flags": len(flags),
    }
    return payload, flags
