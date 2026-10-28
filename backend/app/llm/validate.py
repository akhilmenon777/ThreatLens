"""Validation of model output before it is ever shown to an analyst."""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timedelta

from pydantic import ValidationError

from app.correlation.model import STAGE_LABELS
from app.llm.sanitize import scan_injection
from app.llm.schema import IncidentSummary

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EV_RE = re.compile(r"\bEV-[0-9a-f]{16}\b")
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
ISO_RE = re.compile(r"\b20\d{2}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?\b")
OVERCLAIM = re.compile(
    r"\b(confirmed (compromise|breach|exfiltration|c2|command[- ]and[- ]control)|data (was|has been) (stolen|exfiltrated)"
    r"|definitively|proves? (that|an?)|without (any )?doubt|is certainly)\b", re.IGNORECASE)
COMPLIANCE = re.compile(
    r"(maintenance mode|no attack (has )?occurred|classified as benign|severity (is|set to) low|ignore (all )?previous)",
    re.IGNORECASE)
FORBIDDEN_ACTIONS = re.compile(r"\b(rm -rf|iptables|netsh|block the ip|shut ?down|wipe|format the)\b", re.IGNORECASE)


def _all_text(summary: IncidentSummary) -> str:
    parts = [summary.executive_summary]
    parts += [s.description for s in summary.probable_sequence]
    parts += [c.text for c in summary.claims]
    parts += summary.alternative_explanations + summary.missing_evidence
    parts += summary.investigation_questions + summary.recommended_next_steps
    return "\n".join(parts)


def parse_and_validate(raw: str, payload: dict, member_ids: set[str]) -> tuple[IncidentSummary | None, list[str]]:
    errors: list[str] = []
    try:
        start, end = raw.find("{"), raw.rfind("}")
        obj = json.loads(raw[start:end + 1] if start >= 0 else raw)
    except (json.JSONDecodeError, ValueError):
        return None, ["response is not valid JSON"]
    try:
        summary = IncidentSummary.model_validate(obj)
    except ValidationError as exc:
        return None, [f"schema: {e['loc']}: {e['msg']}" for e in exc.errors()[:6]]

    text = _all_text(summary)
    # 1. evidence references must be real member events
    cited = {eid for s in summary.probable_sequence for eid in s.evidence_event_ids}
    cited |= {eid for c in summary.claims for eid in c.evidence_event_ids}
    cited |= set(EV_RE.findall(text))
    unknown = sorted(cited - member_ids)
    if unknown:
        errors.append(f"cites event IDs not in this incident: {', '.join(unknown[:5])}")
    if not summary.claims:
        errors.append("no evidence-backed claims were provided")
    # 2. no invented IP addresses
    allowed_ips = set()
    for k in ("source_ips", "destination_ips", "internal_hosts", "external_ips"):
        allowed_ips |= set(payload.get("entities", {}).get(k, []))
    for ev in payload.get("evidence_events", []):
        allowed_ips |= {ev.get("src"), ev.get("dst")}
    bad_ips = []
    for ip in set(IP_RE.findall(text)):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if ip not in allowed_ips:
            bad_ips.append(ip)
    if bad_ips:
        errors.append(f"mentions IP addresses not present in the evidence: {', '.join(sorted(bad_ips)[:5])}")
    # 3. no invented ATT&CK techniques
    allowed_tech = {m["technique_id"] for m in payload.get("attack_mappings", []) if m.get("technique_id")}
    allowed_tech |= {t.split(".")[0] for t in allowed_tech}
    bad_tech = sorted(set(TECH_RE.findall(text)) - allowed_tech)
    if bad_tech:
        errors.append(f"mentions ATT&CK techniques not in the incident mappings: {', '.join(bad_tech[:5])}")
    # 4. observed / inferred must not be upgraded
    stage_status = {s["stage"]: s["status"] for s in payload.get("attack_stages", [])}
    for k, label in STAGE_LABELS.items():
        if k in stage_status:
            stage_status[label.lower().replace(" ", "_").replace("-", "_").replace("/", "")] = stage_status[k]
    for item in summary.probable_sequence:
        key = item.stage.lower().replace(" ", "_").replace("-", "_").replace("/", "")
        real = stage_status.get(key)
        if real is None:
            continue
        if real == "NOT_OBSERVED":
            errors.append(f"sequence includes stage '{item.stage}' which has no evidence")
        elif item.status == "OBSERVED" and real == "INFERRED":
            errors.append(f"stage '{item.stage}' is INFERRED but was presented as OBSERVED")
    # 5. timestamps must fall within the incident window
    try:
        lo = datetime.fromisoformat(payload["first_seen_utc"]) - timedelta(minutes=5)
        hi = datetime.fromisoformat(payload["last_seen_utc"]) + timedelta(minutes=5)
        for ts in ISO_RE.findall(text):
            t = datetime.fromisoformat(ts.replace(" ", "T"))
            if not lo <= t <= hi:
                errors.append(f"timestamp {ts} is outside the incident time range")
                break
    except (KeyError, ValueError):
        pass
    # 6. over-claiming, injection compliance, unsafe actions
    if OVERCLAIM.search(text):
        errors.append(f"over-claims certainty ('{OVERCLAIM.search(text).group(0)}')")
    if COMPLIANCE.search(text) or scan_injection(text):
        errors.append("output appears to follow or repeat instructions embedded in log data")
    if FORBIDDEN_ACTIONS.search(text):
        errors.append("recommends an active response/command; only investigative steps are allowed")
    if payload.get("severity") in ("Critical", "High") and re.search(r"\b(is|was) benign\b", text, re.IGNORECASE):
        errors.append("declares a High/Critical incident benign without new evidence")
    return (summary if not errors else None), errors
