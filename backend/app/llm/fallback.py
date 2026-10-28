"""Deterministic (non-LLM) summary built only from the structured incident fields.
Used in AI-off mode, when Ollama is unavailable/too slow, or when model output fails
validation. It is always labelled as a deterministic fallback, never as LLM output."""
from __future__ import annotations

from app.correlation.model import STAGE_LABELS
from app.llm.schema import Claim, IncidentSummary, SequenceItem

MISSING_BY_STAGE = {
    "initial_access": "Host logs (auth.log / EDR) on the targeted system to confirm or rule out a successful login or exploit.",
    "command_and_control": "Process-level data or full packet capture to identify what generated the periodic connections.",
    "exfiltration": "File-access logs or DLP data – network metadata shows volume, not content.",
    "credential_access": "Account lockout and authentication logs from the targeted service.",
    "lateral_movement": "Windows security / SMB audit logs on the destination hosts (logon type 3, share access).",
    "privilege_escalation": "sudo / auditd records with the full command line and the account that ran it.",
}

QUESTIONS_BY_STAGE = {
    "reconnaissance": "Is the scanning source an approved scanner or inventory tool?",
    "scanning": "Which of the probed services are exposed and were any of them accessed afterwards?",
    "credential_access": "Which accounts were targeted, and were any locked out or later used successfully?",
    "initial_access": "What happened on the targeted host after the first successful session?",
    "lateral_movement": "Is the source host an administration server, and which accounts authenticated to the destinations?",
    "privilege_escalation": "Which account gained root on the host, and was that change expected (change ticket, admin session)?",
    "command_and_control": "Which process on the source host opens the periodic connections, and is the destination known to IT?",
    "exfiltration": "What data could the source host access, and is the destination an approved service?",
}


def build_fallback(payload: dict) -> IncidentSummary:
    stages = [s for s in payload["attack_stages"] if s["status"] != "NOT_OBSERVED"]
    seq = [SequenceItem(stage=STAGE_LABELS.get(s["stage"], s["stage"]), status=s["status"],
                        description=(s["observed_behavior"] or "Supporting events present.")[:600],
                        evidence_event_ids=s["evidence_event_ids"][:5]) for s in stages]
    claims = []
    for s in stages:
        if s["evidence_event_ids"]:
            verb = "Telemetry shows" if s["status"] == "OBSERVED" else "Indicators are consistent with"
            claims.append(Claim(text=f"{verb} {STAGE_LABELS.get(s['stage'], s['stage']).lower()}: "
                                     f"{(s['observed_behavior'] or '').strip()[:400]}",
                                status=s["status"], evidence_event_ids=s["evidence_event_ids"][:5]))
    for m in payload["attack_mappings"]:
        if m["evidence_event_ids"] and m["technique_id"]:
            claims.append(Claim(text=f"{m['tactic']} – {m['technique']} ({m['technique_id']}) mapped as {m['status'].lower()} "
                                     f"with confidence {m['confidence']:.2f}.",
                                status=m["status"], evidence_event_ids=m["evidence_event_ids"][:3]))
    seq_txt = " → ".join(f"{STAGE_LABELS.get(s['stage'], s['stage'])}{' (inferred)' if s['status'] == 'INFERRED' else ''}"
                         for s in stages) or "no attack stage could be established"
    obs = sum(1 for s in stages if s["status"] == "OBSERVED")
    exec_summary = (
        f"{payload['event_count']} related events from {', '.join(payload['sensors'])} were grouped between "
        f"{payload['first_seen_utc']} and {payload['last_seen_utc']} UTC. Probable sequence: {seq_txt}. "
        f"{obs} stage(s) are directly observed and {len(stages) - obs} are inferred. Risk score "
        f"{payload['risk_score']:.0f}/100 ({payload['severity']}), correlation confidence "
        f"{payload['correlation_confidence']:.2f}. This is a hypothesis for analyst review, not proof of an attack.")
    missing = [MISSING_BY_STAGE[s["stage"]] for s in stages if s["stage"] in MISSING_BY_STAGE]
    missing += [f"Evidence for stage '{STAGE_LABELS[s['stage']]}' was not observed in network telemetry."
                for s in payload["attack_stages"] if s["status"] == "NOT_OBSERVED"][:2]
    questions = [QUESTIONS_BY_STAGE[s["stage"]] for s in stages if s["stage"] in QUESTIONS_BY_STAGE]
    if payload.get("prompt_injection_flags"):
        questions.append("A log field contained instruction-like text (redacted before summarisation). "
                         "Who controls that field, and is it part of an attempt to mislead analysis tools?")
    steps = ["Review the linked evidence records and the reasons each event was correlated.",
             "Check asset ownership and change records for the hosts involved."]
    if any(s["stage"] in ("command_and_control", "exfiltration") for s in stages):
        steps.append("Compare destination addresses against threat intelligence and approved-service lists.")
    return IncidentSummary(
        executive_summary=exec_summary[:1500], probable_sequence=seq[:10], claims=claims[:15],
        alternative_explanations=payload["deterministic_alternative_explanations"][:8] or ["Insufficient context."],
        missing_evidence=(missing or ["Additional host-level telemetry would be needed to validate the hypothesis."])[:8],
        investigation_questions=questions[:8], recommended_next_steps=steps[:8])
