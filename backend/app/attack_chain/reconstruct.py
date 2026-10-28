"""Probable attack-chain reconstruction with explicit evidence states.

OBSERVED      the telemetry directly contains the behaviour/alert for the stage.
INFERRED      a hypothesis from indirect indicators (e.g. beacon-like timing,
              a large transfer, or later behaviour of a targeted host).
NOT_OBSERVED  no supporting evidence – shown so gaps are visible, never filled in.

Rules (documented in docs/CORRELATION.md):
* reconnaissance / scanning / credential_access are OBSERVED when their tags exist.
* initial_access is OBSERVED for a logged successful authentication after failures;
  INFERRED when only a web-attack signature exists, or when a host that was
  targeted earlier in the incident later initiates C2-like/exfil-like traffic.
* command_and_control is OBSERVED when an IDS C2 signature matched; INFERRED when
  only beacon timing supports it.
* credential_access is INFERRED when only connection bursts to an authentication
  service support it (no auth result is visible in conn records).
* lateral_movement is INFERRED from internal remote-admin fan-out.
* privilege_escalation is OBSERVED when a host logged a root sudo/su execution (Wazuh);
  INFERRED from audit-log anomalies (AMiner) alone.
* host-log web scanning (Wazuh 4xx bursts / forbidden paths) is OBSERVED reconnaissance;
  AMiner web-log anomalies are INFERRED reconnaissance.
* exfiltration is always INFERRED ("possible exfiltration"): a large transfer or
  DNS tunnelling shows data movement, not data theft.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from app.correlation.model import STAGE_LABELS, STAGES, EventView

STRONG_TAGS = {
    "reconnaissance": {"host_sweep", "address_scan_notice", "web_scan_signature", "web_error_burst"},
    "scanning": {"port_scan", "scan_signature", "port_scan_notice"},
    "credential_access": {"ssh_bruteforce", "bruteforce_signature", "password_guessing_notice", "host_bruteforce"},
    "initial_access": {"auth_success_after_failures"},
    "privilege_escalation": {"privilege_signature"},
    "lateral_movement": set(),
    "command_and_control": {"c2_signature"},
    "exfiltration": set(),
}
WEAK_TAGS = {
    "reconnaissance": {"probe_burst", "web_anomaly"},
    "credential_access": {"service_bruteforce"},
    "initial_access": {"web_attack_signature"},
    "privilege_escalation": {"privilege_anomaly"},
    "lateral_movement": {"admin_fanout"},
    "command_and_control": {"beacon"},
    "exfiltration": {"large_outbound", "dns_tunnel", "dns_tunnel_signature", "dns_anomaly"},
}


@dataclass
class StageResult:
    stage: str
    label: str
    order: int
    status: str
    first_ts: datetime | None
    event_ids: list[str] = field(default_factory=list)
    observed_behavior: str = ""
    evidence_strength: str = "none"
    confidence: float = 0.0
    explanation: str = ""


def _summarise(evs: list[EventView], tags: set[str]) -> str:
    seen, parts = set(), []
    for e in evs:
        for t in sorted(e.tags & tags):
            txt = e.tag_evidence.get(t, t)
            if txt not in seen:
                seen.add(txt)
                parts.append(txt)
            if len(parts) >= 3:
                break
        if len(parts) >= 3:
            break
    return "; ".join(parts)


def reconstruct(members: list[EventView]) -> list[StageResult]:
    members = sorted(members, key=lambda e: e.ts)
    results: list[StageResult] = []
    for idx, stage in enumerate(STAGES):
        strong = [e for e in members if e.tags & STRONG_TAGS[stage]]
        weak = [e for e in members if e.tags & WEAK_TAGS.get(stage, set())]
        res = StageResult(stage, STAGE_LABELS[stage], idx + 1, "NOT_OBSERVED", None)
        if strong:
            evs = strong + [e for e in weak if e not in strong]
            res.status = "OBSERVED"
            res.event_ids = [e.event_id for e in evs]
            res.first_ts = min(e.ts for e in evs)
            res.observed_behavior = _summarise(evs, STRONG_TAGS[stage] | WEAK_TAGS.get(stage, set()))
            res.evidence_strength = "strong" if len(strong) >= 3 or any(e.sensor in ("suricata", "wazuh") for e in strong) else "moderate"
            res.confidence = 0.85 if res.evidence_strength == "strong" else 0.7
            res.explanation = (f"Directly supported by {len(strong)} event(s). Placed at "
                               f"{res.first_ts:%H:%M:%S} UTC, the earliest supporting event.")
        elif weak:
            res.status = "INFERRED"
            res.event_ids = [e.event_id for e in weak]
            res.first_ts = min(e.ts for e in weak)
            res.observed_behavior = _summarise(weak, WEAK_TAGS[stage])
            res.evidence_strength = "indirect"
            res.confidence = 0.45
            why = {
                "reconnaissance": "a high rate of connections to one service, or new request patterns in a web "
                                  "server's log, is typical of web/vulnerability scanning, but also of crawlers, load "
                                  "tests or new clients",
                "privilege_escalation": "new user/credential parameter combinations in the audit log are consistent "
                                        "with privilege changes, but the anomaly detector cannot tell admin work from abuse",
                "credential_access": "many rapid connections to one authentication-capable service look like password "
                                     "guessing, but connection metadata cannot show failed logins",
                "lateral_movement": "one internal host reached several internal hosts over remote-administration "
                                    "protocols (SMB/RDP/WinRM/RPC); this is also normal for admin tooling",
                "initial_access": "a web-attack signature shows an attempt; success is not visible in network data",
                "command_and_control": "regular outbound connection timing is consistent with beaconing but also with benign agents",
                "exfiltration": "data movement was observed; whether data was stolen cannot be determined from metadata",
            }[stage]
            res.explanation = f"Hypothesis: {why}. Earliest indicator at {res.first_ts:%H:%M:%S} UTC."
        results.append(res)

    # initial access inferred from later behaviour of a host that was targeted before
    ia = results[STAGES.index("initial_access")]
    if ia.status == "NOT_OBSERVED":
        targeted = {}
        for e in members:
            if e.stage in ("scanning", "credential_access") and e.dst:
                targeted.setdefault(e.dst, e.ts)
        later = [e for e in members if e.stage in ("command_and_control", "exfiltration")
                 and e.src in targeted and e.ts > targeted[e.src]]
        if later:
            ia.status = "INFERRED"
            ia.event_ids = [later[0].event_id]
            ia.first_ts = None
            ia.evidence_strength = "indirect"
            ia.confidence = 0.35
            ia.observed_behavior = f"{later[0].src} was targeted earlier and later initiated suspicious outbound traffic"
            ia.explanation = ("Hypothesis: access to the targeted host is implied by its later behaviour; "
                              "no successful authentication or exploit was observed. Time of access unknown.")

    # flag stage order that deviates from the canonical sequence
    present = [r for r in results if r.first_ts is not None]
    for prev, cur in zip(present, present[1:]):
        if cur.first_ts < prev.first_ts:
            cur.explanation += " Note: occurs earlier than the preceding canonical stage (stages can repeat or overlap)."
    return results
