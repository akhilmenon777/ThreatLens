"""Transparent risk (0–100) and correlation confidence (0–1) scoring.

Risk answers "how much should an analyst care?"; confidence answers "how well do
the links between these events hold up?". They are computed independently.
Confidence is a heuristic score, NOT a calibrated probability.

Risk = Σ weight_i · factor_i (factors in 0..1, weights from settings, default sum
100) − known-scanner penalty, clipped to 0..100. Repeated copies of the same alert
count once: severity and corroboration use distinct evidence units
(signature IDs / notice types / detector tags), never raw event counts.
"""
from __future__ import annotations

import math
from collections import Counter

from app.attack_chain.reconstruct import StageResult
from app.core.config import CorrelationSettings, RiskSettings
from app.correlation.engine import Link
from app.correlation.model import EventView, is_internal

TAG_SEVERITY = {
    "auth_success_after_failures": 0.9, "c2_signature": 0.9, "large_outbound": 0.6, "dns_tunnel": 0.6,
    "dns_tunnel_signature": 0.7, "beacon": 0.55, "ssh_bruteforce": 0.5, "web_attack_signature": 0.7,
    "port_scan": 0.35, "host_sweep": 0.3, "scan_signature": 0.35, "bruteforce_signature": 0.5,
    "password_guessing_notice": 0.5, "port_scan_notice": 0.35, "address_scan_notice": 0.3,
    "policy_signature": 0.1, "service_bruteforce": 0.45, "admin_fanout": 0.55,
    "probe_burst": 0.3, "web_scan_signature": 0.35, "web_error_burst": 0.35, "web_anomaly": 0.2,
    "host_bruteforce": 0.5, "privilege_signature": 0.75, "privilege_anomaly": 0.4, "dns_anomaly": 0.4,
    "host_alert": 0.3, "anomaly_alert": 0.2,
}
HIGH_IMPACT = {"auth_success_after_failures": 1.0, "c2_signature": 1.0, "large_outbound": 0.8,
               "dns_tunnel": 0.8, "dns_tunnel_signature": 0.8, "web_attack_signature": 0.6, "beacon": 0.6,
               "admin_fanout": 0.6, "privilege_signature": 0.8}
STAGE_WEIGHT = {"reconnaissance": 0.1, "scanning": 0.15, "credential_access": 0.2, "initial_access": 0.25,
                "privilege_escalation": 0.25,
                "lateral_movement": 0.25, "command_and_control": 0.25, "exfiltration": 0.25}
TAG_RELIABILITY = {"ids_alert": 1.0, "zeek_notice": 0.9, "ssh_bruteforce": 0.85, "auth_success_after_failures": 0.85,
                   "port_scan": 0.8, "host_sweep": 0.75, "beacon": 0.6, "large_outbound": 0.6, "dns_tunnel": 0.65,
                   "service_bruteforce": 0.6, "admin_fanout": 0.55,
                   "probe_burst": 0.55, "host_alert": 0.85, "web_error_burst": 0.75, "host_bruteforce": 0.8,
                   "anomaly_alert": 0.5}


def _sur_sev(sev: int | None) -> float:
    return {1: 1.0, 2: 0.7, 3: 0.35}.get(sev or 0, 0.3)


def severity_label(score: float, r: RiskSettings) -> str:
    if score >= r.critical_threshold:
        return "Critical"
    if score >= r.high_threshold:
        return "High"
    if score >= r.medium_threshold:
        return "Medium"
    if score >= r.low_threshold:
        return "Low"
    return "Informational"


def compute_risk(members: list[EventView], stages: list[StageResult], rs: RiskSettings,
                 cs: CorrelationSettings) -> tuple[float, list[dict], list[str]]:
    units: dict[str, float] = {}
    for e in members:
        if e.event_type == "ids_alert":
            units[f"sid:{e.signature_id or e.signature}"] = _sur_sev(e.severity)
        elif e.event_type == "zeek_notice":
            units[f"notice:{e.category}"] = 0.6
        elif e.event_type == "host_alert" and e.tags:
            units[f"wazuh:{e.signature_id or e.signature}"] = _sur_sev(e.severity)
        for t in e.tags:
            if t in TAG_SEVERITY:
                units.setdefault(f"tag:{t}", TAG_SEVERITY[t])
    sev_values = sorted(units.values(), reverse=True)
    f_sev = min(1.0, (sev_values[0] if sev_values else 0) + (0.1 if sum(v >= 0.7 for v in sev_values) >= 2 else 0))

    distinct = len(units)
    f_corr = min(1.0, math.log2(1 + distinct) / math.log2(1 + 8))

    prog = sum(STAGE_WEIGHT[s.stage] * (1.0 if s.status == "OBSERVED" else 0.5 if s.status == "INFERRED" else 0)
               for s in stages)
    n_stages = sum(1 for s in stages if s.status != "NOT_OBSERVED")
    f_prog = min(1.0, prog / 0.75) if n_stages > 1 else min(0.3, prog)

    internal = {ip for e in members for ip in (e.src, e.dst) if is_internal(ip, cs.internal_networks)}
    f_ent = min(1.0, len(internal) / 5)

    tags = Counter(t for e in members for t in e.tags)
    f_hi = max([HIGH_IMPACT[t] for t in tags if t in HIGH_IMPACT], default=0.0)

    sensors = {e.sensor for e in members}
    f_cross = 1.0 if len(sensors) > 1 else 0.0

    ts = sorted(e.ts for e in members)
    best, j = 0, 0
    for i in range(len(ts)):
        while (ts[i] - ts[j]).total_seconds() > 3600:
            j += 1
        best = max(best, i - j + 1)
    f_conc = best / len(ts) if ts else 0

    rows = [
        ("severity", "Source alert severity", f_sev, rs.w_severity,
         f"highest distinct evidence severity {sev_values[0] if sev_values else 0:.2f}" + (" plus a second high-severity source" if f_sev > (sev_values[0] if sev_values else 0) else "")),
        ("corroboration", "Distinct corroborating evidence", f_corr, rs.w_corroboration,
         f"{distinct} distinct signatures/notices/detector types (repeats counted once)"),
        ("progression", "Attack progression", f_prog, rs.w_progression,
         f"{n_stages} stage(s) with evidence; inferred stages count half"),
        ("entities", "Internal hosts involved", f_ent, rs.w_entities, f"{len(internal)} internal host(s)"),
        ("high_impact", "High-impact indicators", f_hi, rs.w_high_impact,
         ", ".join(sorted(t for t in tags if t in HIGH_IMPACT)) or "none"),
        ("cross_sensor", "Cross-sensor corroboration", f_cross, rs.w_cross_sensor, " + ".join(sorted(sensors))),
        ("concentration", "Temporal concentration", f_conc, rs.w_concentration,
         f"{best} of {len(ts)} events within the busiest hour"),
    ]
    total_w = sum(r[3] for r in rows) or 1
    scale = 100 / total_w
    breakdown = [{"factor": k, "label": lbl, "value": round(v, 3), "weight": w,
                  "points": round(v * w * scale, 1), "explanation": why} for k, lbl, v, w, why in rows]
    score = sum(b["points"] for b in breakdown)
    adjustments: list[str] = []
    scanners = set(cs.known_scanners)
    if scanners & {e.src for e in members} and n_stages <= 2 and \
            {s.stage for s in stages if s.status != "NOT_OBSERVED"} <= {"reconnaissance", "scanning"}:
        score -= rs.known_scanner_penalty
        breakdown.append({"factor": "known_scanner", "label": "Authorised scanner", "value": 1, "weight": -rs.known_scanner_penalty,
                          "points": -rs.known_scanner_penalty,
                          "explanation": "source is listed as an authorised scanner and only scan stages are present"})
        adjustments.append("known_scanner")
    return round(max(0.0, min(100.0, score)), 1), breakdown, adjustments


def compute_confidence(members: list[EventView], links: list[Link]) -> tuple[float, list[dict]]:
    if not links:
        return 0.0, [{"factor": "links", "label": "No links", "value": 0, "explanation": "single event"}]
    n = len(links)
    ident = sum(l.entity for l in links) / n
    temporal = sum(l.time for l in links) / n
    behavior = sum(l.behavior for l in links) / n
    sensors = {e.sensor for e in members}
    cross = sum(1 for l in links if l.cross_sensor) / n
    cross_f = max(cross, 0.5 if len(sensors) > 1 else 0.0)
    rel = []
    for e in members:
        rel.append(max([TAG_RELIABILITY.get(t, 0.6) for t in e.tags], default=0.5))
    reliability = sum(rel) / len(rel)
    warn_share = sum(1 for e in members if e.has_warnings) / len(members)
    pivots = sum(1 for l in links if l.rule.startswith("pivot")) / n
    penalty = min(0.15, 0.1 * warn_share + 0.1 * pivots)
    parts = [
        ("identifiers", "Strength of shared identifiers", ident, 0.3,
         f"mean entity strength {ident:.2f} across {n} links (flow 1.0, host pair 0.9, endpoint 0.55–0.6)"),
        ("temporal", "Temporal consistency", temporal, 0.2, f"mean time score {temporal:.2f}"),
        ("behavior", "Behavioural consistency", behavior, 0.2, f"mean stage-compatibility {behavior:.2f}"),
        ("cross_sensor", "Cross-sensor corroboration", cross_f, 0.1,
         f"{cross:.0%} of links seen by both sensors; sensors: {', '.join(sorted(sensors))}"),
        ("reliability", "Source evidence reliability", reliability, 0.2,
         "IDS alerts > Zeek notices > rule detectors > timing heuristics"),
    ]
    value = sum(v * w for _, _, v, w, _ in parts) - penalty
    breakdown = [{"factor": k, "label": lbl, "value": round(v, 3), "weight": w,
                  "contribution": round(v * w, 3), "explanation": why} for k, lbl, v, w, why in parts]
    breakdown.append({"factor": "uncertainty", "label": "Missing / indirect data penalty", "value": round(penalty, 3),
                      "weight": -1, "contribution": -round(penalty, 3),
                      "explanation": f"{warn_share:.0%} events with parsing warnings, {pivots:.0%} pivot-only links"})
    return round(max(0.0, min(1.0, value)), 3), breakdown
