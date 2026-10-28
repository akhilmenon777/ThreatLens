"""Turn a correlated group into a fully described incident (pure function, no DB)."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from app.attack_chain.reconstruct import StageResult, reconstruct
from app.attack_mapping.catalog import Catalog
from app.attack_mapping.mapper import MappingResult, map_incident
from app.core.config import AnalysisSettings
from app.correlation.engine import Group, Link
from app.correlation.model import STAGE_LABELS, EventView, is_internal
from app.risk.scoring import compute_confidence, compute_risk, severity_label


@dataclass
class IncidentDraft:
    event_ids: list[str]
    fingerprint: str
    evidence_hash: str
    title: str
    description: str
    first_seen: object
    last_seen: object
    sensors: list[str]
    entities: dict
    stages: list[StageResult]
    stage_of_event: dict[str, str | None]
    mappings: list[MappingResult]
    tactics: list[str]
    risk_score: float
    risk_breakdown: list[dict]
    severity: str
    confidence: float
    confidence_breakdown: list[dict]
    alternative_explanations: list[str]
    links: list[Link]
    notes: list[str] = field(default_factory=list)


def _alternatives(members: list[EventView], cfg: AnalysisSettings, adjustments: list[str]) -> list[str]:
    tags = {t for e in members for t in e.tags}
    alts: list[str] = []
    if "known_scanner" in adjustments:
        alts.append("The source is listed as an authorised vulnerability scanner; this is likely scheduled scanning.")
    if tags & {"host_sweep", "port_scan", "scan_signature"} and "known_scanner" not in adjustments:
        alts.append("Unlisted asset-inventory or vulnerability-scanning tool run by IT.")
    if tags & {"ssh_bruteforce", "bruteforce_signature"}:
        alts.append("Misconfigured automation repeatedly retrying stale credentials.")
    if "auth_success_after_failures" in tags:
        alts.append("A legitimate user who mistyped the password many times before succeeding (less likely at this failure count).")
    if "beacon" in tags:
        snis = sorted({e.sni for e in members if e.sni})
        alts.append("Software update, monitoring or telemetry agent checking in on a fixed schedule"
                    + (f" (TLS server names: {', '.join(snis[:3])})." if snis else "."))
    if "large_outbound" in tags:
        alts.append("Scheduled backup or legitimate large upload to cloud storage.")
    if tags & {"dns_tunnel", "dns_tunnel_signature"}:
        alts.append("Security, CDN or telemetry products that encode hashes in long DNS labels.")
    if "probe_burst" in tags:
        alts.append("A crawler, load test, monitoring probe or chatty client application talking to one service.")
    if "service_bruteforce" in tags:
        alts.append("A monitoring probe, health check or application that reconnects rapidly to the same service.")
    if "admin_fanout" in tags:
        alts.append("IT administration, software deployment, backup or inventory tooling contacting many hosts over SMB/RPC/WinRM.")
    if "web_attack_signature" in tags:
        alts.append("A vulnerability scanner or unusual but benign client user agent.")
    if not alts:
        alts.append("Insufficient context to propose a specific benign explanation.")
    return alts


def _title(members: list[EventView], stages: list[StageResult], cfg: AnalysisSettings) -> tuple[str, str]:
    present = [s for s in stages if s.status != "NOT_OBSERVED"]
    srcs = [e.src for e in members if e.src]
    dsts = [e.dst for e in members if e.dst]
    from collections import Counter
    top_src = Counter(srcs).most_common(1)[0][0] if srcs else "?"
    top_dst = Counter(dsts).most_common(1)[0][0] if dsts else "?"
    if len(set(srcs)) > 3:
        top_src = f"{len(set(srcs))} sources"
    if len(set(dsts)) > 3 and Counter(dsts).most_common(1)[0][1] < 0.5 * len(dsts):
        top_dst = f"{len(set(dsts))} hosts"
    if len(present) >= 3:
        title = f"Multi-stage activity involving {top_src} → {top_dst}"
    elif present:
        names = {
            "reconnaissance": "Reconnaissance (sweep / service probing)", "scanning": "Port scanning", "credential_access": "Brute-force attempts",
            "initial_access": "Suspicious access attempt", "privilege_escalation": "Privilege escalation on a host", "lateral_movement": "Internal remote-admin fan-out", "command_and_control": "Beacon-like outbound connections",
            "exfiltration": "Possible data exfiltration",
        }
        main = present[-1].stage
        if main == "exfiltration" and any("dns_tunnel" in e.tags or "dns_tunnel_signature" in e.tags for e in members):
            label = "Possible DNS tunnelling"
        else:
            label = names[main]
        if len(present) == 2:
            label = f"{names[present[0].stage]} and {label[0].lower() + label[1:]}"
        title = f"{label}: {top_src} → {top_dst}"
    else:
        title = f"Correlated alerts: {top_src} → {top_dst}"
    stage_txt = " → ".join(STAGE_LABELS[s.stage] + (" (inferred)" if s.status == "INFERRED" else "") for s in present)
    desc = (f"{len(members)} related events from {', '.join(sorted({e.sensor for e in members}))} between "
            f"{min(e.ts for e in members):%Y-%m-%d %H:%M} and "
            f"{max(e.end for e in members):{'%H:%M' if max(e.end for e in members).date() == min(e.ts for e in members).date() else '%Y-%m-%d %H:%M'}} UTC. "
            + (f"Probable sequence: {stage_txt}." if stage_txt else "No attack stage could be established."))
    return title[:300], desc


def build_incident(group: Group, by_id: dict[str, EventView], catalog: Catalog, cfg: AnalysisSettings) -> IncidentDraft:
    members = [by_id[i] for i in group.event_ids]
    stages = reconstruct(members)
    mappings, warn = map_incident(members, catalog)
    risk, breakdown, adjustments = compute_risk(members, stages, cfg.risk, cfg.correlation)
    conf, conf_breakdown = compute_confidence(members, group.links)
    nets = cfg.correlation.internal_networks
    ips = {ip for e in members for ip in (e.src, e.dst) if ip}
    entities = {
        "source_ips": sorted({e.src for e in members if e.src}),
        "destination_ips": sorted({e.dst for e in members if e.dst}),
        "internal_hosts": sorted(ip for ip in ips if is_internal(ip, nets)),
        "external_ips": sorted(ip for ip in ips if not is_internal(ip, nets)),
        "hostnames": sorted({h for e in members for h in (e.host, e.sni) if h})[:20],
        "dns_domains": sorted({".".join(e.dns_query.split(".")[-3:]) for e in members if e.dns_query})[:10],
        "users": [],  # network telemetry in scope carries no user identities; never fabricated
        "ports": sorted({e.dport for e in members if e.dport is not None})[:30],
    }
    title, desc = _title(members, stages, cfg)
    fp = hashlib.sha256("|".join(sorted(group.event_ids)).encode()).hexdigest()
    ev_hash = hashlib.sha256((fp + "|" + "|".join(f"{m.technique_id}:{m.status}" for m in mappings)
                              + "|" + "|".join(f"{s.stage}:{s.status}" for s in stages)).encode()).hexdigest()
    tactics = []
    for m in mappings:
        if m.tactic_name not in tactics:
            tactics.append(m.tactic_name)
    return IncidentDraft(
        event_ids=group.event_ids, fingerprint=fp, evidence_hash=ev_hash, title=title, description=desc,
        first_seen=min(e.ts for e in members), last_seen=max(e.end for e in members),
        sensors=sorted({e.sensor for e in members}), entities=entities, stages=stages,
        stage_of_event={e.event_id: e.stage for e in members}, mappings=mappings, tactics=tactics,
        risk_score=risk, risk_breakdown=breakdown, severity=severity_label(risk, cfg.risk), confidence=conf,
        confidence_breakdown=conf_breakdown, alternative_explanations=_alternatives(members, cfg, adjustments),
        links=group.links, notes=group.notes + warn)
