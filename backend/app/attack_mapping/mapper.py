"""Hybrid ATT&CK enrichment: signature-derived and behaviour-derived mappings,
validated against the local versioned catalog. LLM output is never used here."""
from __future__ import annotations

from dataclasses import dataclass

from app.attack_mapping.catalog import Catalog, CatalogError
from app.correlation.model import EventView

MAX_EVIDENCE_IDS = 20


@dataclass
class MappingResult:
    tactic_id: str
    tactic_name: str
    technique_id: str | None
    technique_name: str | None
    method: str
    status: str
    confidence: float
    evidence_event_ids: list[str]
    reason: str
    rule_id: str
    url: str | None


def map_incident(members: list[EventView], catalog: Catalog) -> tuple[list[MappingResult], list[str]]:
    results: dict[tuple, MappingResult] = {}
    warnings: list[str] = []
    for rule in catalog.technique_rules:
        evidence = [e for e in members if e.tags & set(rule.tags)]
        if not evidence:
            continue
        try:
            catalog.validate_mapping(rule.tactic, rule.technique)
        except CatalogError as exc:  # pragma: no cover - rules are validated at load
            warnings.append(f"{rule.id}: {exc}")
            continue
        # a signature-backed rule whose evidence is only behavioural is downgraded one step
        has_sig = any(e.sensor in ("suricata", "wazuh", "aminer") or e.event_type == "zeek_notice" for e in evidence)
        conf = rule.confidence
        method = rule.method
        if "signature" in method and not has_sig:
            method = "behavioral"
        if "behavioral" in method and has_sig and "signature" not in method:
            conf = min(0.95, conf + 0.1)
        n = len(evidence)
        conf = min(0.95, conf + (0.05 if n >= 10 else 0))
        tech = catalog.techniques.get(rule.technique) if rule.technique else None
        key = (rule.tactic, rule.technique)
        existing = results.get(key)
        mr = MappingResult(
            tactic_id=rule.tactic, tactic_name=catalog.tactic_name(rule.tactic),
            technique_id=rule.technique, technique_name=tech.name if tech else None,
            method=method, status=rule.status, confidence=round(conf, 2),
            evidence_event_ids=[e.event_id for e in evidence[:MAX_EVIDENCE_IDS]],
            reason=f"{rule.reason} ({n} supporting event{'s' if n != 1 else ''}; rule {rule.id})",
            rule_id=rule.id, url=tech.url if tech else None)
        if existing is None or (mr.status == "OBSERVED" and existing.status != "OBSERVED") or mr.confidence > existing.confidence:
            results[key] = mr
    ordered = sorted(results.values(), key=lambda m: (catalog.tactics[m.tactic_id]["order"], m.technique_id or ""))
    return ordered, warnings
