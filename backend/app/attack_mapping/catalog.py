"""Versioned local ATT&CK catalog + deterministic rule files, validated on load."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from app.core.config import get_env


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/") + "/"

    @property
    def parent(self) -> str:
        return self.id.split(".")[0]


@dataclass(frozen=True)
class SignatureRule:
    id: str
    pattern: re.Pattern
    tag: str


@dataclass(frozen=True)
class TechniqueRule:
    id: str
    tags: tuple[str, ...]
    tactic: str
    technique: str | None
    method: str
    status: str
    confidence: float
    reason: str


class CatalogError(ValueError):
    pass


@dataclass
class Catalog:
    version: str
    coverage_note: str
    tactics: dict[str, dict]
    techniques: dict[str, Technique]
    signature_rules: list[SignatureRule]
    technique_rules: list[TechniqueRule]
    rules_version: str

    def tactic_name(self, tid: str) -> str:
        return self.tactics[tid]["name"]

    def validate_mapping(self, tactic: str, technique: str | None) -> None:
        if tactic not in self.tactics:
            raise CatalogError(f"unknown tactic {tactic}")
        if technique is None:
            return
        tech = self.techniques.get(technique)
        if tech is None:
            raise CatalogError(f"unknown technique {technique} (not in {self.version})")
        if tactic not in tech.tactics:
            raise CatalogError(f"technique {technique} is not listed under tactic {tactic}")


def _load(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def build_catalog(catalog_path: Path, rules_path: Path) -> Catalog:
    cat = _load(catalog_path)
    rules = _load(rules_path)
    tactics = {t["id"]: t for t in cat["tactics"]}
    techniques = {t["id"]: Technique(t["id"], t["name"], tuple(t["tactics"])) for t in cat["techniques"]}
    for t in techniques.values():
        for ta in t.tactics:
            if ta not in tactics:
                raise CatalogError(f"technique {t.id} references unknown tactic {ta}")
    sig_rules = [SignatureRule(r["id"], re.compile(r["pattern"]), r["tag"]) for r in rules["signature_rules"]]
    tech_rules = [TechniqueRule(r["id"], tuple(r["tags"]), r["tactic"], r.get("technique"), r["method"],
                                r["status"], float(r["confidence"]), r["reason"]) for r in rules["technique_rules"]]
    c = Catalog(cat["version"], cat.get("coverage_note", ""), tactics, techniques, sig_rules, tech_rules,
                rules.get("version", "1"))
    for r in tech_rules:
        c.validate_mapping(r.tactic, r.technique)
        if r.status not in ("OBSERVED", "INFERRED"):
            raise CatalogError(f"rule {r.id}: invalid status {r.status}")
    return c


@lru_cache
def get_catalog() -> Catalog:
    d = get_env().mappings_dir
    return build_catalog(d / "attack_catalog.json", d / "mapping_rules.json")
