"""Structured output schema for incident summaries (LLM and fallback share it)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class SequenceItem(BaseModel):
    stage: str = Field(max_length=60)
    status: Literal["OBSERVED", "INFERRED"]
    description: str = Field(max_length=600)
    evidence_event_ids: list[str] = Field(default_factory=list, max_length=20)


class Claim(BaseModel):
    text: str = Field(max_length=600)
    status: Literal["OBSERVED", "INFERRED"]
    evidence_event_ids: list[str] = Field(min_length=1, max_length=20)


class IncidentSummary(BaseModel):
    executive_summary: str = Field(min_length=20, max_length=1500)
    probable_sequence: list[SequenceItem] = Field(default_factory=list, max_length=10)
    claims: list[Claim] = Field(default_factory=list, max_length=15)
    alternative_explanations: list[str] = Field(min_length=1, max_length=8)
    missing_evidence: list[str] = Field(min_length=1, max_length=8)
    investigation_questions: list[str] = Field(default_factory=list, max_length=8)
    recommended_next_steps: list[str] = Field(default_factory=list, max_length=8)


SCHEMA_HINT = """{
  "executive_summary": "string, 2-5 sentences, plain language",
  "probable_sequence": [{"stage": "stage name from attack_stages", "status": "OBSERVED|INFERRED",
                         "description": "string", "evidence_event_ids": ["EV-..."]}],
  "claims": [{"text": "one factual statement", "status": "OBSERVED|INFERRED", "evidence_event_ids": ["EV-..."]}],
  "alternative_explanations": ["string"],
  "missing_evidence": ["string"],
  "investigation_questions": ["string"],
  "recommended_next_steps": ["string (investigative only, never blocking or remediation commands)"]
}"""
