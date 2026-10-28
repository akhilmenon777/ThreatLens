"""Persistence for analyst-tunable settings (validated before saving)."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.config import AnalysisSettings, get_env
from app.models import Analyst, Setting

KEY = "analysis"
DEFAULT_ANALYSTS = ["Analyst A", "Analyst B", "SOC Lead"]


def ensure_defaults(s: Session) -> None:
    if s.get(Setting, KEY) is None:
        defaults = AnalysisSettings()
        defaults.llm.ollama_base_url = get_env().ollama_base_url
        s.add(Setting(key=KEY, value=defaults.model_dump()))
    if s.query(Analyst).count() == 0:
        s.add_all(Analyst(name=n) for n in DEFAULT_ANALYSTS)
    s.flush()


def load_settings(s: Session) -> AnalysisSettings:
    row = s.get(Setting, KEY)
    if row is None:
        ensure_defaults(s)
        row = s.get(Setting, KEY)
    settings = AnalysisSettings.model_validate(row.value)
    if not settings.llm.ollama_base_url:
        settings.llm.ollama_base_url = get_env().ollama_base_url
    return settings


def save_settings(s: Session, new: AnalysisSettings) -> AnalysisSettings:
    validated = AnalysisSettings.model_validate(new.model_dump())  # re-run validators
    row = s.get(Setting, KEY)
    if row is None:
        s.add(Setting(key=KEY, value=validated.model_dump()))
    else:
        row.value = validated.model_dump()
    s.flush()
    return validated
