"""Process-level configuration (environment variables) and analysis settings.

Two layers:
* ``EnvConfig`` – deployment values read once from the environment / .env file
  (paths, upload limits, CORS, default Ollama URL). Never stored in the DB.
* ``AnalysisSettings`` – analyst-tunable values (correlation windows, weights,
  thresholds, LLM mode). Persisted in the ``settings`` table, validated by
  Pydantic before saving, and exposed through the Settings page.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_DIR.parent


def _load_dotenv() -> None:
    """Minimal .env loader (KEY=VALUE lines) so no extra dependency is needed."""
    for candidate in (PROJECT_ROOT / ".env", BACKEND_DIR / ".env"):
        if not candidate.exists():
            continue
        for line in candidate.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


class EnvConfig(BaseModel):
    database_url: str
    data_dir: Path
    demo_dir: Path
    mappings_dir: Path
    max_upload_mb: int = 50
    max_field_chars: int = 2048
    cors_origins: list[str]
    ollama_base_url: str = "http://127.0.0.1:11434"
    app_version: str = "1.0.0"


@lru_cache
def get_env() -> EnvConfig:
    _load_dotenv()
    data_dir = Path(os.getenv("NTDCP_DATA_DIR", PROJECT_ROOT / "data"))
    runtime_dir = Path(os.getenv("NTDCP_RUNTIME_DIR", PROJECT_ROOT / "runtime"))
    runtime_dir.mkdir(parents=True, exist_ok=True)
    return EnvConfig(
        database_url=os.getenv("NTDCP_DATABASE_URL", f"sqlite:///{runtime_dir / 'ntdcp.db'}"),
        data_dir=data_dir,
        demo_dir=data_dir / "demo",
        mappings_dir=data_dir / "mappings",
        max_upload_mb=int(os.getenv("NTDCP_MAX_UPLOAD_MB", "50")),
        max_field_chars=int(os.getenv("NTDCP_MAX_FIELD_CHARS", "2048")),
        cors_origins=[o.strip() for o in os.getenv(
            "NTDCP_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o.strip()],
        ollama_base_url=os.getenv("NTDCP_OLLAMA_BASE_URL", "http://127.0.0.1:11434"),
    )


# --------------------------------------------------------------------------- #
# Analyst-tunable settings
# --------------------------------------------------------------------------- #
class CorrelationSettings(BaseModel):
    link_window_seconds: int = Field(3600, ge=10, le=86400,
                                     description="Max time between two events for a direct link")
    max_group_gap_seconds: int = Field(7200, ge=60, le=7 * 86400,
                                       description="Incidents are split where consecutive member events are further apart")
    link_threshold: float = Field(0.55, ge=0.05, le=1.0,
                                  description="Minimum pairwise score to accept a link")
    min_incident_events: int = Field(2, ge=1, le=100)
    popular_entity_share: float = Field(0.25, gt=0, le=1.0,
                                        description="IPs reached by more than this share of distinct signal sources (min 5) cannot link on their own")
    max_neighbors_per_entity: int = Field(50, ge=1, le=1000,
                                          description="Candidate cap per entity bucket (bounds pair generation)")
    infrastructure_ips: list[str] = Field(default_factory=lambda: ["10.10.0.2", "10.10.0.1"],
                                          description="Resolvers/gateways never used alone as a linking entity")
    known_scanners: list[str] = Field(default_factory=lambda: ["10.10.0.250"],
                                      description="Authorised scanners: still correlated, but risk is reduced and a benign explanation is attached")
    # detector thresholds
    scan_min_targets: int = Field(15, ge=3)
    bruteforce_min_failures: int = Field(10, ge=3)
    beacon_min_connections: int = Field(8, ge=4)
    beacon_max_jitter_ratio: float = Field(0.15, gt=0, le=1)
    exfil_min_bytes: int = Field(50_000_000, ge=1_000_000)
    dns_tunnel_min_label_len: int = Field(40, ge=20)
    service_bruteforce_min_connections: int = Field(20, ge=5, le=10_000,
                                                    description="Connections to one auth service within 1 h")
    auth_service_ports: list[int] = Field(default_factory=lambda: [21, 22, 23, 25, 110, 143, 389, 445, 1433, 3306,
                                                                    3389, 4848, 5432, 5900, 5985, 8443, 9200])
    admin_ports: list[int] = Field(default_factory=lambda: [135, 139, 445, 3389, 5985, 5986],
                                   description="Remote-admin ports for the lateral-movement fan-out heuristic (SSH excluded: routine admin access)")
    probe_burst_min_connections: int = Field(100, ge=10, le=100_000,
                                             description="Connections to one TCP service within 15 min")
    admin_fanout_min_hosts: int = Field(3, ge=2, le=100)
    web_error_burst_min_errors: int = Field(30, ge=5, le=100_000,
                                            description="HTTP 4xx errors logged by one web server for one client within 15 min (host logs)")
    internal_networks: list[str] = Field(default_factory=lambda: ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"])

    # link score weights (sum need not be 1; score is clipped to [0,1])
    w_entity: float = Field(0.45, ge=0, le=1)
    w_time: float = Field(0.20, ge=0, le=1)
    w_behavior: float = Field(0.25, ge=0, le=1)
    w_cross_sensor: float = Field(0.10, ge=0, le=1)


class RiskSettings(BaseModel):
    w_severity: float = Field(25, ge=0, le=100)
    w_corroboration: float = Field(15, ge=0, le=100)
    w_progression: float = Field(25, ge=0, le=100)
    w_entities: float = Field(10, ge=0, le=100)
    w_high_impact: float = Field(15, ge=0, le=100)
    w_cross_sensor: float = Field(5, ge=0, le=100)
    w_concentration: float = Field(5, ge=0, le=100)
    known_scanner_penalty: float = Field(25, ge=0, le=100)
    critical_threshold: int = Field(80, ge=1, le=100)
    high_threshold: int = Field(60, ge=1, le=100)
    medium_threshold: int = Field(35, ge=1, le=100)
    low_threshold: int = Field(15, ge=0, le=100)

    @model_validator(mode="after")
    def _ordered(self):
        if not (self.critical_threshold > self.high_threshold > self.medium_threshold > self.low_threshold):
            raise ValueError("Severity thresholds must satisfy critical > high > medium > low")
        if sum([self.w_severity, self.w_corroboration, self.w_progression, self.w_entities,
                self.w_high_impact, self.w_cross_sensor, self.w_concentration]) <= 0:
            raise ValueError("At least one risk weight must be positive")
        return self


class LLMSettings(BaseModel):
    mode: Literal["off", "cached", "live"] = "cached"
    ollama_base_url: str = ""
    primary_model: str = "qwen2.5-coder:7b"
    secondary_model: str = "deepseek-r1:7b"
    timeout_seconds: int = Field(90, ge=5, le=600)
    max_retries: int = Field(1, ge=0, le=3)
    temperature: float = Field(0.1, ge=0, le=1)
    max_events_in_prompt: int = Field(25, ge=5, le=200)

    @field_validator("ollama_base_url")
    @classmethod
    def _url(cls, v: str) -> str:
        if v and not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("Ollama URL must start with http:// or https://")
        return v.rstrip("/")


class DisplaySettings(BaseModel):
    timezone: str = "UTC"
    attack_version: str = "v15.1-subset"
    retain_raw_payload: bool = True
    max_raw_payload_chars: int = Field(8000, ge=256, le=200_000)

    @field_validator("timezone")
    @classmethod
    def _tz(cls, v: str) -> str:
        if v in ("UTC", "Etc/UTC", "GMT"):
            return v  # always valid, even where no IANA database is installed (plain Windows Python)
        from zoneinfo import ZoneInfo
        try:
            ZoneInfo(v)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"Unknown timezone '{v}' (on Windows install the 'tzdata' package for named zones)") from exc
        return v


class AnalysisSettings(BaseModel):
    correlation: CorrelationSettings = Field(default_factory=CorrelationSettings)
    risk: RiskSettings = Field(default_factory=RiskSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    display: DisplaySettings = Field(default_factory=DisplaySettings)
