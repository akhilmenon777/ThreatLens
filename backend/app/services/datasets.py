"""Dataset management and demo-data loading."""
from __future__ import annotations

import gzip
import json
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import AnalysisSettings, get_env
from app.ingestion.service import ingest_text
from app.models import Dataset, IngestionJob

DEMO_FILES = [
    ("suricata_eve.json", "suricata"),
    ("zeek_conn.log", "zeek"),
    ("zeek_dns.log", "zeek"),
    ("zeek_http.log", "zeek"),
    ("zeek_ssl.log", "zeek"),
    ("zeek_ssh.log", "zeek"),
    ("zeek_notice.log", "zeek"),
    ("zeek_files.tsv.log", "zeek"),
]


UWF_PARTS = {
    "2025": {"label": "UWF-ZeekData24 · 2025 capture",
             "description": "Zeek conn records from the University of West Florida cyber range (May–Jul 2025): "
                            "benign baseline plus labelled Reconnaissance, Discovery, Initial Access, Privilege "
                            "Escalation, Defense Evasion and Lateral Movement activity."},
    "2024": {"label": "UWF-ZeekData24 · 2024 capture",
             "description": "Zeek conn records from the University of West Florida cyber range (Feb–Mar 2024 attacks, "
                            "Oct–Nov 2024 benign): Reconnaissance, Credential Access, Initial Access, Persistence, "
                            "Privilege Escalation, Defense Evasion and Exfiltration."},
}
UWF_INTERNAL_NET = "143.88.0.0/16"

AIT_PART = {
    "label": "AIT-ADS · host & IDS alerts (8 scenarios)",
    "description": "Wazuh, Suricata and AMiner alerts from the AIT Log Data Set V2 testbed (Jan–Feb 2022, 8 "
                   "enterprise-network scenarios): network/service scans, dirb & WPScan, webshell upload "
                   "(CVE-2020-24186), password cracking, reverse shell, privilege escalation, service stop and "
                   "DNS exfiltration. Balanced subset: repetitive alert floods are thinned evenly over time "
                   "(see data/ait/manifest.json).",
}
# all bundled, one-click datasets: UWF parts + AIT
BUNDLED_PARTS = {**UWF_PARTS, "ait": AIT_PART}
BUNDLED_VERSIONS = ("UWF-ZeekData24", "AIT-ADS", "Hybrid UWF-ZeekData24 + AIT-ADS")
HYBRID_NAME = "Hybrid · UWF-ZeekData24 + AIT-ADS"


class DemoDataMissing(Exception):
    pass


def uwf_files(parts: list[str]) -> list[Path]:
    """Files of the bundled parts: data/uwf/<year>/*.csv and data/ait/*.jsonl.gz."""
    data = get_env().data_dir
    files: list[Path] = []
    for p in parts:
        if p == "ait":
            files.extend(sorted((data / "ait").glob("*.jsonl.gz")) or sorted((data / "ait").glob("*_*.json")))
        else:
            files.extend(sorted((data / "uwf" / p).glob("*.csv")))
    return files


def read_bundled(path: Path) -> str:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    return path.read_text(encoding="utf-8", errors="replace")


def ait_manifest() -> dict | None:
    path = get_env().data_dir / "ait" / "manifest.json"
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
    except ValueError:
        return None


def active_dataset(session: Session) -> Dataset | None:
    return session.scalars(select(Dataset).where(Dataset.is_active.is_(True)).order_by(Dataset.id.desc())).first()


def activate(session: Session, ds: Dataset) -> None:
    session.execute(update(Dataset).values(is_active=False))
    ds.is_active = True
    session.flush()


def create_dataset(session: Session, name: str, description: str = "", synthetic: bool = False) -> Dataset:
    ds = Dataset(name=name[:200], description=description, synthetic=synthetic, is_active=False)
    session.add(ds)
    session.flush()
    activate(session, ds)
    return ds


def load_demo(session: Session, settings: AnalysisSettings) -> tuple[Dataset, list[IngestionJob]]:
    demo_dir = get_env().demo_dir
    manifest_path = demo_dir / "manifest.json"
    if not manifest_path.exists():
        raise DemoDataMissing(f"Demo data not found in {demo_dir}. Run: python scripts/generate_demo_data.py")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    # replace any previous demo dataset (deterministic reload)
    for old in session.scalars(select(Dataset).where(Dataset.synthetic.is_(True))).all():
        session.delete(old)
    session.flush()
    ds = create_dataset(session, f"Synthetic demo v{manifest['version']}",
                        "Deterministic synthetic Suricata + Zeek telemetry (scenarios A–G). Not real-world data.",
                        synthetic=True)
    ds.version = manifest["version"]
    labels_path = demo_dir / "labels.json"
    ds.labels = json.loads(labels_path.read_text(encoding="utf-8")) if labels_path.exists() else None
    jobs = []
    for fname, sensor in DEMO_FILES:
        path = demo_dir / fname
        if not path.exists():
            continue
        jobs.append(ingest_text(session, ds, path.read_text(encoding="utf-8"), fname, sensor, settings))
    session.flush()
    return ds, jobs


def bundled_identity(parts: list[str]) -> tuple[str, str, str]:
    """(name, version, description) for a combination of bundled parts."""
    uwf_parts = [p for p in ("2025", "2024") if p in parts]
    has_ait = "ait" in parts
    if uwf_parts:
        uwf_name = UWF_PARTS[uwf_parts[0]]["label"] if len(uwf_parts) == 1 else "UWF-ZeekData24 · full (2024 + 2025)"
        uwf_desc = (UWF_PARTS[uwf_parts[0]]["description"] if len(uwf_parts) == 1 else
                    "Zeek conn records from the University of West Florida cyber range – 2024 capture (Feb–Nov 2024) "
                    "and 2025 capture (May–Jul 2025): benign baseline plus labelled Reconnaissance, Discovery, "
                    "Credential Access, Initial Access, Persistence, Privilege Escalation, Defense Evasion, Lateral "
                    "Movement and Exfiltration.")
    if not has_ait:
        return (uwf_name, "UWF-ZeekData24", uwf_desc + " Real lab traffic with MITRE ATT&CK labels (labels are used "
                                                       "only by the evaluation lab and dataset analytics).")
    if not uwf_parts:
        return (AIT_PART["label"], "AIT-ADS", AIT_PART["description"] + " Attack-phase labels are used only by the "
                                                                        "evaluation lab and dataset analytics.")
    years = " + ".join(sorted(uwf_parts))
    name = HYBRID_NAME if len(uwf_parts) == 2 else f"Hybrid · UWF-ZeekData24 {years} + AIT-ADS"
    desc = ("Hybrid dataset combining two public, labelled sources in one view. NETWORK layer – "
            f"UWF-ZeekData24 ({years}): {uwf_desc} HOST/IDS layer – AIT-ADS: {AIT_PART['description']} "
            "The two sources come from different testbeds and years; their timestamps are kept as recorded "
            "(nothing is shifted), so the timeline has a 2022 block (AIT) and a 2024–2025 block (UWF). Labels "
            "from both publishers are used only by the evaluation lab and dataset analytics.")
    return name, "Hybrid UWF-ZeekData24 + AIT-ADS", desc


def load_uwf(session: Session, settings: AnalysisSettings, parts: list[str], progress=None
             ) -> tuple[Dataset, list[IngestionJob]]:
    """Import bundled parts (UWF-ZeekData24 years and/or the AIT-ADS alerts) as ONE dataset.

    A previous dataset with the same name is replaced, so the import is repeatable."""
    parts = [p for p in ("2025", "2024", "ait") if p in parts] or ["2025"]
    files = uwf_files(parts)
    if not files:
        raise DemoDataMissing(f"Dataset files not found in {get_env().data_dir}")
    name, version, desc = bundled_identity(parts)
    for old in session.scalars(select(Dataset).where(Dataset.name == name)).all():
        session.delete(old)
    session.flush()
    ds = create_dataset(session, name, desc)
    ds.version = version
    total = sum(f.stat().st_size * (6 if f.suffix == ".gz" else 1) for f in files) or 1
    done = 0
    jobs = []
    for f in files:
        size = f.stat().st_size * (6 if f.suffix == ".gz" else 1)  # gz ≈ 6x smaller than its text
        if progress:
            progress(0.05 + 0.6 * done / total, f"Importing {f.name}…")
        sensor = "uwf" if f.suffix == ".csv" else "ait"
        name_for_job = f.name[:-3] if f.suffix == ".gz" else f.name
        line_phases = None
        if sensor == "ait":
            side = f.parent / (name_for_job.rsplit(".", 1)[0] + ".labels.json")
            if side.exists():
                line_phases = {int(k): v for k, v in json.loads(side.read_text(encoding="utf-8"))["lines"].items()}
        jobs.append(ingest_text(session, ds, read_bundled(f), name_for_job, sensor, settings, line_phases=line_phases))
        session.flush()
        done += size
    return ds, jobs
