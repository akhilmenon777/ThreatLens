"""Build the balanced AIT-ADS subset shipped in data/ait/.

AIT Alert Data Set (Landauer, Skopik, Wurzenberger; Zenodo 10.5281/zenodo.8263181, CC BY 4.0)
holds 2.66M Wazuh / Suricata / AMiner alerts for 8 attack scenarios. About 60% of them are a
single repeated Wazuh rule ("Web server 400 error code") produced by the dirb scans.

Balanced subset (deterministic, no randomness):
  * alerts are grouped by (scenario, file, alert type, attack phase or "none");
  * groups with <= CAP alerts are kept completely;
  * larger groups are thinned to CAP alerts spaced evenly over the group (every k-th alert in
    time order), so every flood stays visible with its original timing and every attack phase
    of every scenario is represented.
Records are copied byte-for-byte (original JSON lines). manifest.json records, for every group,
how many original alerts it had and how many were kept.

Ground truth (``<scenario>_<kind>.labels.json``): the publisher's labels.csv only gives attack-phase
time windows, and the testbed keeps producing normal alerts (mail logins, ClamAV updates, TLS noise)
during those windows. An alert is therefore labelled with the phase only when its alert type is
*elevated* inside that window compared with the same scenario's alerts outside all windows:

    count_in_window >= 5 * (baseline rate per second * window length) + 1

(alert types never seen outside the windows qualify with a single occurrence). Labels are computed
on the FULL data before thinning, then attached to the kept lines by line number.

usage: python scripts/build_ait_subset.py <dir with *_wazuh.json / *_aminer.json> [--cap 1500]
"""
from __future__ import annotations

import argparse
import gzip
import json
import math
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "ait"
SCENARIOS = ["fox", "harrison", "russellmitchell", "santos", "shaw", "wardbeck", "wheeler", "wilson"]


def load_phases(path: Path) -> dict[str, list[tuple[str, float, float]]]:
    phases: dict[str, list] = defaultdict(list)
    for line in path.read_text().splitlines()[1:]:
        if line.strip():
            sc, attack, st, en = line.split(",")
            phases[sc].append((attack, float(st), float(en)))
    return phases


def alert_time(obj: dict, kind: str) -> float:
    if kind == "aminer":
        return float(obj["LogData"]["Timestamps"][0])
    return datetime.fromisoformat(obj["@timestamp"].replace("Z", "+00:00")).timestamp()


def alert_key(obj: dict, kind: str) -> str:
    if kind == "aminer":
        ac = obj.get("AnalysisComponent", {})
        return f"aminer|{ac.get('AnalysisComponentName') or ac.get('AnalysisComponentType')}"
    rule = obj.get("rule", {})
    return f"wazuh|{rule.get('id')}|{rule.get('description')}"


def phase_of(t: float, phases) -> str:
    for attack, st, en in phases:
        if st <= t <= en:
            return attack
    return "none"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("--cap", type=int, default=1500)
    a = ap.parse_args()
    src = Path(a.src)
    phases = load_phases(OUT / "labels.csv")
    manifest = {"source": "AIT Alert Data Set (AIT-ADS) v1, Zenodo 10.5281/zenodo.8263181, CC BY 4.0",
                "method": f"per (scenario, file, alert type, attack phase) groups capped at {a.cap} alerts, "
                          "evenly spaced in time; smaller groups kept completely",
                "cap": a.cap, "files": {}}
    total_in = total_out = 0
    for sc in SCENARIOS:
        for kind in ("wazuh", "aminer"):
            f = src / f"{sc}_{kind}.json"
            if not f.exists():
                print(f"missing {f}", file=sys.stderr)
                continue
            # pass 1: group membership in time order
            recs: list[tuple[float, int, str]] = []
            with f.open(encoding="utf-8") as fh:
                for i, line in enumerate(fh):
                    if not line.strip():
                        continue
                    obj = json.loads(line)
                    t = alert_time(obj, kind)
                    recs.append((t, i, f"{alert_key(obj, kind)}|{phase_of(t, phases[sc])}"))
            groups: dict[str, list[tuple[float, int]]] = defaultdict(list)
            for t, i, g in recs:
                groups[g].append((t, i))
            # ---- ground truth: elevated alert types inside phase windows
            span = (max(t for t, _, _ in recs) - min(t for t, _, _ in recs)) or 1.0
            win_len = {ph: max(1.0, en - st) for ph, st, en in phases[sc]}
            outside = Counter(g.rsplit("|", 1)[0] for _, _, g in recs if g.endswith("|none"))
            inside_time = sum(win_len.values())
            elevated: dict[str, bool] = {}
            for g, members in groups.items():
                akey, ph = g.rsplit("|", 1)
                if ph == "none":
                    continue
                rate = outside[akey] / max(1.0, span - inside_time)
                elevated[g] = len(members) >= 5 * rate * win_len[ph] + 1
            attack_idx = {i: g.rsplit("|", 1)[1] for _, i, g in recs if elevated.get(g)}
            keep: set[int] = set()
            stats = {}
            for g, members in groups.items():
                members.sort()
                if len(members) <= a.cap:
                    chosen = members
                else:
                    step = len(members) / a.cap
                    chosen = [members[min(len(members) - 1, math.floor(k * step))] for k in range(a.cap)]
                keep.update(i for _, i in chosen)
                stats[g] = [len(members), len(chosen)]
            # pass 2: copy kept lines unchanged
            out = OUT / f"{sc}_{kind}.jsonl.gz"
            line_labels: dict[int, str] = {}
            n_out = 0
            with f.open(encoding="utf-8") as fh, gzip.open(out, "wt", encoding="utf-8", compresslevel=9) as w:
                for i, line in enumerate(fh):
                    if i in keep:
                        n_out += 1
                        w.write(line if line.endswith("\n") else line + "\n")
                        if i in attack_idx:
                            line_labels[n_out] = attack_idx[i]  # 1-based line number in the subset file
            (OUT / f"{sc}_{kind}.labels.json").write_text(json.dumps(
                {"scenario": sc, "kind": kind, "lines": line_labels,
                 "phase_counts_full": dict(Counter(attack_idx.values())),
                 "phase_counts_kept": dict(Counter(line_labels.values()))}, separators=(",", ":")))
            manifest["files"][out.name] = {"scenario": sc, "kind": kind, "original": len(recs),
                                           "kept": len(keep), "attack_full": len(attack_idx),
                                           "attack_kept": len(line_labels), "groups": stats}
            total_in += len(recs)
            total_out += len(keep)
            print(f"{out.name}: {len(recs):,} -> {len(keep):,}  attack {len(attack_idx):,} -> {len(line_labels):,}  "
                  f"{dict(Counter(line_labels.values()))}")
    manifest["labels"] = ("phase windows from labels.csv; an alert is attack-labelled when its alert type is "
                          "elevated in the window: count >= 5 x baseline expectation + 1 (baseline = same scenario, "
                          "same alert type, outside all windows)")
    manifest["original_total"] = total_in
    manifest["kept_total"] = total_out
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=1))
    print(f"total {total_in:,} -> {total_out:,}")


if __name__ == "__main__":
    main()
