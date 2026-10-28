# Correlation method

## What is established, adapted and new

| Part | Status |
|---|---|
| Normalising heterogeneous sensors into one schema; temporal + entity correlation; kill-chain/ATT&CK tactic progression for campaign building | **Established** (alert-correlation literature; Ferazza et al. 2026 §3.2, §6) |
| Using network-only evidence (IPs, ports, flow IDs/Community ID, conn state, bytes, DNS/TLS/HTTP metadata) instead of PIDs and host logs | **Adaptation** of the base paper, which used Linux syslog and SentinelOne EDR |
| Replacing GNN sequencing + LLM-summary-then-cluster with an explainable pairwise score, so the LLM sits *after* correlation | **Engineering design choice** for explainability and robustness (an LLM error cannot change grouping) |
| Explicit OBSERVED / INFERRED / NOT OBSERVED stage states, separate risk and confidence, evidence-validated LLM summaries with injection defences | **Integration** of known ideas into one pipeline; not claimed as new science |

No GNN or transformer classifier is used: there is no labelled network training data in scope, and the
prototype must run on a laptop and explain every decision.

## 1. Detectors (`correlation/detectors.py`)

Tags mark *signal* events. Untagged events (ordinary flows, DNS lookups) stay as context and are never
linked, which keeps background traffic out of incidents.

| Tag | Rule (defaults, all configurable) | Stage |
|---|---|---|
| `ids_alert`, `zeek_notice` + signature tags | any Suricata alert / Zeek notice; signature text mapped by `mapping_rules.json` (first match wins) | per rule |
| `host_sweep` | ≥ 15 distinct destination hosts from one source within 15 min over failed/short connections | reconnaissance |
| `port_scan` | ≥ 15 distinct ports on one host from one source within 15 min | scanning |
| `ssh_bruteforce` | ≥ 10 failed Zeek ssh.log authentications for a host pair within 1 h | credential access |
| `auth_success_after_failures` | successful ssh.log auth preceded by ≥ 10 failures in the previous 2 h | access |
| `beacon` | internal→external series of ≥ 8 connections to the same host:port with median-absolute-deviation / median interval ≤ 0.15 | C2 (inferred) |
| `large_outbound` | internal→external connection sending ≥ 50 MB | exfiltration (inferred) |
| `dns_tunnel` | first DNS label ≥ 40 chars with Shannon entropy ≥ 3.5 bits/char | exfiltration (inferred) |

## 2. Linking (`correlation/engine.py`)

Entities per signal event: `flow:<community_id>` / `uid:<flow uid>`, `pair:<src>><dst>`, `ip:<src>`,
`ip:<dst>`. **Infrastructure IPs** (configured) and **popular IPs** – reached by ≥ max(5, 25 %) of the
distinct signal sources (fan-in, e.g. a resolver or busy server) – are not used as single-IP entities.
Attackers and scanners have high *fan-out*, not fan-in, so they stay linkable.

Candidates come from entity buckets: each event is compared with at most 50 earlier events in each of
its buckets (no all-pairs comparison). A pair is scored only when the gap between the end of the earlier
event and the start of the later one is ≤ the link window (default 3,600 s):

```
score = 0.45·E + 0.20·T + 0.25·B + 0.10·C            (clipped to 0..1, accepted if ≥ 0.55)
E  entity strength: same flow 1.0 · same-direction host pair 0.9 · reversed pair 0.8 ·
   shared endpoint in the same role 0.6 · pivot (target of one = source of the other) 0.55
T  1 − gap / window
B  stage compatibility: same 1.0 · forward ≤ 3 steps 0.8 · further forward 0.6 · unknown 0.5 · backward 0.3
C  1 if different sensors saw the same flow or host pair
```
Events without a stage tag (policy/info signatures) may link only through the same flow or host pair.
Each event keeps its 3 best links; every stored link records its components, shared entities, gap, rule
name and an explanation, plus an uncertainty note for pivot-only or out-of-order links.

## 3. Grouping safeguards

1. Connected components of the link graph.
2. **Time-gap split**: a component is split wherever member activity pauses longer than 7,200 s.
3. **Weak-bridge cut**: a link that is a graph bridge, below threshold + 0.15, not based on a host pair
   or flow, and whose removal leaves two sides that each meet the minimum size, is removed (recorded in
   the incident's correlation notes). This prevents A–B–C chains through one weak shared endpoint.
4. Components with fewer than 2 events stay unassigned (reported as noise / individual items).

## 4. Attack chain

Stages are ordered by their earliest supporting event. OBSERVED requires direct telemetry (sweep, scan,
failed auths, logged successful auth, C2 signature). INFERRED covers hypotheses: beacon timing, large
transfers or DNS tunnelling ("possible exfiltration"), web-attack attempts, and access implied when a host
targeted earlier later starts suspicious outbound traffic. Stages without evidence are shown as NOT
OBSERVED – never filled in because they "should" be there.

## 5. Scores

**Risk (0–100)** – weighted sum of factors in 0..1 (weights normalised to 100): source severity (distinct
signature/notice/detector units, repeats count once), distinct corroboration (log-scaled), attack
progression (inferred stages count half), internal hosts involved, high-impact indicators, cross-sensor
corroboration, temporal concentration; minus a penalty for authorised scanners when only scan stages are
present. Severity: Critical ≥ 80, High ≥ 60, Medium ≥ 35, Low ≥ 15, else Informational.

**Correlation confidence (0–1)** – identifier strength 0.3, temporal 0.2, behavioural 0.2, cross-sensor
0.1, source reliability 0.2, minus up to 0.15 for parsing warnings and pivot-only links. It is a heuristic
score, **not a calibrated probability**.
