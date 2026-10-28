"""Evidence-aware correlation engine.

Algorithm (all steps deterministic and explainable):

1. **Signal selection** – only events carrying at least one detector/signature tag
   can be linked. Untagged traffic stays as context (reported as unassigned).
2. **Entity extraction** – each signal event exposes entity keys:
   ``flow:<community_id|uid>`` (same connection), ``pair:<src>><dst>`` (directional
   host pair) and ``ip:<addr>`` (single endpoint). Infrastructure IPs from settings
   and *popular* IPs (reached by many distinct sources among signal events – fan-in)
   are never used on their own.
3. **Candidate generation** – per entity bucket, events are time-sorted and each
   event is compared only with the previous ``max_neighbors_per_entity`` events
   whose activity ended no more than ``link_window_seconds`` earlier. No global
   all-pairs comparison.
4. **Pairwise score** = w_entity·E + w_time·T + w_behavior·B + w_cross_sensor·C
   (clipped to 0..1). E: strongest shared entity (flow 1.0, same-direction pair 0.9,
   reversed pair 0.8, shared endpoint in the same role 0.6, pivot – the target of
   one event is the source of the other – 0.55). T: 1 − gap/window, where gap is the
   time between the end of the earlier event and the start of the later one.
   B: stage compatibility (same stage 1.0, plausible forward progression 0.8,
   unrelated/unknown 0.5, regression 0.3). C: 1 if different sensors observed the
   same flow or host pair.
5. **Sparse graph** – each event keeps at most 3 best links above ``link_threshold``.
6. **Grouping with safeguards** – connected components, then (a) split where the
   member timeline has a gap above ``max_group_gap_seconds`` and (b) cut weak
   *bridges* (single links whose removal separates two sub-groups that each meet the
   minimum size and share no host pair). Groups in which no event indicates an attack
   stage (only policy/info signatures), or only anomaly-detector hits, are not incidents. Events without an attack-stage tag (e.g.
   policy/info signatures) can only link through the same flow or host pair. Components smaller than
   ``min_incident_events`` are left unassigned (noise).
Every accepted link is returned with its components, shared entities, time gap,
rule name and a plain-language explanation.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime

import networkx as nx

from app.core.config import CorrelationSettings
from app.correlation.model import STAGES, EventView

MAX_LINKS_PER_EVENT = 3
MAX_ACCEPTED_PER_BUCKET = 2 * MAX_LINKS_PER_EVENT
STRONG_MARGIN = 0.15


@dataclass
class Link:
    a: str
    b: str
    score: float
    entity: float
    time: float
    behavior: float
    cross_sensor: float
    shared: list[str]
    dt_seconds: float
    rule: str
    explanation: str
    uncertainty: str = ""

    @property
    def components(self) -> dict[str, float]:
        return {"entity": round(self.entity, 3), "time": round(self.time, 3),
                "behavior": round(self.behavior, 3), "cross_sensor": round(self.cross_sensor, 3)}


@dataclass
class Group:
    event_ids: list[str]
    links: list[Link] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class CorrelationResult:
    groups: list[Group]
    unassigned: list[str]
    signal_ids: list[str]
    popular_entities: list[str]
    n_candidates: int
    n_links: int


def _entities(e: EventView, blocked: set[str]) -> dict[str, str]:
    """entity key -> role ('flow' | 'pair' | 'src' | 'dst')."""
    ents: dict[str, str] = {}
    if e.community_id:
        ents["flow:" + e.community_id] = "flow"
    if e.flow_uid:
        ents["uid:" + e.flow_uid] = "flow"
    if e.src and e.dst:
        ents[f"pair:{e.src}>{e.dst}"] = "pair"
    if e.src and e.src not in blocked:
        ents["ip:" + e.src] = "src"
    if e.dst and e.dst not in blocked:
        ents["ip:" + e.dst] = "dst"
    return ents


def _behavior(sa: str | None, sb: str | None) -> tuple[float, str]:
    if sa is None or sb is None:
        return 0.5, "no stage information"
    ia, ib = STAGES.index(sa), STAGES.index(sb)
    if ia == ib:
        return 1.0, f"both events indicate {sa.replace('_', ' ')}"
    if 0 < ib - ia <= 3:
        return 0.8, f"plausible progression {sa.replace('_', ' ')} → {sb.replace('_', ' ')}"
    if ib > ia:
        return 0.6, f"distant progression {sa.replace('_', ' ')} → {sb.replace('_', ' ')}"
    return 0.3, f"later event looks like an earlier stage ({sb.replace('_', ' ')} after {sa.replace('_', ' ')})"


def _entity_strength(ea: EventView, eb: EventView, shared: list[str], ents_a: dict, ents_b: dict) -> tuple[float, str]:
    best, why = 0.0, ""
    for k in shared:
        ra, rb = ents_a[k], ents_b[k]
        if ra == "flow":
            s, w = 1.0, "same network flow (community ID / flow UID)"
        elif ra == "pair":
            s, w = 0.9, f"same host pair {ea.src} → {ea.dst}"
        elif ra == rb:
            s, w = 0.6, f"shared {'source' if ra == 'src' else 'destination'} {k[3:]}"
        else:
            s, w = 0.55, f"pivot: {k[3:]} is the {'target' if ra == 'dst' else 'source'} of the earlier event and the {'source' if rb == 'src' else 'target'} of the later one"
        if s > best:
            best, why = s, w
    # reversed pair (b's src/dst are a's dst/src)
    if ea.src and ea.dst and eb.src == ea.dst and eb.dst == ea.src and best < 0.8:
        best, why = 0.8, f"reverse direction of host pair {ea.src} ↔ {ea.dst}"
    return best, why


def popular_ips(signal: list[EventView], cfg: CorrelationSettings) -> set[str]:
    """IPs that many *different* sources reach (fan-in), e.g. resolvers, proxies, shared
    servers. A scanner or attacker has high fan-out instead and must stay linkable."""
    sources_per_dst: dict[str, set[str]] = defaultdict(set)
    all_srcs: set[str] = set()
    for e in signal:
        if e.src and e.dst:
            sources_per_dst[e.dst].add(e.src)
            all_srcs.add(e.src)
    limit = max(5, cfg.popular_entity_share * (len(all_srcs) or 1))
    return {ip for ip, s in sources_per_dst.items() if len(s) >= limit}


def score_pair(a: EventView, b: EventView, ents_a: dict, ents_b: dict, cfg: CorrelationSettings) -> Link | None:
    """``a`` must start no later than ``b``."""
    shared = [k for k in ents_a if k in ents_b]
    if not shared:
        return None
    gap = max(0.0, (b.ts - a.end).total_seconds())
    if gap > cfg.link_window_seconds:
        return None
    E, ent_why = _entity_strength(a, b, shared, ents_a, ents_b)
    if E <= 0:
        return None
    if E < 0.8 and (a.stage is None or b.stage is None):
        # Context-free alerts (policy/info signatures) may only join through the same
        # flow or host pair – a shared busy server alone is not evidence of a relationship.
        return None
    T = 1.0 - gap / cfg.link_window_seconds
    B, beh_why = _behavior(a.stage, b.stage)
    same_flow_or_pair = any(ents_a[k] in ("flow", "pair") for k in shared)
    C = 1.0 if (a.sensor != b.sensor and same_flow_or_pair) else 0.0
    score = min(1.0, cfg.w_entity * E + cfg.w_time * T + cfg.w_behavior * B + cfg.w_cross_sensor * C)
    if score < cfg.link_threshold:
        return None
    rule = ("same-flow" if E >= 1.0 else "same-host-pair" if E >= 0.8 else
            "shared-endpoint" if E >= 0.6 else "pivot-endpoint")
    if C:
        rule += "+cross-sensor"
    expl = (f"{ent_why}; {gap:.0f}s apart; {beh_why}"
            + ("; observed by both Suricata and Zeek" if C else ""))
    unc = ""
    if rule.startswith("pivot"):
        unc = "Linked only through a shared endpoint in different roles; the relationship is a hypothesis."
    elif B <= 0.3:
        unc = "Stage order is unusual for an attack progression."
    return Link(a.event_id, b.event_id, round(score, 4), E, T, B, C, shared, round(gap, 1), rule, expl, unc)


def correlate(events: list[EventView], cfg: CorrelationSettings) -> CorrelationResult:
    signal = [e for e in events if e.is_signal]
    signal.sort(key=lambda e: (e.ts, e.event_id))
    blocked = set(cfg.infrastructure_ips)
    popular = popular_ips(signal, cfg) - blocked
    blocked |= popular
    ents = {e.event_id: _entities(e, blocked) for e in signal}
    by_id = {e.event_id: e for e in signal}

    buckets: dict[str, list[EventView]] = defaultdict(list)
    for e in signal:
        for k in ents[e.event_id]:
            buckets[k].append(e)

    best: dict[str, dict[str, Link]] = defaultdict(dict)   # later event -> {earlier: link}
    n_candidates = 0
    for k, evs in buckets.items():
        if len(evs) < 2:
            continue
        for i, b in enumerate(evs):
            lo = max(0, i - cfg.max_neighbors_per_entity)
            accepted = 0
            for a in reversed(evs[lo:i]):
                if (b.ts - a.end).total_seconds() > cfg.link_window_seconds and (b.ts - a.ts).total_seconds() > 86400:
                    break
                if a.event_id in best[b.event_id]:
                    continue
                n_candidates += 1
                link = score_pair(a, b, ents[a.event_id], ents[b.event_id], cfg)
                if link:
                    best[b.event_id][a.event_id] = link
                    accepted += 1
                    # neighbours are visited nearest-first, so further ones in this bucket can only
                    # score lower on time; enough accepted links per bucket bounds the work on dense data
                    if accepted >= MAX_ACCEPTED_PER_BUCKET:
                        break

    g = nx.Graph()
    g.add_nodes_from(by_id)
    links: dict[tuple[str, str], Link] = {}
    for b_id, cands in best.items():
        for link in sorted(cands.values(), key=lambda l: -l.score)[:MAX_LINKS_PER_EVENT]:
            key = tuple(sorted((link.a, link.b)))
            if key not in links or links[key].score < link.score:
                links[key] = link
                g.add_edge(*key, weight=link.score)

    groups: list[Group] = []
    unassigned: list[str] = []
    strong = cfg.link_threshold + STRONG_MARGIN
    links_of: dict[str, list[tuple[str, str]]] = defaultdict(list)  # node -> link keys (avoids O(groups·links))
    for key in links:
        links_of[key[0]].append(key)
    for comp in nx.connected_components(g):
        for part, notes in _split(comp, g, links, by_id, cfg, strong):
            if len(part) < cfg.min_incident_events:
                unassigned.extend(part)
                continue
            if not any(by_id[i].has_attack_evidence for i in part):
                # only context-free alerts (policy/info signatures, protocol-decoder noise) or only
                # log-anomaly detector hits: no attack behaviour is indicated, so no incident
                unassigned.extend(part)
                continue
            sub_links = [links[k] for x in part for k in links_of.get(x, ()) if k[1] in part]
            groups.append(Group(sorted(part, key=lambda i: (by_id[i].ts, i)), sub_links, notes))
    unassigned.extend(e.event_id for e in events if not e.is_signal)
    groups.sort(key=lambda gr: (by_id[gr.event_ids[0]].ts, gr.event_ids[0]))
    return CorrelationResult(groups, unassigned, [e.event_id for e in signal], sorted(popular),
                             n_candidates, len(links))


def _split(comp: set[str], g: nx.Graph, links: dict, by_id: dict[str, EventView], cfg: CorrelationSettings,
           strong: float) -> list[tuple[set[str], list[str]]]:
    """Apply over-merging safeguards to one connected component."""
    # (a) time-gap split
    members = sorted(comp, key=lambda i: by_id[i].ts)
    parts: list[set[str]] = []
    current: set[str] = set()
    horizon: datetime | None = None
    notes: list[str] = []
    for i in members:
        e = by_id[i]
        if horizon is not None and (e.ts - horizon).total_seconds() > cfg.max_group_gap_seconds:
            parts.append(current)
            notes.append(f"split at a {(e.ts - horizon).total_seconds() / 3600:.1f} h gap in activity")
            current = set()
            horizon = None
        current.add(i)
        horizon = e.end if horizon is None or e.end > horizon else horizon
    parts.append(current)

    out: list[tuple[set[str], list[str]]] = []
    for p in parts:
        sub = g.subgraph(p).copy()
        queue = [set(c) for c in nx.connected_components(sub)]
        while queue:
            nodes = queue.pop()
            h = sub.subgraph(nodes)
            cut = None
            if len(nodes) >= 2 * cfg.min_incident_events:
                for x, y in nx.bridges(h):
                    l = links[tuple(sorted((x, y)))]
                    if l.score >= strong or any(k.startswith(("pair:", "flow:", "uid:")) for k in l.shared):
                        continue
                    h2 = h.copy()
                    h2.remove_edge(x, y)
                    sides = list(nx.connected_components(h2))
                    if all(len(s) >= cfg.min_incident_events for s in sides):
                        cut = (x, y, sides, l)
                        break
            if cut:
                x, y, sides, l = cut
                sub.remove_edge(x, y)
                note = (f"weak bridge removed between {x} and {y} (score {l.score:.2f}, {l.rule}) "
                        "to avoid transitive over-merging")
                notes.append(note)
                queue.extend(set(s) for s in sides)
            else:
                out.append((nodes, list(notes)))
    return out


# --------------------------------------------------------------------------- #
# Baselines used by the evaluation laboratory
# --------------------------------------------------------------------------- #
def baseline_independent(events: list[EventView]) -> list[list[str]]:
    """Baseline A: every alert-bearing event is its own triage item."""
    return [[e.event_id] for e in events if e.is_signal]


def baseline_rule_based(events: list[EventView], cfg: CorrelationSettings) -> list[list[str]]:
    """Baseline B: union events that share any IP within the time window (no
    behaviour, no safeguards). Infrastructure IPs are still excluded so the
    comparison isolates the effect of the evidence-aware scoring."""
    signal = sorted((e for e in events if e.is_signal), key=lambda e: e.ts)
    parent = {e.event_id: e.event_id for e in signal}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    last_seen: dict[str, EventView] = {}
    infra = set(cfg.infrastructure_ips)
    for e in signal:
        for ip in {e.src, e.dst} - {None} - infra:
            prev = last_seen.get(ip)
            if prev is not None and (e.ts - prev.end).total_seconds() <= cfg.link_window_seconds:
                parent[find(e.event_id)] = find(prev.event_id)
            if prev is None or e.end >= prev.end:
                last_seen[ip] = e
    groups: dict[str, list[str]] = defaultdict(list)
    for e in signal:
        groups[find(e.event_id)].append(e.event_id)
    return list(groups.values())


def group_stats(groups: list[list[str]], min_size: int) -> Counter:
    c: Counter = Counter()
    for gr in groups:
        c["incidents" if len(gr) >= min_size else "singletons"] += 1
    return c
