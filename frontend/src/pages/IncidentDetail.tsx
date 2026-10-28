import {
  AlertTriangle, ArrowLeft, Bot, CheckCircle2, ChevronRight, ExternalLink, FileDown, FileJson, FileSpreadsheet, Link2,
  RotateCcw, ShieldQuestion, Sparkles, UserCheck,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import type { EventItem, IncidentDetail, Summary } from '../api/types'
import { EventDrawer } from '../components/EventDrawer'
import {
  Button, Card, Chip, cx, EmptyState, ErrorState, EvidenceBadge, HelpTip, Pagination, ScoreBar, SensorBadge, SEV_COLOR,
  SeverityBadge, Spinner, StatusBadge, TacticPill,
} from '../components/ui'
import { useApp } from '../lib/app-context'
import { fmtBytes, fmtDuration, fmtScore, fmtSpan, fmtTime, STAGE_LABELS, STAGES, STATUS_LABELS, tzLabel } from '../lib/format'
import { useAsync } from '../lib/hooks'

function EvidenceRef({ id, onOpen }: { id: string; onOpen: (id: string) => void }) {
  return <button onClick={() => onOpen(id)} className="mono rounded-md bg-sky-50 px-1.5 py-0.5 text-[10px] font-medium text-sky-800 ring-1 ring-sky-200/70 hover:bg-sky-100 hover:underline">{id}</button>
}

function eventDetail(e: EventItem): string {
  if (e.alert_signature) return e.alert_signature
  if (e.dns_query) return `DNS ${e.dns_query}`
  if (e.event_type === 'ssh_auth') return `SSH auth ${e.auth_success === true ? 'success' : e.auth_success === false ? 'failure' : ''}`
  if (e.tls_server_name) return `TLS ${e.tls_server_name}`
  if (e.http_host) return `HTTP ${e.http_host}${e.http_uri ?? ''}`
  if (e.bytes_sent !== null) return `${e.connection_state ?? ''} ${fmtBytes(e.bytes_sent)} out${e.duration ? `, ${e.duration.toFixed(1)}s` : ''}`
  return e.event_type
}

// ---------------------------------------------------------------- attack chain
const multiDay = (inc: IncidentDetail) => new Date(inc.last_seen).getTime() - new Date(inc.first_seen).getTime() > 20 * 3600 * 1000

function AttackChain({ inc, onOpen, onStage }: { inc: IncidentDetail; onOpen: (id: string) => void; onStage: (s: string) => void }) {
  return (
    <Card title="Attack chain" subtitle="Probable sequence reconstructed from correlated events. Stages are never filled in without evidence.">
      <ol className="grid gap-3 sm:grid-cols-2 md:grid-cols-4 xl:grid-cols-7">
        {inc.stages.map((s) => (
          <li key={s.stage} className={cx('flex flex-col rounded-2xl border p-3.5',
            s.status === 'OBSERVED' ? 'border-sky-300 bg-gradient-to-b from-sky-50 to-white shadow-sm' : s.status === 'INFERRED' ? 'inferred-outline border-inferred/60 bg-amber-50/40' : 'border-ink-700 bg-ink-900/40 opacity-60')}>
            <div className="flex items-center justify-between gap-1">
              <span className={cx('num grid h-6 w-6 place-items-center rounded-full text-[11px] font-bold', s.status === 'OBSERVED' ? 'gold-gradient text-white' : 'bg-ink-700 text-muted')}>{s.order}</span>
              <EvidenceBadge status={s.status} small />
            </div>
            <div className="mt-1.5 text-sm font-semibold">{STAGE_LABELS[s.stage]}</div>
            {s.first_timestamp && <div className="num text-[11px] text-muted">{fmtTime(s.first_timestamp, { date: multiDay(inc) })}</div>}
            {s.status !== 'NOT_OBSERVED' ? (
              <>
                <p className="mt-2 text-xs leading-snug text-muted">{s.observed_behavior}</p>
                <p className="mt-2 text-[11px] leading-snug text-faint">{s.explanation}</p>
                <div className="mt-auto flex items-center justify-between pt-2 text-[11px] text-muted">
                  <span>{s.event_ids.length} events · {s.evidence_strength}</span>
                  <button className="text-sky-700 hover:underline" onClick={() => onStage(s.stage)}>Show</button>
                </div>
                {s.event_ids[0] && <div className="mt-1"><EvidenceRef id={s.event_ids[0]} onOpen={onOpen} /></div>}
              </>
            ) : <p className="mt-2 text-xs text-faint">No supporting evidence in the telemetry.</p>}
          </li>
        ))}
      </ol>
    </Card>
  )
}

// ---------------------------------------------------------------- timeline
function Timeline({ inc, stage, setStage, onOpen }: { inc: IncidentDetail; stage: string; setStage: (s: string) => void; onOpen: (id: string) => void }) {
  const [page, setPage] = useState(1)
  useEffect(() => setPage(1), [stage])
  const { data, error, loading } = useAsync(() => api.incidentEvents(inc.id, { page, page_size: 25, stage }), [inc.id, page, stage])
  const mapsByEvent = new Map<string, string[]>()
  inc.mappings.forEach((m) => m.evidence_event_ids.forEach((e) => mapsByEvent.set(e, [...(mapsByEvent.get(e) ?? []), m.technique_id ?? m.tactic_id])))
  const stageStatus = Object.fromEntries(inc.stages.map((s) => [s.stage, s.status]))
  return (
    <Card title="Attack timeline" subtitle={`All ${inc.event_count.toLocaleString()} grouped events in chronological order (${tzLabel()}).`}
      actions={
        <select aria-label="Filter by stage" value={stage} onChange={(e) => setStage(e.target.value)} className="rounded-xl border-0 bg-white px-2.5 py-1.5 text-xs shadow-sm ring-1 ring-ink-600">
          <option value="">All stages</option>
          {STAGES.filter((s) => inc.stages_present.includes(s)).map((s) => <option key={s} value={s}>{STAGE_LABELS[s]}</option>)}
        </select>}>
      {error ? <ErrorState error={error} /> : loading && !data ? <Spinner /> : data && (
        <>
          <div className="overflow-x-auto">
            <table className="table-modern w-full text-xs">
              <thead className="text-left"><tr>
                <th className="px-2 py-2 font-medium">Time</th><th className="pr-3 font-medium">Event</th><th className="pr-3 font-medium">Type</th>
                <th className="pr-3 font-medium">Source → destination</th><th className="pr-3 font-medium">Details</th><th className="pr-3 font-medium">Stage</th><th className="font-medium">ATT&CK</th>
              </tr></thead>
              <tbody className="divide-y divide-ink-700/60">
                {data.items.map((e) => (
                  <tr key={e.event_id} className="hover:bg-ink-800/50">
                    <td className="num whitespace-nowrap px-2 py-1.5 text-muted">{fmtTime(e.timestamp_utc, { date: multiDay(inc) })}</td>
                    <td className="pr-3"><EvidenceRef id={e.event_id} onOpen={onOpen} /></td>
                    <td className="whitespace-nowrap pr-3"><SensorBadge sensor={e.source_sensor} /> <span className="text-muted">{e.event_type}</span></td>
                    <td className="mono whitespace-nowrap pr-3 text-[11px]">{e.source_ip}{e.source_port !== null && `:${e.source_port}`} → {e.destination_ip}{e.destination_port !== null && `:${e.destination_port}`} <span className="text-faint">{e.transport_protocol}</span></td>
                    <td className="max-w-[22rem] truncate pr-3 text-muted" title={eventDetail(e)}>{eventDetail(e)}</td>
                    <td className="whitespace-nowrap pr-3">{e.stage ? <span className="inline-flex items-center gap-1">{STAGE_LABELS[e.stage]} <EvidenceBadge status={stageStatus[e.stage] ?? 'NOT_OBSERVED'} small /></span> : <span className="text-faint">context</span>}</td>
                    <td className="mono text-[10px] text-muted">{(mapsByEvent.get(e.event_id) ?? []).join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination page={page} pageSize={25} total={data.total} onPage={setPage} />
        </>
      )}
    </Card>
  )
}

// ---------------------------------------------------------------- linkage evidence
function Linkage({ inc, onOpen }: { inc: IncidentDetail; onOpen: (id: string) => void }) {
  const [page, setPage] = useState(1)
  const summary = useAsync(() => api.linkSummary(inc.id), [inc.id, inc.run_id])
  const links = useAsync(() => api.incidentLinks(inc.id, { page, page_size: 10 }), [inc.id, page, inc.run_id])
  return (
    <Card title="Why these events were linked" subtitle={`${inc.link_count.toLocaleString()} accepted links (each event keeps at most its 3 strongest). Score = entity + time + behaviour + cross-sensor.`}>
      {summary.data && (
        <div className="mb-3 flex flex-wrap gap-2">
          {summary.data.map((r) => (
            <div key={r.rule} className="rounded-xl border border-ink-700 bg-white px-3 py-2 text-xs shadow-sm">
              <div className="mono text-sky-700">{r.rule}</div>
              <div className="num text-muted">{r.count} links · avg {r.avg_score.toFixed(2)} · min {r.min_score.toFixed(2)}</div>
            </div>
          ))}
        </div>
      )}
      {inc.correlation_notes.length > 0 && (
        <div className="mb-3 rounded-lg border border-amber-500/30 bg-amber-500/5 p-2 text-xs text-amber-700">
          {inc.correlation_notes.map((n) => <div key={n}>Safeguard: {n}</div>)}
        </div>
      )}
      {links.error ? <ErrorState error={links.error} /> : links.data && (
        <>
          <ul className="divide-y divide-ink-700/70">
            {links.data.items.map((l) => (
              <li key={l.event_a + l.event_b} className="py-2 text-xs">
                <div className="flex flex-wrap items-center gap-2">
                  <EvidenceRef id={l.event_a} onOpen={onOpen} /><Link2 size={12} className="text-faint" aria-hidden /><EvidenceRef id={l.event_b} onOpen={onOpen} />
                  <span className="mono text-sky-700">{l.rule}</span>
                  <span className="num font-semibold">{l.score.toFixed(2)}</span>
                  <span className="num text-faint">E {l.components.entity.toFixed(2)} · T {l.components.time.toFixed(2)} · B {l.components.behavior.toFixed(2)} · X {l.components.cross_sensor.toFixed(0)}</span>
                </div>
                <div className="mt-1 text-muted">{l.explanation}</div>
                <div className="mono mt-0.5 text-[10px] text-faint">shared: {l.shared_entities.join(', ')}</div>
                {l.uncertainty && <div className="mt-0.5 text-amber-700/90">Uncertainty: {l.uncertainty}</div>}
              </li>
            ))}
          </ul>
          <Pagination page={page} pageSize={10} total={links.data.total} onPage={setPage} />
        </>
      )}
    </Card>
  )
}

// ---------------------------------------------------------------- ATT&CK
function Attack({ inc, onOpen }: { inc: IncidentDetail; onOpen: (id: string) => void }) {
  return (
    <Card title="ATT&CK analysis" subtitle={`Hybrid mapping (signature + behaviour rules) validated against ${inc.mappings[0]?.attack_version ?? 'the local catalog'}. LLM output is never used for mappings.`}>
      {inc.mappings.length === 0 ? <p className="text-sm text-muted">No ATT&CK mapping is supported by the evidence.</p> : (
        <div className="overflow-x-auto">
          <table className="table-modern w-full text-xs">
            <thead className="text-left"><tr>
              <th className="px-2 py-2 font-medium">Tactic</th><th className="pr-3 font-medium">Technique</th><th className="pr-3 font-medium">Evidence</th>
              <th className="pr-3 font-medium">Method</th><th className="pr-3 font-medium">Confidence</th><th className="font-medium">Reason &amp; evidence</th>
            </tr></thead>
            <tbody className="divide-y divide-ink-700/60">
              {inc.mappings.map((m) => (
                <tr key={m.tactic_id + (m.technique_id ?? '')} className="align-top">
                  <td className="px-2 py-2"><TacticPill tactic={m.tactic_name} /><div className="mono text-[10px] text-faint">{m.tactic_id}</div></td>
                  <td className="pr-3 py-2">
                    {m.technique_id ? (
                      <a href={m.url ?? '#'} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 hover:underline">
                        <span className="mono text-sky-700">{m.technique_id}</span><ExternalLink size={10} aria-hidden />
                      </a>) : <span className="text-faint">tactic only</span>}
                    <div className="text-muted">{m.technique_name}</div>
                  </td>
                  <td className="pr-3 py-2"><EvidenceBadge status={m.status} small /></td>
                  <td className="mono pr-3 py-2 text-muted">{m.method}</td>
                  <td className="w-24 pr-3 py-2"><div className="num">{m.confidence.toFixed(2)}</div><ScoreBar value={m.confidence} max={1} color={m.status === 'OBSERVED' ? '#c9a227' : '#3d3426'} /></td>
                  <td className="py-2 text-muted">{m.reason}
                    <div className="mt-1 flex flex-wrap gap-1">{m.evidence_event_ids.slice(0, 4).map((e) => <EvidenceRef key={e} id={e} onOpen={onOpen} />)}{m.evidence_event_ids.length > 4 && <span className="text-faint">+{m.evidence_event_ids.length - 4}</span>}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

// ---------------------------------------------------------------- scores
function Scores({ inc }: { inc: IncidentDetail }) {
  return (
    <Card title="Risk & confidence" subtitle="Two separate scores: risk = how much it matters; confidence = how well the links hold.">
      <div className="mb-3 flex items-baseline justify-between">
        <span className="text-xs text-muted">Risk score <HelpTip text="Σ weight × factor (each factor 0–1, weights in Settings, normalised to 0–100). Repeated copies of the same alert count once." /></span>
        <span className="num text-2xl font-semibold" style={{ color: SEV_COLOR[inc.severity] }}>{inc.risk_score.toFixed(1)}</span>
      </div>
      <ul className="space-y-2">
        {inc.risk_breakdown.map((b) => (
          <li key={b.factor} className="text-xs">
            <div className="flex justify-between"><span>{b.label}</span><span className={cx('num font-medium', (b.points ?? 0) < 0 && 'text-emerald-700')}>{(b.points ?? 0) > 0 ? '+' : ''}{b.points?.toFixed(1)}</span></div>
            {b.factor !== 'known_scanner' && <ScoreBar value={b.value} max={1} color={SEV_COLOR[inc.severity]} />}
            <div className="text-[11px] text-faint">{b.explanation}</div>
          </li>
        ))}
      </ul>
      <div className="mb-3 mt-5 flex items-baseline justify-between border-t border-ink-700 pt-4">
        <span className="text-xs text-muted">Correlation confidence <HelpTip text="Heuristic 0–1 score from identifier strength, timing, behaviour, cross-sensor corroboration and source reliability, minus a penalty for indirect/missing data. Not a calibrated probability." /></span>
        <span className="num text-2xl font-semibold text-sky-700">{fmtScore(inc.confidence)}</span>
      </div>
      <ul className="space-y-2">
        {inc.confidence_breakdown.map((b) => (
          <li key={b.factor} className="text-xs">
            <div className="flex justify-between"><span>{b.label}</span><span className="num">{(b.contribution ?? 0) >= 0 ? '+' : ''}{(b.contribution ?? 0).toFixed(3)}</span></div>
            {b.weight > 0 && <ScoreBar value={b.value} max={1} />}
            <div className="text-[11px] text-faint">{b.explanation}</div>
          </li>
        ))}
      </ul>
    </Card>
  )
}

// ---------------------------------------------------------------- AI narrative
function Narrative({ inc, onOpen, onUpdated }: { inc: IncidentDetail; onOpen: (id: string) => void; onUpdated: () => void }) {
  const { health, notify } = useApp()
  const settings = useAsync(() => api.settings(), [])
  const [busy, setBusy] = useState(false)
  const [model, setModel] = useState('')
  const s: Summary | null = inc.summary
  const llmModels = settings.data ? [settings.data.llm.primary_model, settings.data.llm.secondary_model].filter(Boolean) : []
  const run = async (mode: string) => {
    setBusy(true)
    try {
      const r = await api.summarize(inc.id, mode, mode === 'live' ? (model || llmModels[0]) : undefined)
      notify(r.generator === 'llm' ? 'success' : 'info', r.generator === 'llm' ? `Summary generated by ${r.model} in ${fmtDuration(r.latency_ms)}` : `Deterministic summary used: ${r.content.fallback_reason ?? ''}`)
      onUpdated()
    } catch (e) { notify('error', (e as Error).message) } finally { setBusy(false) }
  }
  const c = s?.content
  return (
    <Card id="narrative" title={<span className="flex items-center gap-2"><Bot size={15} aria-hidden />Analyst narrative</span>}
      subtitle="Generated only from the structured, sanitised incident fields. Untrusted log text is redacted if it looks like an instruction."
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <select aria-label="Model" value={model} onChange={(e) => setModel(e.target.value)} className="rounded-xl border-0 bg-white shadow-sm ring-1 ring-ink-600 px-2 py-1 text-xs">
            {llmModels.map((m) => <option key={m} value={m}>{m}{health?.llm.models.includes(m) ? '' : ' (not installed)'}</option>)}
          </select>
          <Button size="sm" variant="primary" disabled={busy} onClick={() => run('live')} title="Request a new summary from the local Ollama model"><Sparkles size={13} aria-hidden />{busy ? 'Generating…' : s ? 'Regenerate (live AI)' : 'Generate (live AI)'}</Button>
          <Button size="sm" disabled={busy} onClick={() => run('off')} title="Deterministic template, no LLM">Template summary</Button>
        </div>}>
      <div className="mb-4 flex flex-wrap gap-2">
        <div className="flex items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-1.5 text-xs font-semibold text-rose-700"><ShieldQuestion size={14} aria-hidden />Hypothesis, not proof of attack.</div>
        {s && (s.generator === 'llm'
          ? <div className="flex items-center gap-1.5 rounded-lg border border-violet-500/40 bg-violet-500/10 px-3 py-1.5 text-xs font-semibold text-violet-700"><Bot size={14} aria-hidden />AI-generated analysis — analyst review required.</div>
          : <div className="flex items-center gap-1.5 rounded-lg border border-slate-500/40 bg-slate-500/10 px-3 py-1.5 text-xs font-semibold text-slate-700">Deterministic fallback summary (no LLM) — analyst review required.</div>)}
        {!health?.llm.available && <div className="rounded-lg border border-ink-600 px-3 py-1.5 text-xs text-muted">Ollama unavailable — live requests fall back to the deterministic template.</div>}
      </div>
      {!s || !c ? (
        <EmptyState title="No summary yet">Generate one with the local model, or use the deterministic template (works without Ollama).</EmptyState>
      ) : (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-faint">
            <span>Generator: <b className="text-muted">{s.generator === 'llm' ? 'local LLM' : 'deterministic template'}</b></span>
            <span>Model: <b className="mono text-muted">{s.model}</b>{s.model_version && ` (${s.model_version})`}</span>
            <span>Generated: {fmtTime(s.created_at)} {tzLabel()}</span>
            <span>Status: {s.status}</span><span>Prompt: {s.prompt_version}</span>
            {s.generator === 'llm' && <><span>Latency: {fmtDuration(s.latency_ms)}</span><span>Attempts: {s.attempts}</span></>}
            {!s.is_current && <span className="text-amber-700">Evidence changed since generation — regenerate</span>}
          </div>
          {c.fallback_reason && <div className="text-xs text-muted">Fallback reason: {c.fallback_reason}</div>}
          {s.validation_errors.length > 0 && (
            <details className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-2 text-xs text-amber-700">
              <summary className="cursor-pointer">Model output was rejected by the validator ({s.validation_errors.length} issues)</summary>
              <ul className="mt-1 list-disc pl-5">{s.validation_errors.map((e) => <li key={e}>{e}</li>)}</ul>
            </details>
          )}
          {s.injection_flags.length > 0 && (
            <div className="rounded-lg border border-amber-500/40 bg-amber-500/5 p-3 text-xs text-amber-700">
              <div className="mb-1 flex items-center gap-1.5 font-semibold"><AlertTriangle size={13} aria-hidden />Instruction-like text found in untrusted log fields — redacted before summarisation and treated as evidence only</div>
              {s.injection_flags.map((f, i) => (
                <div key={i} className="mt-1">{f.event_id && <EvidenceRef id={f.event_id} onOpen={onOpen} />} <span className="mono">{f.field}</span>: “{f.excerpt}…”</div>
              ))}
            </div>
          )}
          <section><h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted">Executive summary</h3><p className="text-sm leading-relaxed">{c.executive_summary}</p></section>
          <section>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted">Probable sequence</h3>
            <ol className="space-y-1.5">
              {c.probable_sequence.map((x, i) => (
                <li key={i} className="flex flex-wrap items-start gap-2 text-sm"><ChevronRight size={14} className="mt-0.5 text-faint" aria-hidden /><span className="font-medium">{x.stage}</span><EvidenceBadge status={x.status} small />
                  <span className="text-muted">{x.description}</span><span className="flex gap-1">{x.evidence_event_ids.slice(0, 3).map((e) => <EvidenceRef key={e} id={e} onOpen={onOpen} />)}</span></li>
              ))}
            </ol>
          </section>
          <section>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted">Claims and supporting evidence</h3>
            <ul className="space-y-1.5">
              {c.claims.map((x, i) => (
                <li key={i} className="rounded-xl border border-ink-700 bg-white px-3 py-2 text-sm">
                  <div className="flex items-start gap-2"><EvidenceBadge status={x.status} small /><span>{x.text}</span></div>
                  <div className="mt-1 flex flex-wrap gap-1">{x.evidence_event_ids.map((e) => <EvidenceRef key={e} id={e} onOpen={onOpen} />)}</div>
                </li>
              ))}
            </ul>
          </section>
          <div className="grid gap-4 md:grid-cols-2">
            {([['Alternative benign explanations', c.alternative_explanations], ['Missing evidence', c.missing_evidence],
               ['Suggested investigation questions', c.investigation_questions], ['Recommended next steps (investigative only)', c.recommended_next_steps]] as [string, string[]][]).map(([t, xs]) => (
              <section key={t}><h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted">{t}</h3>
                <ul className="list-disc space-y-1 pl-5 text-sm text-muted">{xs.map((x) => <li key={x}>{x}</li>)}</ul></section>
            ))}
          </div>
        </div>
      )}
    </Card>
  )
}

// ---------------------------------------------------------------- workflow
function Workflow({ inc, onChanged }: { inc: IncidentDetail; onChanged: (d: IncidentDetail) => void }) {
  const { notify } = useApp()
  const analysts = useAsync(() => api.analysts(), [])
  const [actor, setActor] = useState(() => localStorage.getItem('ntdcp.analyst') || 'Analyst A')
  const [note, setNote] = useState('')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => { localStorage.setItem('ntdcp.analyst', actor) }, [actor])
  const patch = async (body: Parameters<typeof api.updateIncident>[1], msg: string) => {
    setBusy(true)
    try { onChanged(await api.updateIncident(inc.id, body)); notify('success', msg); setReason('') }
    catch (e) { notify('error', (e as Error).message) } finally { setBusy(false) }
  }
  const closed = inc.status === 'resolved' || inc.status === 'closed'
  return (
    <Card title={<span className="flex items-center gap-2"><UserCheck size={15} aria-hidden />Analyst workflow</span>} subtitle="Changes are saved to the database immediately.">
      <div className="space-y-3">
        <label className="flex flex-col gap-1 text-xs text-muted">Acting as
          <select value={actor} onChange={(e) => setActor(e.target.value)} className="rounded-xl border-0 bg-white shadow-sm ring-1 ring-ink-600 px-2 py-1.5 text-sm text-fg">
            {(analysts.data ?? [actor]).map((a) => <option key={a}>{a}</option>)}
          </select>
        </label>
        <div className="grid grid-cols-2 gap-2">
          <label className="flex flex-col gap-1 text-xs text-muted">Status
            <select disabled={busy} value={inc.status} onChange={(e) => patch({ status: e.target.value, actor, reason }, `Status set to ${STATUS_LABELS[e.target.value]}`)}
              className="rounded-xl border-0 bg-white shadow-sm ring-1 ring-ink-600 px-2 py-1.5 text-sm text-fg">
              {Object.entries(STATUS_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs text-muted">Assignee
            <select disabled={busy} value={inc.assignee ?? ''} onChange={(e) => patch({ assignee: e.target.value, actor }, e.target.value ? `Assigned to ${e.target.value}` : 'Unassigned')}
              className="rounded-xl border-0 bg-white shadow-sm ring-1 ring-ink-600 px-2 py-1.5 text-sm text-fg">
              <option value="">Unassigned</option>{(analysts.data ?? []).map((a) => <option key={a}>{a}</option>)}
            </select>
          </label>
        </div>
        <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (optional, recorded with the change)" aria-label="Reason"
          className="w-full rounded-xl border-0 bg-white shadow-sm ring-1 ring-ink-600 px-2.5 py-1.5 text-sm placeholder:text-faint" />
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant={inc.suspected_false_positive ? 'secondary' : 'danger'} disabled={busy}
            onClick={() => patch({ suspected_false_positive: !inc.suspected_false_positive, actor, reason }, inc.suspected_false_positive ? 'False-positive flag removed' : 'Marked as suspected false positive')}>
            {inc.suspected_false_positive ? 'Unmark false positive' : 'Mark suspected false positive'}
          </Button>
          {closed ? <Button size="sm" disabled={busy} onClick={() => patch({ status: 'in_progress', actor, reason: reason || 'reopened' }, 'Incident reopened')}><RotateCcw size={13} aria-hidden />Reopen</Button>
            : <Button size="sm" disabled={busy} onClick={() => patch({ status: 'resolved', actor, reason }, 'Incident resolved')}><CheckCircle2 size={13} aria-hidden />Resolve</Button>}
          <Button size="sm" disabled={busy || inc.status === 'escalated'} onClick={() => patch({ status: 'escalated', actor, reason }, 'Incident escalated')}>Escalate</Button>
        </div>
        <form className="space-y-2 border-t border-ink-700 pt-3" onSubmit={async (e) => {
          e.preventDefault()
          if (!note.trim()) return
          setBusy(true)
          try { await api.addNote(inc.id, actor, note); setNote(''); notify('success', 'Note added'); onChanged(await api.incident(inc.id)) }
          catch (err) { notify('error', (err as Error).message) } finally { setBusy(false) }
        }}>
          <label className="text-xs text-muted" htmlFor="note">Add note</label>
          <textarea id="note" value={note} onChange={(e) => setNote(e.target.value)} rows={3} maxLength={5000}
            className="w-full rounded-xl border-0 bg-white shadow-sm ring-1 ring-ink-600 px-2.5 py-1.5 text-sm" placeholder="What did you check? What did you find?" />
          <Button size="sm" type="submit" variant="primary" disabled={busy || !note.trim()}>Save note</Button>
        </form>
        <ul className="space-y-2">
          {[...inc.notes].reverse().map((n) => (
            <li key={n.id} className="rounded-xl border border-ink-700 bg-white p-2 text-xs">
              <div className="flex justify-between text-faint"><span className="font-medium text-muted">{n.author}</span><span>{fmtTime(n.created_at)}</span></div>
              <p className="mt-1 whitespace-pre-wrap text-fg">{n.text}</p>
            </li>
          ))}
        </ul>
        {inc.status_changes.length > 0 && (
          <details className="text-xs text-muted">
            <summary className="cursor-pointer">History ({inc.status_changes.length})</summary>
            <ul className="mt-2 space-y-1">
              {[...inc.status_changes].reverse().map((c, i) => (
                <li key={i}><span className="text-faint">{fmtTime(c.created_at)}</span> · {c.actor}: {c.from_status !== c.to_status ? `${STATUS_LABELS[c.from_status ?? ''] ?? c.from_status} → ${STATUS_LABELS[c.to_status]}` : ''} {c.reason}</li>
              ))}
            </ul>
          </details>
        )}
      </div>
    </Card>
  )
}

function HeroCell({ label, children }: { label: string; children: React.ReactNode }) {
  return <div className="rounded-2xl bg-white/[0.06] p-3 ring-1 ring-white/10"><div className="text-[11px] text-ink-500">{label}</div><div className="num font-display text-xl font-bold">{children}</div></div>
}

export default function IncidentDetailPage() {
  const { id = '' } = useParams()
  const { version } = useApp()
  const { data: inc, error, loading, reload, setData } = useAsync(() => api.incident(id), [id, version])
  const [eventId, setEventId] = useState<string | null>(null)
  const [stage, setStage] = useState('')
  if (loading && !inc) return <Spinner />
  if (error) return <div className="space-y-4"><Link to="/incidents" className="text-sm text-sky-700">← Incidents</Link><ErrorState error={error} onRetry={reload} /></div>
  if (!inc) return null
  const onStage = (s: string) => { setStage(s); document.getElementById('timeline')?.scrollIntoView({ behavior: 'smooth' }) }
  return (
    <div className="space-y-4">
      <Link to="/incidents" className="inline-flex items-center gap-1.5 rounded-xl px-2 py-1 text-sm font-medium text-muted transition hover:bg-white hover:text-fg"><ArrowLeft size={14} aria-hidden />All incidents</Link>
      <header className="hero-surface grid-pattern relative overflow-hidden rounded-3xl p-6 text-white shadow-[var(--shadow-lift)] animate-fade-up">
        <div className="pointer-events-none absolute -right-16 -top-20 h-64 w-64 rounded-full blur-3xl" style={{ background: SEV_COLOR[inc.severity] + '40' }} />
        <div className="relative flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={inc.severity} /><StatusBadge status={inc.status} /><span className="mono rounded-md bg-white/10 px-1.5 py-0.5 text-xs text-sky-200">{inc.id}</span>
              {inc.suspected_false_positive && <Chip className="text-amber-700">Suspected false positive</Chip>}</div>
            <h1 className="mt-3 font-display text-2xl font-bold leading-tight tracking-tight sm:text-[28px]">{inc.title}</h1>
            <p className="mt-2 max-w-4xl text-sm text-ink-600">{inc.description}</p>
          </div>
          <div className="flex flex-wrap gap-2">
            {([['html', 'HTML report', FileDown], ['json', 'JSON', FileJson], ['csv', 'CSV', FileSpreadsheet]] as const).map(([f, l, Icon]) => (
              <a key={f} className="inline-flex items-center gap-1.5 rounded-xl bg-white/10 px-3.5 py-2 text-sm font-medium text-white ring-1 ring-white/20 transition hover:bg-white/20" href={api.reportUrl(inc.id, f)}><Icon size={14} aria-hidden />{l}</a>
            ))}
          </div>
        </div>
        <div className="relative mt-6 grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
          <HeroCell label="Risk"><span style={{ color: SEV_COLOR[inc.severity] }} className="brightness-125">{inc.risk_score.toFixed(1)}</span></HeroCell>
          <HeroCell label="Confidence"><span className="text-sky-300">{fmtScore(inc.confidence)}</span></HeroCell>
          <HeroCell label="Events">{inc.event_count.toLocaleString()}</HeroCell>
          <div className="col-span-2 rounded-2xl bg-white/[0.06] p-3 ring-1 ring-white/10"><div className="text-[11px] text-ink-500">Time range ({tzLabel()})</div><div className="num text-sm font-medium">{fmtTime(inc.first_seen)} → {fmtTime(inc.last_seen, { date: multiDay(inc) })}</div><div className="text-xs text-ink-500">{fmtSpan(inc.first_seen, inc.last_seen)}</div></div>
          <div className="rounded-2xl bg-white/[0.06] p-3 ring-1 ring-white/10"><div className="text-[11px] text-ink-500">Sensors</div><div className="mt-1.5 flex gap-1">{inc.sensors.map((s) => <SensorBadge key={s} sensor={s} />)}</div></div>
          <HeroCell label="Assignee"><span className="text-base">{inc.assignee ?? '—'}</span></HeroCell>
        </div>
        <div className="relative mt-4">
          <div className="text-[11px] text-ink-500">Affected entities</div>
          <div className="mono mt-1.5 flex flex-wrap gap-1 text-[11px]">
            {inc.entities.internal_hosts.slice(0, 12).map((h) => <span key={h} title="internal host" className="rounded-md bg-white/10 px-1.5 py-0.5 text-sky-100">{h}</span>)}
            {inc.entities.external_ips.slice(0, 8).map((h) => <span key={h} title="external IP" className="rounded-md bg-rose-500/20 px-1.5 py-0.5 text-rose-200">{h}</span>)}
            {inc.entities.hostnames.slice(0, 6).map((h) => <span key={h} title="hostname / SNI" className="rounded-md bg-white/10 px-1.5 py-0.5 text-sky-100">{h}</span>)}
            {inc.entities.internal_hosts.length > 12 && <span className="rounded-md bg-white/10 px-1.5 py-0.5 text-ink-500">+{inc.entities.internal_hosts.length - 12} hosts</span>}
          </div>
        </div>
      </header>
      {inc.ground_truth && (
        <div className="flex flex-wrap items-center gap-3 rounded-2xl border border-ink-700 bg-white px-4 py-3 text-sm shadow-[var(--shadow-card)]">
          <span className="text-xs font-semibold uppercase tracking-wider text-faint">Dataset labels of member events</span>
          <span className="num text-rose-700"><b>{inc.ground_truth.malicious.toLocaleString()}</b> attack</span>
          <span className="num text-muted"><b>{inc.ground_truth.benign.toLocaleString()}</b> benign</span>
          <div className="flex flex-wrap gap-1">{inc.ground_truth.tactics.map((t) => <TacticPill key={t.tactic} tactic={t.tactic} count={t.count} />)}</div>
          <span className="ml-auto text-[11px] text-faint">Ground truth for review only — never used by detection or scoring.</span>
        </div>
      )}

      <AttackChain inc={inc} onOpen={setEventId} onStage={onStage} />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]">
        <div className="min-w-0 space-y-4">
          <Narrative inc={inc} onOpen={setEventId} onUpdated={reload} />
          <div id="timeline"><Timeline inc={inc} stage={stage} setStage={setStage} onOpen={setEventId} /></div>
          <Attack inc={inc} onOpen={setEventId} />
          <Linkage inc={inc} onOpen={setEventId} />
        </div>
        <div className="space-y-4">
          <Workflow inc={inc} onChanged={setData} />
          <Scores inc={inc} />
          <Card title="Alternative explanations" subtitle="Benign possibilities the analyst should rule out">
            <ul className="list-disc space-y-1.5 pl-5 text-sm text-muted">{inc.alternative_explanations.map((a) => <li key={a}>{a}</li>)}</ul>
          </Card>
        </div>
      </div>
      <EventDrawer eventId={eventId} onClose={() => setEventId(null)} />
    </div>
  )
}
