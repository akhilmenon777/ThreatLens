import {
  Activity, AlertOctagon, ArrowRight, CalendarRange, Crosshair, Inbox, Layers, PieChart as PieIcon, Radar, RefreshCw,
  ShieldAlert, ShieldCheck, Target,
} from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { api } from '../api/client'
import type { Analytics, Overview } from '../api/types'
import { DataGate } from '../components/NoDataset'
import {
  Button, Card, CHART, cx, HelpTip, sensorColor, SENSORS, SEV_COLOR, SeverityBadge, Skeleton, Stat, StatusBadge, tacticColor, TacticPill,
  tooltipStyle,
} from '../components/ui'
import { useApp } from '../lib/app-context'
import {
  fmtBucket, fmtCompact, fmtDay, fmtDuration, fmtInt, fmtPct, fmtScore, fmtTime, STAGE_LABELS, STATUS_LABELS, tzLabel,
} from '../lib/format'
import { useAsync } from '../lib/hooks'

function OverviewSkeleton() {
  return (
    <div className="space-y-5">
      <Skeleton className="h-48" />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">{Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-24" />)}</div>
      <div className="grid gap-4 xl:grid-cols-3"><Skeleton className="h-80 xl:col-span-2" /><Skeleton className="h-80" /></div>
    </div>
  )
}

function Hero({ ov, an, running, onRun }: { ov: Overview; an: Analytics | null; running: boolean; onRun: () => void }) {
  const t = ov.totals
  const gt = an?.ground_truth
  return (
    <section className="hero-surface grid-pattern relative overflow-hidden rounded-3xl p-6 text-white shadow-[var(--shadow-lift)] animate-fade-up sm:p-8">
      <div className="pointer-events-none absolute -right-20 -top-24 h-72 w-72 rounded-full bg-sky-400/20 blur-3xl" />
      <div className="relative grid gap-8 xl:grid-cols-[1.35fr_1fr]">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-sky-300">
            <span className="rounded-full bg-white/10 px-2.5 py-1 ring-1 ring-white/15">{ov.dataset.synthetic ? 'Synthetic dataset' : an?.ground_truth.available ? 'Labelled dataset' : 'Uploaded dataset'}</span>
            {an?.totals.first_seen && <span className="inline-flex items-center gap-1.5 text-ink-600"><CalendarRange size={13} aria-hidden />{fmtDay(an.totals.first_seen)} → {fmtDay(an.totals.last_seen ?? '')}</span>}
          </div>
          <h2 className="mt-3 font-display text-3xl font-extrabold leading-tight tracking-tight sm:text-4xl">{ov.dataset.name}</h2>
          {an?.dataset.description && <p className="mt-2 line-clamp-2 max-w-2xl text-sm text-ink-600">{an.dataset.description}</p>}
          {an && an.sources.length > 1 && (
            <div className="mt-4 flex flex-wrap gap-2" aria-label="Telemetry sources">
              {an.sources.map((s) => (
                <span key={s.sensor} title={SENSORS[s.sensor]?.layer} className="inline-flex items-center gap-2 rounded-full bg-white/[0.07] px-3 py-1 text-xs ring-1 ring-white/15">
                  <span className="h-2 w-2 rounded-full" style={{ background: sensorColor(s.sensor) }} aria-hidden />
                  <span className="font-semibold text-white">{SENSORS[s.sensor]?.name ?? s.sensor}</span>
                  <span className="num text-ink-500">{fmtCompact(s.events)}</span>
                </span>
              ))}
            </div>
          )}
          <div className="mt-6 flex flex-wrap items-end gap-x-4 gap-y-2">
            <div><div className="num font-display text-4xl font-extrabold">{fmtCompact(t.raw_events)}</div><div className="text-xs text-ink-500">raw events</div></div>
            <ArrowRight className="mb-5 text-sky-300" aria-hidden />
            <div><div className="num font-display text-4xl font-extrabold text-sky-300">{fmtInt(t.signal_events)}</div><div className="text-xs text-ink-500">signal events</div></div>
            <ArrowRight className="mb-5 text-sky-300" aria-hidden />
            <div><div className="num font-display text-4xl font-extrabold text-sky-200">{fmtInt(t.incidents)}</div><div className="text-xs text-ink-500">incidents</div></div>
          </div>
          <div className="mt-6 flex flex-wrap gap-2">
            <Button variant="primary" disabled={running} onClick={onRun}><RefreshCw size={14} className={running ? 'animate-spin' : ''} aria-hidden />{running ? 'Correlating…' : 'Re-run correlation'}</Button>
            <Link to="/incidents" className="inline-flex items-center gap-1.5 rounded-xl bg-white/10 px-4 py-2 text-sm font-medium text-white ring-1 ring-white/20 transition hover:bg-white/15"><ShieldAlert size={14} aria-hidden />Investigate incidents</Link>
            <Link to="/dataset" className="inline-flex items-center gap-1.5 rounded-xl px-3 py-2 text-sm font-medium text-sky-200 transition hover:text-white"><PieIcon size={14} aria-hidden />Dataset insights</Link>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3 self-center">
          <HeroMetric label="Triage reduction" value={fmtPct(t.triage_reduction_pct, 1)} help={ov.definitions.triage_reduction_pct} />
          <HeroMetric label="Event → incident" value={fmtPct(t.reduction_pct, 2)} help={ov.definitions.reduction_pct} />
          {gt?.available && gt.detection ? <>
            <HeroMetric label="Detection precision" value={fmtPct((gt.detection.precision ?? 0) * 100, 1)} help="Share of events placed in incidents that the dataset labels as attack traffic." accent />
            <HeroMetric label="Detection recall" value={fmtPct((gt.detection.recall ?? 0) * 100, 1)} help="Share of labelled attack events that ended up inside an incident." accent />
          </> : <>
            <HeroMetric label="Analyst items" value={fmtInt(t.triage_items)} help="Incidents + alert-bearing events left outside any incident." />
            <HeroMetric label="Open incidents" value={fmtInt(t.open_incidents)} help="Incidents not resolved or closed." />
          </>}
          <div className="col-span-2 text-[11px] text-ink-500">
            Latest ingestion {fmtTime(ov.latest_ingestion)} {tzLabel()}
            {ov.correlation_run && <> · correlation run #{ov.correlation_run.id} in {fmtDuration(ov.correlation_run.duration_ms)}</>}
          </div>
        </div>
      </div>
    </section>
  )
}

function HeroMetric({ label, value, help, accent }: { label: string; value: string; help?: string; accent?: boolean }) {
  return (
    <div className={cx('rounded-2xl p-4 ring-1 backdrop-blur', accent ? 'bg-sky-400/10 ring-sky-300/30' : 'bg-white/[0.06] ring-white/10')}>
      <div className="flex items-center gap-1 text-[11px] font-medium text-ink-500">{label}{help && <span className="[&_svg]:text-ink-500"><HelpTip text={help} /></span>}</div>
      <div className={cx('num mt-1 font-display text-2xl font-bold', accent ? 'text-sky-300' : 'text-white')}>{value}</div>
    </div>
  )
}

export default function OverviewPage() {
  const { version, refresh, notify } = useApp()
  const { data, error, loading, reload } = useAsync(() => api.overview(), [version])
  const an = useAsync(() => api.analytics().catch(() => null), [version])
  const [running, setRunning] = useState(false)

  if (loading && !data) return <OverviewSkeleton />
  if (error) return <DataGate error={error} onRetry={reload} />
  if (!data) return null
  const t = data.totals
  const a = an.data
  const gt = a?.ground_truth
  const maxHeat = Math.max(1, ...data.heatmap.cells.map((c) => c.count))
  const sevData = data.severity_distribution.filter((s) => s.count > 0)
  const run = async () => {
    setRunning(true)
    try { const r = await api.runCorrelation(); notify('success', `Correlation finished: ${r.n_incidents.toLocaleString()} incidents in ${fmtDuration(r.duration_ms)}`); refresh() }
    catch (e) { notify('error', (e as Error).message) } finally { setRunning(false) }
  }

  return (
    <div className="space-y-5">
      <Hero ov={data} an={a} running={running} onRun={run} />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Raw events" value={fmtCompact(t.raw_events)} hint="normalised records" icon={<Layers size={18} />} accent="blue" />
        <Stat label="Incidents" value={fmtInt(t.incidents)} hint="correlated meta-alerts" icon={<ShieldAlert size={18} />} />
        <Stat label="Critical + High" value={fmtInt(t.critical_high)} hint="risk ≥ high threshold" tone={t.critical_high ? 'text-rose-700' : undefined} icon={<AlertOctagon size={18} />} accent="rose" />
        <Stat label="Open incidents" value={fmtInt(t.open_incidents)} hint="not resolved / closed" icon={<Inbox size={18} />} accent="violet" />
        {gt?.available ? (
          <Stat label="Labelled attacks" value={fmtCompact(gt.malicious ?? 0)} hint={`${fmtCompact(gt.benign ?? 0)} benign events`} icon={<Crosshair size={18} />} accent="amber" />
        ) : (
          <Stat label="Unassigned" value={fmtCompact(t.unassigned_events)} hint={<span className="inline-flex items-center gap-1">{fmtInt(t.unassigned_signal_events)} with alerts <HelpTip text={data.definitions.unassigned_events} /></span>} icon={<Radar size={18} />} accent="amber" />
        )}
        <Stat label="Signal events" value={fmtCompact(t.signal_events)} hint="alert / detector tagged" icon={<Activity size={18} />} accent="teal" />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2" icon={<Activity size={15} />} title="Activity over time"
          subtitle={gt?.available ? `Events per ${a?.granularity} — labelled attack vs benign traffic, and events the detectors flagged (${tzLabel()}).` : `Events per ${a?.granularity ?? 'hour'} and the share flagged by detectors (${tzLabel()}).`}>
          <div className="h-72">
            {a ? (
              <ResponsiveContainer>
                <AreaChart data={a.timeline} margin={{ left: -6, right: 8, top: 6 }}>
                  <defs>
                    <linearGradient id="gMal" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor={CHART.malicious} stopOpacity={0.55} /><stop offset="1" stopColor={CHART.malicious} stopOpacity={0.05} /></linearGradient>
                    <linearGradient id="gBen" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor={CHART.gold} stopOpacity={0.45} /><stop offset="1" stopColor={CHART.gold} stopOpacity={0.05} /></linearGradient>
                    <linearGradient id="gSig" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor={CHART.espresso} stopOpacity={0.5} /><stop offset="1" stopColor={CHART.espresso} stopOpacity={0.02} /></linearGradient>
                  </defs>
                  <CartesianGrid vertical={false} strokeDasharray="3 4" />
                  <XAxis dataKey="t" tickFormatter={(v) => fmtBucket(String(v), a.granularity)} minTickGap={28} tickLine={false} axisLine={false} />
                  <YAxis tickFormatter={(v) => fmtCompact(Number(v))} tickLine={false} axisLine={false} width={44} />
                  <Tooltip contentStyle={tooltipStyle} labelFormatter={(v) => fmtBucket(String(v), a.granularity)} formatter={(v) => Number(v).toLocaleString()} />
                  <Legend wrapperStyle={{ fontSize: 12 }} iconType="circle" />
                  {gt?.available ? <>
                    <Area type="monotone" dataKey="benign" name="Benign (label)" stackId="l" stroke={CHART.gold} fill="url(#gBen)" strokeWidth={1.5} />
                    <Area type="monotone" dataKey="malicious" name="Attack (label)" stackId="l" stroke={CHART.malicious} fill="url(#gMal)" strokeWidth={1.5} />
                  </> : <Area type="monotone" dataKey="events" name="Events" stroke={CHART.gold} fill="url(#gBen)" strokeWidth={1.5} />}
                  <Area type="monotone" dataKey="signal" name="Flagged by detectors" stroke={CHART.espresso} fill="url(#gSig)" strokeWidth={1.5} strokeDasharray="4 3" />
                </AreaChart>
              </ResponsiveContainer>
            ) : <Skeleton className="h-full" />}
          </div>
        </Card>
        <Card icon={<ShieldCheck size={15} />} title="Severity mix" subtitle="Risk-based severity of correlated incidents">
          {sevData.length === 0 ? <p className="text-sm text-muted">No incidents yet.</p> : (
            <div className="flex h-72 flex-col">
              <div className="relative flex-1">
                <ResponsiveContainer>
                  <PieChart>
                    <Pie data={sevData} dataKey="count" nameKey="severity" innerRadius="62%" outerRadius="90%" paddingAngle={2} stroke="none">
                      {sevData.map((s) => <Cell key={s.severity} fill={SEV_COLOR[s.severity]} />)}
                    </Pie>
                    <Tooltip contentStyle={tooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
                  <div><div className="num font-display text-3xl font-bold">{fmtInt(t.incidents)}</div><div className="text-[11px] uppercase tracking-wider text-faint">incidents</div></div>
                </div>
              </div>
              <div className="mt-2 grid grid-cols-2 gap-1.5">
                {data.severity_distribution.map((s) => (
                  <Link key={s.severity} to={`/incidents?severity=${s.severity}`} className="flex items-center justify-between rounded-lg px-2 py-1 text-xs hover:bg-ink-800">
                    <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ background: SEV_COLOR[s.severity] }} />{s.severity}</span>
                    <span className="num font-semibold">{s.count}</span>
                  </Link>
                ))}
              </div>
            </div>
          )}
        </Card>
      </div>

      {gt?.available && gt.tactics && gt.tactics.length > 0 && (
        <Card icon={<Target size={15} />} title="Labelled ATT&CK tactics vs. what the platform detected"
          subtitle="Ground truth from the dataset labels (never used by the engine). Coverage = labelled events that ended up inside an incident."
          actions={<Link to="/dataset" className="text-xs font-semibold text-sky-700 hover:underline">Full breakdown →</Link>}>
          <div className="grid gap-5 lg:grid-cols-[1.4fr_1fr]">
            <div className="h-72">
              <ResponsiveContainer>
                <BarChart data={gt.tactics} layout="vertical" margin={{ left: 24, right: 12 }}>
                  <CartesianGrid horizontal={false} strokeDasharray="3 4" />
                  <XAxis type="number" scale="sqrt" tickFormatter={(v) => fmtCompact(Number(v))} tickLine={false} axisLine={false} />
                  <YAxis type="category" dataKey="tactic" width={130} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(201,162,39,0.08)' }} formatter={(v) => Number(v).toLocaleString()} />
                  <Legend wrapperStyle={{ fontSize: 12 }} iconType="circle" />
                  <Bar dataKey="events" name="Labelled events" fill={CHART.sand} radius={[0, 6, 6, 0]} barSize={10} />
                  <Bar dataKey="in_incident" name="Detected (in an incident)" fill={CHART.gold} radius={[0, 6, 6, 0]} barSize={10} />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <ul className="space-y-2.5 self-center">
              {gt.tactics.map((r) => (
                <li key={r.tactic} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center justify-between gap-2 text-xs"><TacticPill tactic={r.tactic} /><span className="num text-muted">{fmtInt(r.in_incident)} / {fmtInt(r.events)}</span></div>
                    <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-ink-800"><div className="h-full rounded-full" style={{ width: `${r.coverage_pct ?? 0}%`, background: tacticColor(r.tactic) }} /></div>
                  </div>
                  <span className={cx('num w-14 text-right text-sm font-bold', (r.coverage_pct ?? 0) >= 50 ? 'text-emerald-700' : (r.coverage_pct ?? 0) > 0 ? 'text-amber-700' : 'text-faint')}>{fmtPct(r.coverage_pct, 0)}</span>
                </li>
              ))}
            </ul>
          </div>
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Attack-stage distribution" subtitle="How far did activity progress? Incidents per stage, observed vs inferred.">
          <div className="h-64">
            <ResponsiveContainer>
              <BarChart data={data.stage_distribution.map((s) => ({ ...s, label: STAGE_LABELS[s.stage] ?? s.stage }))} layout="vertical" margin={{ left: 24 }}>
                <CartesianGrid horizontal={false} strokeDasharray="3 4" />
                <XAxis type="number" allowDecimals={false} tickLine={false} axisLine={false} />
                <YAxis type="category" dataKey="label" width={120} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(201,162,39,0.08)' }} />
                <Legend wrapperStyle={{ fontSize: 12 }} iconType="circle" />
                <Bar dataKey="OBSERVED" name="Observed" stackId="a" fill={CHART.gold} barSize={12} />
                <Bar dataKey="INFERRED" name="Inferred (hypothesis)" stackId="a" fill={CHART.espresso} fillOpacity={0.3} stroke={CHART.espresso} strokeDasharray="4 2" radius={[0, 6, 6, 0]} barSize={12} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Analyst workload" subtitle="Incident status distribution">
          <ul className="space-y-3">
            {data.status_distribution.map((s) => (
              <li key={s.status}>
                <Link to={`/incidents?status=${s.status}`} className="flex items-center gap-3 rounded-lg p-1 hover:bg-ink-800/60">
                  <div className="w-24"><StatusBadge status={s.status} /></div>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-ink-800">
                    <div className="gold-gradient h-full rounded-full" style={{ width: `${t.incidents ? (s.count / t.incidents) * 100 : 0}%` }} />
                  </div>
                  <span className="num w-12 text-right text-sm font-semibold">{fmtInt(s.count)}</span>
                </Link>
              </li>
            ))}
          </ul>
          <p className="mt-4 text-xs text-faint">{STATUS_LABELS.new} incidents have not been touched by an analyst yet.</p>
        </Card>
        <Card title="Detector signals" subtitle="Which behaviours fired, and on how many events?">
          {a && a.detector_tags.length > 0 ? (
            <ul className="space-y-2.5">
              {a.detector_tags.slice(0, 8).map((d) => (
                <li key={d.tag}>
                  <div className="flex justify-between text-xs"><span className="mono text-fg">{d.tag}</span><span className="num text-muted">{fmtInt(d.count)}</span></div>
                  <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-ink-800"><div className="h-full rounded-full bg-espresso-700" style={{ width: `${(d.count / Math.max(1, a.detector_tags[0].count)) * 100}%` }} /></div>
                </li>
              ))}
            </ul>
          ) : (
            <ul className="space-y-3">
              {data.sensor_distribution.map((s) => (
                <li key={s.sensor}>
                  <div className="flex justify-between text-sm"><span className="capitalize">{s.sensor}</span><span className="num text-muted">{fmtInt(s.count)}</span></div>
                  <div className="mt-1 h-2 overflow-hidden rounded-full bg-ink-800">
                    <div className="h-full rounded-full" style={{ width: `${(s.count / Math.max(1, t.raw_events)) * 100}%`, background: sensorColor(s.sensor) }} />
                  </div>
                </li>
              ))}
            </ul>
          )}
          <p className="mt-4 text-xs text-faint">Tags are investigation hints, not verdicts. Untagged traffic stays as context.</p>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.3fr_1fr]">
        <Card title="Tactic × host matrix" subtitle="Which internal hosts are involved in which ATT&CK tactics? (count of incident mappings)">
          {data.heatmap.hosts.length === 0 ? <p className="text-sm text-muted">No ATT&CK mappings yet.</p> : (
            <div className="overflow-x-auto">
              <table className="w-full border-separate border-spacing-1 text-xs">
                <thead>
                  <tr><th className="text-left font-medium text-muted">Host</th>{data.heatmap.tactics.map((ta) => <th key={ta} className="px-1 text-center text-[11px] font-medium text-muted">{ta}</th>)}</tr>
                </thead>
                <tbody>
                  {data.heatmap.hosts.map((h) => (
                    <tr key={h}>
                      <td className="mono whitespace-nowrap pr-2 text-muted">{h}</td>
                      {data.heatmap.tactics.map((ta) => {
                        const c = data.heatmap.cells.find((x) => x.host === h && x.tactic === ta)?.count ?? 0
                        const k = c / maxHeat
                        return <td key={ta} title={`${h} · ${ta}: ${c}`} className={cx('num h-8 rounded-lg text-center font-medium', k > 0.55 ? 'text-white' : 'text-fg')}
                          style={{ background: c ? `rgba(143,106,16,${0.12 + 0.8 * k})` : 'rgba(236,228,205,0.45)' }}>{c || ''}</td>
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card title="Highest-risk incidents" subtitle="Start here" actions={<Link to="/incidents" className="text-xs font-semibold text-sky-700 hover:underline">All incidents →</Link>}>
          <ul className="-mx-2 space-y-1">
            {data.top_incidents.map((i) => (
              <li key={i.id}>
                <Link to={`/incidents/${i.id}`} className="group flex items-center gap-3 rounded-xl px-2 py-2.5 transition hover:bg-ink-800/70">
                  <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl font-display text-sm font-bold text-white" style={{ background: SEV_COLOR[i.severity] }}>{i.risk_score.toFixed(0)}</div>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-medium group-hover:text-sky-800">{i.title}</div>
                    <div className="mono text-[11px] text-faint">{i.id} · {i.event_count.toLocaleString()} events · conf {fmtScore(i.confidence)}</div>
                  </div>
                  <SeverityBadge severity={i.severity} />
                </Link>
              </li>
            ))}
            {data.top_incidents.length === 0 && <li className="px-2 text-sm text-muted">No incidents yet.</li>}
          </ul>
        </Card>
      </div>
    </div>
  )
}
