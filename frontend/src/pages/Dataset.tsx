import { ArrowDownToLine, ArrowUpFromLine, CalendarRange, Crosshair, Globe2, Layers, Network, Server, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { api } from '../api/client'
import { DataGate } from '../components/NoDataset'
import {
  BarList, Card, CHART, cx, HelpTip, PageHeader, Segmented, SensorBadge, sensorColor, SENSORS, Skeleton, Stat, tacticColor,
  TacticPill, tooltipStyle,
} from '../components/ui'
import { useApp } from '../lib/app-context'
import { fmtBucket, fmtBytes, fmtCompact, fmtDay, fmtInt, fmtPct, tzLabel } from '../lib/format'
import { useAsync } from '../lib/hooks'

const PIE_COLORS = ['#c9a227', '#3d3426', '#8f6a10', '#0d9488', '#ebcb5b', '#7c3aed', '#c2b48a', '#ea580c', '#574a32', '#e11d48', '#64748b', '#ddd2b4']

function Donut({ data, total, label }: { data: { key: string | number; count: number }[]; total: number; label: string }) {
  if (!data.length) return <p className="text-sm text-muted">No data</p>
  return (
    <div className="grid items-center gap-4 sm:grid-cols-[10rem_1fr]">
      <div className="relative h-40">
        <ResponsiveContainer>
          <PieChart>
            <Pie data={data} dataKey="count" nameKey="key" innerRadius="60%" outerRadius="95%" paddingAngle={1.5} stroke="none">
              {data.map((d, i) => <Cell key={String(d.key)} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
            </Pie>
            <Tooltip contentStyle={tooltipStyle} formatter={(v) => Number(v).toLocaleString()} />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
          <div><div className="num font-display text-lg font-bold">{fmtCompact(total)}</div><div className="text-[10px] uppercase tracking-wider text-faint">{label}</div></div>
        </div>
      </div>
      <ul className="space-y-1.5 text-xs">
        {data.map((d, i) => (
          <li key={String(d.key)} className="flex items-center justify-between gap-2">
            <span className="flex min-w-0 items-center gap-2"><span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: PIE_COLORS[i % PIE_COLORS.length] }} /><span className="mono truncate">{String(d.key)}</span></span>
            <span className="num text-muted">{fmtInt(d.count)} <span className="text-faint">({fmtPct((d.count / Math.max(1, total)) * 100, 1)})</span></span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export default function DatasetPage() {
  const { version } = useApp()
  const { data, error, loading, reload } = useAsync(() => api.analytics(), [version])
  const [talkers, setTalkers] = useState<'count' | 'bytes'>('count')

  if (loading && !data) return (
    <div className="space-y-4"><Skeleton className="h-16" /><div className="grid grid-cols-2 gap-3 xl:grid-cols-6">{Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-24" />)}</div><Skeleton className="h-80" /></div>
  )
  if (error) return <><PageHeader title="Dataset insights" /><DataGate error={error} onRetry={reload} /></>
  if (!data) return null
  const t = data.totals
  const gt = data.ground_truth
  const tactics = gt.tactics ?? []
  const tacticNames = tactics.map((x) => x.tactic)
  const sources = data.sources ?? []
  const onlyConn = sources.length > 0 && sources.every((x) => x.sensor === 'zeek')
  const unit = onlyConn ? 'connections' : 'events'

  return (
    <div className="space-y-5">
      <PageHeader eyebrow="Dataset insights" title={data.dataset.name}
        subtitle={data.dataset.description || 'Traffic profile of the active dataset.'}
        actions={<Link to="/events" className="rounded-xl bg-white px-4 py-2 text-sm font-medium shadow-sm ring-1 ring-ink-600 hover:bg-sky-50">Browse raw events</Link>} />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label={onlyConn ? 'Connections' : 'Events'} value={fmtCompact(t.events)} hint={`${fmtInt(t.events)} normalised records`} icon={<Network size={18} />} accent="blue" />
        <Stat label="Time span" value={t.span_hours > 72 ? `${Math.round(t.span_hours / 24)} d` : `${t.span_hours} h`} hint={t.first_seen ? `${fmtDay(t.first_seen)} → ${fmtDay(t.last_seen ?? '')}` : '—'} icon={<CalendarRange size={18} />} />
        <Stat label="Sources" value={fmtInt(t.unique_sources)} hint="unique originator IPs" icon={<Server size={18} />} accent="violet" />
        <Stat label="Destinations" value={fmtInt(t.unique_destinations)} hint="unique responder IPs" icon={<Globe2 size={18} />} accent="teal" />
        <Stat label="Bytes out" value={fmtBytes(t.bytes_out)} hint="originator payload" icon={<ArrowUpFromLine size={18} />} accent="amber" />
        <Stat label="Bytes in" value={fmtBytes(t.bytes_in)} hint="responder payload" icon={<ArrowDownToLine size={18} />} accent="rose" />
      </div>

      {sources.length > 1 && (
        <Card icon={<Layers size={15} />} title="Data sources" subtitle="Each telemetry layer in this dataset, what the detectors made of it, and – where labels exist – how much of its labelled attack activity ended up in an incident.">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {sources.map((s) => {
              const meta = SENSORS[s.sensor]
              return (
                <div key={s.sensor} className="relative overflow-hidden rounded-2xl border border-ink-700 bg-white p-4">
                  <span className="absolute inset-y-0 left-0 w-1" style={{ background: sensorColor(s.sensor) }} aria-hidden />
                  <div className="flex items-center justify-between gap-2">
                    <div>
                      <div className="font-display text-sm font-bold">{meta?.name ?? s.sensor}</div>
                      <div className="text-[11px] text-faint">{meta?.layer ?? 'Telemetry'}</div>
                    </div>
                    <SensorBadge sensor={s.sensor} />
                  </div>
                  <div className="num mt-3 font-display text-2xl font-bold">{fmtCompact(s.events)}</div>
                  <div className="text-[11px] text-muted">{s.first_seen ? `${fmtDay(s.first_seen)} → ${fmtDay(s.last_seen ?? '')}` : '—'}</div>
                  <dl className="num mt-3 grid grid-cols-3 gap-1 text-center text-[11px]">
                    <div className="rounded-lg bg-ink-800/70 py-1.5"><dt className="text-faint">flagged</dt><dd className="font-semibold">{fmtCompact(s.signal)}</dd></div>
                    <div className="rounded-lg bg-ink-800/70 py-1.5"><dt className="text-faint">in incident</dt><dd className="font-semibold">{fmtCompact(s.in_incident)}</dd></div>
                    <div className="rounded-lg bg-sky-50 py-1.5 ring-1 ring-sky-100"><dt className="text-faint">recall</dt><dd className="font-semibold text-sky-800">{s.recall === null ? '—' : fmtPct(s.recall * 100, 0)}</dd></div>
                  </dl>
                  {s.malicious > 0 && <div className="mt-2 text-[11px] text-muted">{fmtInt(s.detected)} of {fmtInt(s.malicious)} labelled attack events detected</div>}
                </div>
              )
            })}
          </div>
          {data.top_alerts.length > 0 && (
            <div className="mt-5">
              <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-faint">Most frequent alerts</div>
              <ul className="grid gap-x-6 gap-y-1.5 text-xs md:grid-cols-2">
                {data.top_alerts.map((x) => (
                  <li key={x.sensor + x.key} className="flex min-w-0 items-center gap-2">
                    <SensorBadge sensor={x.sensor} />
                    <span className="min-w-0 flex-1 truncate" title={x.key}>{x.key}</span>
                    <span className="num text-muted">{fmtInt(x.count)}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Card>
      )}

      {gt.available && (
        <div className="grid gap-4 xl:grid-cols-[1fr_1.6fr]">
          <Card icon={<Crosshair size={15} />} title="Ground truth" subtitle={gt.note ?? 'Labels published with the dataset (evaluation only).'}>
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-2xl bg-rose-50 p-4 ring-1 ring-rose-100">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-rose-700/80">Attack {unit}</div>
                <div className="num font-display text-2xl font-bold text-rose-700">{fmtInt(gt.malicious)}</div>
                <div className="text-xs text-rose-700/70">{fmtPct(((gt.malicious ?? 0) / Math.max(1, gt.labelled_events ?? 1)) * 100, 1)} of labelled</div>
              </div>
              <div className="rounded-2xl bg-ink-800 p-4 ring-1 ring-ink-700">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-faint">Benign {unit}</div>
                <div className="num font-display text-2xl font-bold">{fmtInt(gt.benign)}</div>
                <div className="text-xs text-muted">baseline traffic</div>
              </div>
            </div>
            {gt.detection && (
              <div className="mt-4 rounded-2xl border border-ink-700 p-4">
                <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-faint"><ShieldCheck size={13} aria-hidden />Platform detection vs labels
                  <HelpTip text="Event level. Positive = labelled attack event; predicted positive = the event is a member of a correlated incident. Labels are never shown to the engine." /></div>
                <div className="mt-3 grid grid-cols-3 gap-2 text-center">
                  {(['precision', 'recall', 'f1'] as const).map((k) => (
                    <div key={k} className="rounded-xl bg-sky-50/70 py-2 ring-1 ring-sky-100">
                      <div className="num font-display text-xl font-bold text-sky-800">{gt.detection?.[k] === null || gt.detection?.[k] === undefined ? '—' : (gt.detection[k]! * 100).toFixed(1) + '%'}</div>
                      <div className="text-[10px] font-semibold uppercase tracking-wider text-faint">{k}</div>
                    </div>
                  ))}
                </div>
                <div className="num mt-3 grid grid-cols-4 gap-2 text-center text-[11px] text-muted">
                  <div><b className="block text-sm text-emerald-700">{fmtCompact(gt.detection.tp)}</b>true pos.</div>
                  <div><b className="block text-sm text-rose-700">{fmtCompact(gt.detection.fp)}</b>false pos.</div>
                  <div><b className="block text-sm text-amber-700">{fmtCompact(gt.detection.fn)}</b>missed</div>
                  <div><b className="block text-sm text-fg">{fmtCompact((gt.detection as { tn?: number }).tn ?? 0)}</b>true neg.</div>
                </div>
              </div>
            )}
          </Card>
          <Card title="Labelled tactics — coverage" subtitle={`For every tactic in the labels: how many ${unit} exist, how many a detector flagged, and how many ended up in an incident.`}>
            <div className="overflow-x-auto">
              <table className="table-modern w-full text-sm">
                <thead><tr>
                  <th className="px-3 py-2 text-left">Tactic</th><th className="px-3 py-2 text-right">Labelled</th><th className="px-3 py-2 text-right">Flagged</th>
                  <th className="px-3 py-2 text-right">In incident</th><th className="w-40 px-3 py-2 text-left">Coverage</th><th className="px-3 py-2" />
                </tr></thead>
                <tbody className="divide-y divide-ink-700/60">
                  {tactics.map((r) => (
                    <tr key={r.tactic} className="hover:bg-ink-800/50">
                      <td className="px-3 py-2"><TacticPill tactic={r.tactic} /></td>
                      <td className="num px-3 text-right">{fmtInt(r.events)}</td>
                      <td className="num px-3 text-right text-muted">{fmtInt(r.tagged)}</td>
                      <td className="num px-3 text-right font-semibold">{fmtInt(r.in_incident)}</td>
                      <td className="px-3">
                        <div className="flex items-center gap-2">
                          <div className="h-2 flex-1 overflow-hidden rounded-full bg-ink-800"><div className="h-full rounded-full" style={{ width: `${r.coverage_pct ?? 0}%`, background: tacticColor(r.tactic) }} /></div>
                          <span className={cx('num w-11 text-right text-xs font-bold', (r.coverage_pct ?? 0) >= 50 ? 'text-emerald-700' : (r.coverage_pct ?? 0) > 0 ? 'text-amber-700' : 'text-faint')}>{fmtPct(r.coverage_pct, 0)}</span>
                        </div>
                      </td>
                      <td className="whitespace-nowrap px-3 text-right"><Link className="text-xs font-semibold text-sky-700 hover:underline" to={`/events?label=${encodeURIComponent(r.tactic)}`}>Events →</Link></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="mt-3 text-xs text-faint">Some tactics (e.g. Persistence or Privilege Escalation carried over SMB, or offline password cracking) leave no distinctive trace in the available telemetry; low coverage there is expected and shown rather than hidden.</p>
          </Card>
        </div>
      )}

      <Card title="Traffic timeline" subtitle={`${onlyConn ? 'Connections' : 'Events'} per ${data.granularity} (${tzLabel()})${gt.available ? ', stacked by labelled tactic for attack traffic' : ''}.`}>
        <div className="h-72">
          <ResponsiveContainer>
            {gt.available && gt.tactic_timeline && gt.tactic_timeline.length > 0 ? (
              <BarChart data={gt.tactic_timeline} margin={{ left: -6, right: 8, top: 6 }}>
                <CartesianGrid vertical={false} strokeDasharray="3 4" />
                <XAxis dataKey="t" tickFormatter={(v) => fmtBucket(String(v), data.granularity)} minTickGap={24} tickLine={false} axisLine={false} />
                <YAxis tickFormatter={(v) => fmtCompact(Number(v))} tickLine={false} axisLine={false} width={44} />
                <Tooltip contentStyle={tooltipStyle} labelFormatter={(v) => fmtBucket(String(v), data.granularity)} cursor={{ fill: 'rgba(201,162,39,0.08)' }} formatter={(v) => Number(v).toLocaleString()} />
                <Legend wrapperStyle={{ fontSize: 11 }} iconType="circle" />
                {tacticNames.map((n, i) => <Bar key={n} dataKey={n} stackId="t" fill={tacticColor(n)} radius={i === tacticNames.length - 1 ? [4, 4, 0, 0] : undefined} />)}
              </BarChart>
            ) : (
              <AreaChart data={data.timeline} margin={{ left: -6, right: 8, top: 6 }}>
                <CartesianGrid vertical={false} strokeDasharray="3 4" />
                <XAxis dataKey="t" tickFormatter={(v) => fmtBucket(String(v), data.granularity)} minTickGap={24} tickLine={false} axisLine={false} />
                <YAxis tickFormatter={(v) => fmtCompact(Number(v))} tickLine={false} axisLine={false} width={44} />
                <Tooltip contentStyle={tooltipStyle} labelFormatter={(v) => fmtBucket(String(v), data.granularity)} />
                <Area type="monotone" dataKey="events" name="Events" stroke={CHART.gold} fill={CHART.gold} fillOpacity={0.25} />
                <Area type="monotone" dataKey="signal" name="Flagged" stroke={CHART.espresso} fill={CHART.espresso} fillOpacity={0.2} />
              </AreaChart>
            )}
          </ResponsiveContainer>
        </div>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2 2xl:grid-cols-3">
        <Card title="Application services" subtitle="Zeek service / Suricata app-layer detection"><Donut data={data.services} total={data.services.reduce((a, b) => a + b.count, 0)} label="identified" /></Card>
        <Card title="Connection states" subtitle="Zeek conn_state (S0 = no reply, REJ = rejected, SF = normal close…)"><Donut data={data.conn_states} total={t.events} label="connections" /></Card>
        <Card title="Transport protocols"><Donut data={data.protocols} total={t.events} label="connections" /></Card>
        <Card title="Top destination ports" subtitle="Most-contacted services">
          <BarList mono items={data.dest_ports.map((p) => ({ key: p.key, value: p.count }))} />
        </Card>
        <Card title="Top talkers" subtitle="Busiest source hosts" actions={<Segmented label="Rank by" value={talkers} onChange={setTalkers} options={[{ value: 'count', label: 'Connections' }, { value: 'bytes', label: 'Bytes' }]} />}>
          {talkers === 'count'
            ? <BarList mono items={data.top_sources.map((p) => ({ key: p.key, value: p.count }))} />
            : <BarList mono color={CHART.espresso} format={fmtBytes} items={data.top_sources_by_bytes.map((p) => ({ key: p.key, value: p.bytes }))} />}
        </Card>
        <Card title="Top destinations" subtitle="Most-contacted hosts">
          <BarList mono color={CHART.goldDark} items={data.top_destinations.map((p) => ({ key: p.key, value: p.count }))} />
        </Card>
      </div>

      {gt.available && gt.techniques && gt.techniques.length > 0 && (
        <Card title="Labelled ATT&CK techniques" subtitle={`Technique IDs attached to attack ${unit} in the dataset`}>
          <div className="flex flex-wrap gap-2">
            {gt.techniques.map((x) => (
              <a key={x.technique} href={`https://attack.mitre.org/techniques/${x.technique.replace('.', '/')}/`} target="_blank" rel="noreferrer noopener"
                className="group inline-flex items-center gap-2 rounded-xl border border-ink-700 bg-white px-3 py-2 text-sm shadow-sm transition hover:-translate-y-0.5 hover:border-sky-300 hover:shadow-[var(--shadow-lift)]">
                <span className="mono font-semibold text-sky-700">{x.technique}</span><span className="num text-muted">{fmtInt(x.count)}</span>
              </a>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}
