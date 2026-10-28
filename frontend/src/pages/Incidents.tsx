import { ArrowDown, ArrowUp, Search, SearchX } from 'lucide-react'
import { useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { api } from '../api/client'
import type { IncidentListItem } from '../api/types'
import { DataGate } from '../components/NoDataset'
import {
  Button, Card, Chip, cx, EmptyState, PageHeader, Pagination, ScoreBar, SensorBadge, SEV_COLOR, SeverityBadge, Spinner,
  StatusBadge,
} from '../components/ui'
import { useApp } from '../lib/app-context'
import { fmtScore, fmtSpan, fmtTime, SEVERITIES, STAGE_LABELS, STAGE_SHORT, STAGES, STATUS_LABELS, tzLabel } from '../lib/format'
import { useAsync, useDebounced } from '../lib/hooks'

const TACTICS = ['Reconnaissance', 'Initial Access', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Command and Control', 'Exfiltration']

function toUtcIso(local: string): string | undefined {
  if (!local) return undefined
  const d = new Date(local) // interpreted in the browser's local zone
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString()
}

export function StageChips({ stages }: { stages: string[] }) {
  return (
    <div className="flex flex-wrap gap-1">
      {STAGES.filter((s) => stages.includes(s)).map((s) => <Chip key={s} title={STAGE_LABELS[s]}>{STAGE_SHORT[s]}</Chip>)}
      {stages.length === 0 && <span className="text-xs text-faint">—</span>}
    </div>
  )
}

export default function IncidentsPage() {
  const { version } = useApp()
  const nav = useNavigate()
  const [sp, setSp] = useSearchParams()
  const get = (k: string) => sp.get(k) ?? ''
  const getAll = (k: string) => sp.getAll(k)
  const [qInput, setQInput] = useState(get('q'))
  const q = useDebounced(qInput)
  const page = Number(get('page') || 1)
  const sort = get('sort') || 'risk_score'
  const order = get('order') || 'desc'

  const update = (patch: Record<string, string | string[] | null>) => {
    const next = new URLSearchParams(sp)
    for (const [k, v] of Object.entries(patch)) {
      next.delete(k)
      if (Array.isArray(v)) v.forEach((x) => next.append(k, x))
      else if (v) next.set(k, v)
    }
    if (!('page' in patch)) next.delete('page')
    setSp(next, { replace: true })
  }
  const toggle = (k: string, v: string) => {
    const cur = getAll(k)
    update({ [k]: cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v] })
  }

  const { data, error, loading, reload } = useAsync(() => api.incidents({
    q, severity: getAll('severity'), status: getAll('status'), sensor: get('sensor'), tactic: get('tactic'),
    technique: get('technique'), start: toUtcIso(get('start')), end: toUtcIso(get('end')), sort, order, page, page_size: 20,
  }), [version, q, sp.toString()])

  const sortHeader = (key: string, label: string, align = 'text-left') => (
    <th className={cx('px-3 py-2 font-medium', align)} aria-sort={sort === key ? (order === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button className="inline-flex items-center gap-1 hover:text-fg" onClick={() => update({ sort: key, order: sort === key && order === 'desc' ? 'asc' : 'desc' })}>
        {label}{sort === key && (order === 'asc' ? <ArrowUp size={12} /> : <ArrowDown size={12} />)}
      </button>
    </th>
  )
  const filtersActive = ['severity', 'status', 'sensor', 'tactic', 'technique', 'start', 'end'].some((k) => sp.get(k)) || q

  if (error) return <><PageHeader title="Incidents" /><DataGate error={error} onRetry={reload} /></>

  return (
    <div className="space-y-4">
      <PageHeader eyebrow="Monitor" title="Incidents" subtitle="What should I investigate first? Risk-ranked correlated incidents (meta-alerts)." actions={data ? <span className="num rounded-full bg-white px-3 py-1.5 text-xs font-semibold text-muted ring-1 ring-ink-600">{data.total.toLocaleString()} incident{data.total === 1 ? '' : 's'}</span> : undefined} />
      <Card bodyClass="p-4 space-y-3">
        <div className="flex flex-wrap items-end gap-3">
          <label className="relative min-w-[16rem] flex-1">
            <span className="sr-only">Search incidents</span>
            <Search size={14} className="absolute left-2.5 top-2.5 text-faint" aria-hidden />
            <input value={qInput} onChange={(e) => { setQInput(e.target.value); update({}) }} placeholder="Search ID, title, IP, hostname…"
              className="w-full rounded-xl border-0 bg-white shadow-sm ring-1 ring-ink-600 py-2 pl-8 pr-3 text-sm placeholder:text-faint focus:ring-2 focus:ring-sky-400" />
          </label>
          <label className="flex flex-col gap-1 text-xs text-muted">Sensor
            <select value={get('sensor')} onChange={(e) => update({ sensor: e.target.value })} className="rounded-xl border-0 bg-white shadow-sm ring-1 ring-ink-600 px-2.5 py-2 text-sm text-fg">
              <option value="">Any</option><option value="suricata">Suricata</option><option value="zeek">Zeek</option><option value="wazuh">Wazuh</option><option value="aminer">AMiner</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs text-muted">ATT&CK tactic
            <select value={get('tactic')} onChange={(e) => update({ tactic: e.target.value })} className="rounded-xl border-0 bg-white shadow-sm ring-1 ring-ink-600 px-2.5 py-2 text-sm text-fg">
              <option value="">Any</option>{TACTICS.map((t) => <option key={t}>{t}</option>)}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs text-muted">Technique
            <input value={get('technique')} onChange={(e) => update({ technique: e.target.value.trim().toUpperCase() })} placeholder="e.g. T1110"
              className="w-28 rounded-xl border-0 bg-white shadow-sm ring-1 ring-ink-600 px-2.5 py-2 text-sm text-fg placeholder:text-faint" />
          </label>
          <label className="flex flex-col gap-1 text-xs text-muted">From (local)
            <input type="datetime-local" value={get('start')} onChange={(e) => update({ start: e.target.value })} className="rounded-xl border-0 bg-white shadow-sm ring-1 ring-ink-600 px-2.5 py-1.5 text-sm text-fg" />
          </label>
          <label className="flex flex-col gap-1 text-xs text-muted">To (local)
            <input type="datetime-local" value={get('end')} onChange={(e) => update({ end: e.target.value })} className="rounded-xl border-0 bg-white shadow-sm ring-1 ring-ink-600 px-2.5 py-1.5 text-sm text-fg" />
          </label>
          {filtersActive && <Button size="sm" variant="ghost" onClick={() => { setQInput(''); setSp(new URLSearchParams(), { replace: true }) }}>Clear filters</Button>}
        </div>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Severity filter">
            <span className="text-xs text-muted">Severity</span>
            {SEVERITIES.map((s) => (
              <button key={s} aria-pressed={getAll('severity').includes(s)} onClick={() => toggle('severity', s)}
                className={cx('rounded-full border px-3 py-0.5 text-xs', getAll('severity').includes(s) ? 'border-transparent text-white font-semibold shadow-sm' : 'border-ink-600 bg-white text-muted hover:text-fg')}
                style={getAll('severity').includes(s) ? { background: SEV_COLOR[s] } : undefined}>{s}</button>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Status filter">
            <span className="text-xs text-muted">Status</span>
            {Object.entries(STATUS_LABELS).map(([k, v]) => (
              <button key={k} aria-pressed={getAll('status').includes(k)} onClick={() => toggle('status', k)}
                className={cx('rounded-full border px-3 py-0.5 text-xs', getAll('status').includes(k) ? 'border-sky-500 bg-sky-100 font-semibold text-sky-800' : 'border-ink-600 bg-white text-muted hover:text-fg')}>{v}</button>
            ))}
          </div>
        </div>
      </Card>

      <Card bodyClass="p-0">
        {loading && !data ? <Spinner /> : data && data.total === 0 ? (
          <div className="p-6"><EmptyState title={filtersActive ? 'No incidents match these filters' : 'No incidents in this dataset'} icon={<SearchX aria-hidden />}>
            {filtersActive ? 'Clear or relax the filters.' : 'Run correlation from the Overview page, or load data.'}
          </EmptyState></div>
        ) : data && (
          <div className={cx('overflow-x-auto', loading && 'opacity-60')}>
            <table className="table-modern w-full text-sm">
              <thead>
                <tr>
                  {sortHeader('id', 'Incident')}
                  {sortHeader('severity', 'Severity')}
                  {sortHeader('risk_score', 'Risk')}
                  {sortHeader('confidence', 'Confidence')}
                  {sortHeader('first_seen', `First seen (${tzLabel()})`)}
                  <th className="hidden px-3 py-2 text-left font-medium 2xl:table-cell">Duration</th>
                  {sortHeader('event_count', 'Events', 'text-right')}
                  <th className="hidden px-3 py-2 text-left font-medium 2xl:table-cell">Entities</th>
                  <th className="px-3 py-2 text-left font-medium">Sensors</th>
                  <th className="px-3 py-2 text-left font-medium">Stages / tactics</th>
                  {sortHeader('status', 'Status')}
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-700/70">
                {data.items.map((i: IncidentListItem) => (
                  <tr key={i.id} tabIndex={0} onClick={() => nav(`/incidents/${i.id}`)} onKeyDown={(e) => { if (e.key === 'Enter') nav(`/incidents/${i.id}`) }}
                    className="cursor-pointer hover:bg-sky-50/50 focus:bg-sky-50/60">
                    <td className="max-w-[20rem] px-3 py-2.5">
                      <div className="truncate font-semibold text-fg" title={i.title}>{i.title}</div>
                      <div className="mono text-[11px] text-faint">{i.id}{i.suspected_false_positive && <span className="ml-2 text-amber-700">suspected FP</span>}{i.assignee && <span className="ml-2">→ {i.assignee}</span>}</div>
                    </td>
                    <td className="px-3"><SeverityBadge severity={i.severity} /></td>
                    <td className="w-28 px-3"><div className="num text-sm font-semibold">{i.risk_score.toFixed(0)}</div><ScoreBar value={i.risk_score} color={SEV_COLOR[i.severity]} /></td>
                    <td className="num px-3 text-sm">{fmtScore(i.confidence)}</td>
                    <td className="num whitespace-nowrap px-3 text-xs text-muted">{fmtTime(i.first_seen)}</td>
                    <td className="num hidden whitespace-nowrap px-3 text-xs text-muted 2xl:table-cell">{fmtSpan(i.first_seen, i.last_seen)}</td>
                    <td className="num px-3 text-right">{i.event_count.toLocaleString()}</td>
                    <td className="mono hidden max-w-[12rem] px-3 text-[11px] text-muted 2xl:table-cell">
                      <div className="truncate" title={i.entities.internal_hosts.join(', ')}>{i.entities.internal_hosts.slice(0, 2).join(', ')}{i.entities.internal_hosts.length > 2 && ` +${i.entities.internal_hosts.length - 2}`}</div>
                      {i.entities.external_ips.length > 0 && <div className="truncate text-faint" title={i.entities.external_ips.join(', ')}>ext: {i.entities.external_ips.slice(0, 2).join(', ')}</div>}
                    </td>
                    <td className="px-3"><div className="flex gap-1">{i.sensors.map((s) => <SensorBadge key={s} sensor={s} />)}</div></td>
                    <td className="max-w-[13rem] px-3 py-2"><StageChips stages={i.stages_present} /><div className="mt-1 truncate text-[11px] text-faint">{i.tactics.join(' · ')}</div></td>
                    <td className="px-3"><StatusBadge status={i.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && data.total > 0 && <div className="border-t border-ink-700 px-4 pb-3"><Pagination page={page} pageSize={20} total={data.total} onPage={(p) => update({ page: String(p) })} /></div>}
      </Card>
    </div>
  )
}
