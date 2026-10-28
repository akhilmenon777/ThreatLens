import { AlertTriangle, Search, X } from 'lucide-react'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api/client'
import type { GroundTruth } from '../api/types'
import { EventDrawer } from '../components/EventDrawer'
import { DataGate } from '../components/NoDataset'
import { Card, cx, EmptyState, inputCls, PageHeader, Pagination, SensorBadge, Spinner, tacticColor } from '../components/ui'
import { useApp } from '../lib/app-context'
import { fmtBytes, fmtTime, STAGE_LABELS, tzLabel } from '../lib/format'
import { useAsync, useDebounced } from '../lib/hooks'

export function LabelCell({ gt }: { gt?: GroundTruth | null }) {
  if (!gt) return <span className="text-faint">—</span>
  if (!gt.malicious) return <span className="inline-flex rounded-full bg-ink-800 px-2 py-0.5 text-[10px] font-medium text-muted ring-1 ring-ink-700">benign</span>
  return (
    <div className="flex flex-wrap gap-1">
      {gt.tactics.map((t) => (
        <span key={t} className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold whitespace-nowrap"
          style={{ background: tacticColor(t) + '18', color: tacticColor(t) }} title={gt.techniques.join(', ')}>
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: tacticColor(t) }} />{t}
        </span>
      ))}
    </div>
  )
}

export default function EventsPage() {
  const { version, dataset } = useApp()
  const [sp, setSp] = useSearchParams()
  const get = (k: string) => sp.get(k) ?? ''
  const [qInput, setQInput] = useState(get('q'))
  const q = useDebounced(qInput)
  const [open, setOpen] = useState<string | null>(null)
  const page = Number(get('page') || 1)
  const set = (patch: Record<string, string>) => {
    const n = new URLSearchParams(sp)
    Object.entries(patch).forEach(([k, v]) => (v ? n.set(k, v) : n.delete(k)))
    if (!('page' in patch)) n.delete('page')
    setSp(n, { replace: true })
  }
  const types = useAsync(() => api.eventTypes(), [version])
  const labels = useAsync(() => (dataset?.has_labels ? api.eventLabels() : Promise.resolve([] as string[])), [version, dataset?.id])
  const { data, error, loading, reload } = useAsync(() => api.events({
    q, sensor: get('sensor'), event_type: get('event_type'), ip: get('ip'), assigned: get('assigned'), label: get('label'),
    tagged: get('tagged') || undefined, warnings: get('warnings') || undefined, incident_id: get('incident'), page, page_size: 50,
  }), [version, q, sp.toString()])
  const hasLabels = !!dataset?.has_labels && (labels.data?.length ?? 0) > 0
  const active = ['sensor', 'event_type', 'ip', 'assigned', 'tagged', 'warnings', 'incident', 'label'].some((k) => get(k)) || q

  if (error) return <><PageHeader title="Raw events" /><DataGate error={error} onRetry={reload} /></>
  return (
    <div className="space-y-4">
      <PageHeader eyebrow="Monitor" title="Raw events" subtitle="Show me the underlying data — every normalised record with its original payload." />
      <Card bodyClass="p-4">
        <div className="flex flex-wrap items-end gap-3">
          <label className="relative min-w-[16rem] flex-1">
            <span className="sr-only">Search events</span>
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-faint" aria-hidden />
            <input value={qInput} onChange={(e) => { setQInput(e.target.value); set({}) }} placeholder="Event ID, IP, signature, DNS query, host, user agent…"
              className={cx(inputCls, 'w-full pl-9')} />
          </label>
          <label className="flex flex-col gap-1 text-xs font-medium text-muted">Sensor
            <select className={inputCls} value={get('sensor')} onChange={(e) => set({ sensor: e.target.value })}><option value="">Any</option><option value="suricata">Suricata</option><option value="zeek">Zeek</option><option value="wazuh">Wazuh</option><option value="aminer">AMiner</option></select></label>
          <label className="flex flex-col gap-1 text-xs font-medium text-muted">Event type
            <select className={inputCls} value={get('event_type')} onChange={(e) => set({ event_type: e.target.value })}>
              <option value="">Any</option>{types.data?.map((t) => <option key={t.event_type} value={t.event_type}>{t.event_type} ({t.count.toLocaleString()})</option>)}</select></label>
          <label className="flex flex-col gap-1 text-xs font-medium text-muted">IP address
            <input className={cx(inputCls, 'w-36')} value={get('ip')} onChange={(e) => set({ ip: e.target.value.trim() })} placeholder="143.88.3.11" /></label>
          <label className="flex flex-col gap-1 text-xs font-medium text-muted">Correlation
            <select className={inputCls} value={get('assigned')} onChange={(e) => set({ assigned: e.target.value })}>
              <option value="">All events</option><option value="yes">In an incident</option><option value="no">Not in any incident</option></select></label>
          <label className="flex flex-col gap-1 text-xs font-medium text-muted">Signal
            <select className={inputCls} value={get('tagged')} onChange={(e) => set({ tagged: e.target.value })}>
              <option value="">All</option><option value="true">Alert/detector tagged</option><option value="false">Context only</option></select></label>
          {hasLabels && (
            <label className="flex flex-col gap-1 text-xs font-medium text-muted">Ground-truth label
              <select className={inputCls} value={get('label')} onChange={(e) => set({ label: e.target.value })}>
                <option value="">Any</option><option value="malicious">Any attack</option><option value="benign">Benign</option>
                {labels.data?.map((t) => <option key={t} value={t}>{t}</option>)}
              </select></label>
          )}
          <label className="flex items-center gap-1.5 pb-2.5 text-xs text-muted"><input type="checkbox" className="accent-[#8f6a10]" checked={get('warnings') === 'true'} onChange={(e) => set({ warnings: e.target.checked ? 'true' : '' })} />Parsing warnings</label>
          {get('incident') && <button onClick={() => set({ incident: '' })} className="mb-1 inline-flex items-center gap-1 rounded-full bg-sky-100 px-3 py-1 text-xs font-medium text-sky-800">Incident {get('incident')} <X size={12} /></button>}
          {active && <button onClick={() => { setQInput(''); setSp(new URLSearchParams(), { replace: true }) }} className="mb-2 text-xs font-medium text-sky-700 hover:underline">Clear all</button>}
        </div>
      </Card>
      <Card bodyClass="p-0">
        {loading && !data ? <Spinner /> : data && data.total === 0 ? <div className="p-6"><EmptyState title="No events match">Adjust the filters.</EmptyState></div> : data && (
          <div className={cx('overflow-x-auto', loading && 'opacity-60')}>
            <table className="table-modern w-full text-xs">
              <thead><tr>
                <th className="px-3 py-2.5 text-left">Time ({tzLabel()})</th><th className="px-3 text-left">Event ID</th><th className="px-3 text-left">Sensor / type</th>
                <th className="px-3 text-left">Source</th><th className="px-3 text-left">Destination</th>
                <th className="px-3 text-left">Detail</th><th className="px-3 text-left">Tags</th>
                {hasLabels && <th className="px-3 text-left">Label</th>}
                <th className="px-3 text-left">Incident</th>
              </tr></thead>
              <tbody className="divide-y divide-ink-700/60">
                {data.items.map((e) => (
                  <tr key={e.event_id} className="cursor-pointer hover:bg-sky-50/50" onClick={() => setOpen(e.event_id)} tabIndex={0} onKeyDown={(k) => { if (k.key === 'Enter') setOpen(e.event_id) }}>
                    <td className="num whitespace-nowrap px-3 py-2 text-muted">{fmtTime(e.timestamp_utc)}</td>
                    <td className="mono whitespace-nowrap px-3 font-medium text-sky-700">{e.event_id}</td>
                    <td className="whitespace-nowrap px-3"><SensorBadge sensor={e.source_sensor} /> <span className="text-muted">{e.event_type}</span>
                      {(e.transport_protocol || e.application_protocol) && <div className="text-[10px] text-faint">{e.transport_protocol ?? ''}{e.application_protocol ? `/${e.application_protocol}` : ''}</div>}</td>
                    <td className="mono whitespace-nowrap px-3">{e.source_ip ?? '—'}{e.source_port !== null && <span className="text-faint">:{e.source_port}</span>}</td>
                    <td className="mono whitespace-nowrap px-3">{e.destination_ip ?? '—'}{e.destination_port !== null && <span className="text-faint">:{e.destination_port}</span>}</td>
                    <td className="max-w-[14rem] truncate px-3 text-muted" title={e.alert_signature ?? e.dns_query ?? ''}>
                      {e.normalization_warnings.length > 0 && <AlertTriangle size={11} className="mr-1 inline text-amber-600" aria-label="parsing warnings" />}
                      {e.alert_signature ?? e.dns_query ?? e.tls_server_name ?? e.http_host ?? (e.connection_state ? `${e.connection_state}${e.bytes_sent ? ` · ${fmtBytes(e.bytes_sent)} out` : ''}` : '')}
                    </td>
                    <td className="max-w-[11rem] px-3">
                      <div className="flex flex-wrap gap-1">{e.detector_tags.map((t) => <span key={t} className="mono rounded bg-espresso-900 px-1.5 py-0.5 text-[10px] text-sky-200">{t}</span>)}</div>
                    </td>
                    {hasLabels && <td className="px-3"><LabelCell gt={e.ground_truth} /></td>}
                    <td className="px-3" onClick={(ev) => ev.stopPropagation()}>
                      {e.incident_ids.map((i) => <Link key={i} to={`/incidents/${i}`} className="mono font-medium text-sky-700 hover:underline">{i}</Link>)}
                      {e.incident_ids.length === 0 && <span className="text-faint">{e.detector_tags.length ? 'unassigned' : 'context'}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && data.total > 0 && <div className="border-t border-ink-700 px-4 pb-3"><Pagination page={page} pageSize={50} total={data.total} onPage={(p) => set({ page: String(p) })} /></div>}
      </Card>
      <p className="text-xs text-faint">Stages: {Object.values(STAGE_LABELS).join(' · ')}. Click a row for the normalised record and the original payload.{hasLabels && ' Ground-truth labels come from the dataset and are never used by detection.'}</p>
      <EventDrawer eventId={open} onClose={() => setOpen(null)} />
    </div>
  )
}
