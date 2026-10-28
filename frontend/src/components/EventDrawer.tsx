import { AlertTriangle } from 'lucide-react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { fmtBytes, fmtTime, STAGE_LABELS, tzLabel } from '../lib/format'
import { useAsync } from '../lib/hooks'
import { Chip, Drawer, ErrorState, JsonBlock, SensorBadge, Spinner, TacticPill } from './ui'

const FIELDS: [string, string][] = [
  ['timestamp_utc', 'Timestamp'], ['event_type', 'Event type'], ['source_log', 'Source log'],
  ['source_ip', 'Source IP'], ['source_port', 'Source port'], ['destination_ip', 'Destination IP'], ['destination_port', 'Destination port'],
  ['transport_protocol', 'Transport'], ['application_protocol', 'Application protocol'], ['connection_state', 'Connection state'],
  ['bytes_sent', 'Bytes sent'], ['bytes_received', 'Bytes received'], ['duration', 'Duration (s)'],
  ['alert_signature', 'Signature / notice'], ['alert_signature_id', 'Signature ID'], ['alert_category', 'Category'],
  ['sensor_severity', 'Sensor severity'], ['dns_query', 'DNS query'], ['http_host', 'HTTP host'], ['http_uri', 'HTTP URI'],
  ['http_user_agent', 'HTTP user agent'], ['tls_server_name', 'TLS SNI'], ['auth_success', 'Auth success'],
  ['community_id', 'Community ID'], ['flow_uid', 'Flow UID'], ['source_record_id', 'Source record ID'],
  ['original_event_reference', 'Original reference'], ['schema_version', 'Schema version'],
]

export function EventDrawer({ eventId, onClose }: { eventId: string | null; onClose: () => void }) {
  const { data, error, loading } = useAsync(() => (eventId ? api.event(eventId) : Promise.resolve(null)), [eventId])
  return (
    <Drawer open={!!eventId} onClose={onClose} wide title={<span className="mono">{eventId}</span>}>
      {loading ? <Spinner /> : error ? <ErrorState error={error} /> : data && (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-2">
            <SensorBadge sensor={data.source_sensor} />
            {data.stage && <Chip>{STAGE_LABELS[data.stage]}</Chip>}
            {data.incident_ids.map((i) => <Link key={i} to={`/incidents/${i}`} onClick={onClose} className="mono rounded-md bg-sky-100 px-1.5 py-0.5 text-[11px] font-semibold text-sky-800 hover:underline">{i}</Link>)}
            {data.incident_ids.length === 0 && <span className="text-xs text-faint">Not part of any incident</span>}
          </div>
          {data.ground_truth && (
            <section className={data.ground_truth.malicious ? 'rounded-2xl border border-rose-200 bg-rose-50/60 p-3' : 'rounded-2xl border border-ink-700 bg-white p-3'}>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted">Dataset ground-truth label <span className="font-normal normal-case text-faint">(evaluation only — not seen by the engine)</span></h3>
              {data.ground_truth.malicious ? (
                <div className="flex flex-wrap items-center gap-1.5">
                  {data.ground_truth.tactics.map((t) => <TacticPill key={t} tactic={t} />)}
                  {data.ground_truth.techniques.map((t) => <a key={t} href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`} target="_blank" rel="noreferrer noopener" className="mono rounded-md bg-white px-1.5 py-0.5 text-[11px] font-semibold text-sky-700 ring-1 ring-ink-700 hover:underline">{t}</a>)}
                </div>
              ) : <span className="text-sm text-muted">Benign baseline traffic</span>}
            </section>
          )}
          {data.detector_tags.length > 0 && (
            <section>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted">Why this event matters (detector tags)</h3>
              <ul className="space-y-1.5">
                {data.detector_tags.map((t) => (
                  <li key={t} className="rounded-xl border border-ink-700 bg-white px-3 py-2 text-xs">
                    <span className="mono text-sky-700">{t}</span>
                    {data.tag_evidence[t] && <span className="text-muted"> — {data.tag_evidence[t]}</span>}
                  </li>
                ))}
              </ul>
            </section>
          )}
          {data.normalization_warnings.length > 0 && (
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-xs text-amber-700">
              <div className="mb-1 flex items-center gap-1.5 font-semibold"><AlertTriangle size={13} aria-hidden />Normalization warnings</div>
              <ul className="list-disc pl-5">{data.normalization_warnings.map((w) => <li key={w}>{w}</li>)}</ul>
            </div>
          )}
          <section>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted">Normalized record (schema {data.schema_version})</h3>
            <dl className="grid grid-cols-[10rem_1fr] gap-x-3 gap-y-1.5 rounded-2xl border border-ink-700 bg-white p-4 text-xs">
              {FIELDS.map(([k, label]) => {
                const raw = (data as unknown as Record<string, unknown>)[k]
                if (raw === null || raw === undefined || raw === '') return null
                let v = String(raw)
                if (k === 'timestamp_utc') v = `${fmtTime(String(raw))} ${tzLabel()}`
                if (k.startsWith('bytes')) v = `${Number(raw).toLocaleString()} (${fmtBytes(Number(raw))})`
                return [<dt key={k + 'l'} className="text-muted">{label}</dt>, <dd key={k} className="mono break-all text-fg">{v}</dd>]
              })}
            </dl>
          </section>
          <section>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted">Original source payload (untrusted, shown as text)</h3>
            <JsonBlock value={data.raw_payload} />
          </section>
        </div>
      )}
    </Drawer>
  )
}
