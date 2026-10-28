import { CheckCircle2, PlugZap, RotateCcw, Save, XCircle } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api } from '../api/client'
import type { AnalysisSettings, LlmStatus } from '../api/types'
import { Button, Card, cx, ErrorState, HelpTip, inputCls, PageHeader, Spinner } from '../components/ui'
import { useApp } from '../lib/app-context'
import { setDisplayTimezone } from '../lib/format'
import { useAsync } from '../lib/hooks'

type Field = { key: string; label: string; help?: string; step?: number; kind?: 'number' | 'list' }

const CORR: Field[] = [
  { key: 'link_window_seconds', label: 'Link time window (s)', help: 'Max gap between the end of one event and the start of the next for a direct link.' },
  { key: 'max_group_gap_seconds', label: 'Incident split gap (s)', help: 'Incidents are split where member activity pauses for longer than this.' },
  { key: 'link_threshold', label: 'Link score threshold', step: 0.01, help: 'Minimum pairwise score (0–1). Higher = stricter grouping.' },
  { key: 'min_incident_events', label: 'Minimum events per incident' },
  { key: 'popular_entity_share', label: 'Popular-entity share', step: 0.01, help: 'IPs reached by more than this share of distinct signal sources (min 5) cannot link on their own (prevents over-merging through busy servers).' },
  { key: 'max_neighbors_per_entity', label: 'Candidate cap per entity', help: 'Bounds pair generation: each event is compared with at most this many earlier events per entity.' },
  { key: 'w_entity', label: 'Weight: shared entity', step: 0.05 },
  { key: 'w_time', label: 'Weight: time proximity', step: 0.05 },
  { key: 'w_behavior', label: 'Weight: behaviour/stage', step: 0.05 },
  { key: 'w_cross_sensor', label: 'Weight: cross-sensor', step: 0.05 },
  { key: 'infrastructure_ips', label: 'Infrastructure IPs (never link alone)', kind: 'list' },
  { key: 'known_scanners', label: 'Authorised scanners', kind: 'list', help: 'Still correlated, but risk is reduced and a benign explanation is attached.' },
  { key: 'internal_networks', label: 'Internal networks (CIDR)', kind: 'list' },
]
const DETECT: Field[] = [
  { key: 'scan_min_targets', label: 'Scan: min hosts/ports in 15 min' },
  { key: 'bruteforce_min_failures', label: 'Brute force: min failed logins in 1 h' },
  { key: 'beacon_min_connections', label: 'Beacon: min connections' },
  { key: 'beacon_max_jitter_ratio', label: 'Beacon: max jitter ratio', step: 0.01 },
  { key: 'exfil_min_bytes', label: 'Large transfer: min bytes out' },
  { key: 'dns_tunnel_min_label_len', label: 'DNS tunnel: min label length' },
  { key: 'service_bruteforce_min_connections', label: 'Service brute force: min connections in 1 h', help: 'Connection-only heuristic for logs without auth results (e.g. UWF conn records).' },
  { key: 'probe_burst_min_connections', label: 'Service probing: min connections in 15 min', help: 'High-rate connections to one TCP service (web / vulnerability scanning).' },
  { key: 'admin_fanout_min_hosts', label: 'Lateral fan-out: min internal hosts in 1 h' },
  { key: 'web_error_burst_min_errors', label: 'Web scan (host logs): min HTTP 4xx errors in 15 min', help: 'Wazuh web-access errors logged for one client on one server (dirb / WPScan style scanning).' },
  { key: 'auth_service_ports', label: 'Authentication-capable service ports', kind: 'list' },
  { key: 'admin_ports', label: 'Remote-administration ports (lateral-movement heuristic)', kind: 'list' },
]
const RISK: Field[] = [
  { key: 'w_severity', label: 'Alert severity' }, { key: 'w_corroboration', label: 'Distinct corroboration' },
  { key: 'w_progression', label: 'Attack progression' }, { key: 'w_entities', label: 'Hosts involved' },
  { key: 'w_high_impact', label: 'High-impact indicators' }, { key: 'w_cross_sensor', label: 'Cross-sensor' },
  { key: 'w_concentration', label: 'Temporal concentration' }, { key: 'known_scanner_penalty', label: 'Authorised-scanner penalty' },
  { key: 'critical_threshold', label: 'Critical ≥' }, { key: 'high_threshold', label: 'High ≥' },
  { key: 'medium_threshold', label: 'Medium ≥' }, { key: 'low_threshold', label: 'Low ≥' },
]
const TIMEZONES = ['UTC', 'Asia/Kolkata', 'Europe/London', 'Europe/Berlin', 'America/New_York', 'America/Los_Angeles', 'Asia/Singapore', 'Asia/Dubai', 'Australia/Sydney']

function NumGrid({ fields, values, onChange }: { fields: Field[]; values: Record<string, number | string[]>; onChange: (k: string, v: number | string[]) => void }) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
      {fields.map((f) => (
        <label key={f.key} className={cx('flex flex-col gap-1 text-xs font-medium text-muted', f.kind === 'list' && 'sm:col-span-2 xl:col-span-3')}>
          <span className="flex items-center gap-1">{f.label}{f.help && <HelpTip text={f.help} />}</span>
          {f.kind === 'list'
            ? <input className={inputCls} value={((values[f.key] ?? []) as (string | number)[]).join(', ')} onChange={(e) => onChange(f.key, e.target.value.split(',').map((x) => x.trim()).filter(Boolean))} />
            : <input className={cx(inputCls, 'num')} type="number" step={f.step ?? 1} value={values[f.key] as number} onChange={(e) => onChange(f.key, Number(e.target.value))} />}
        </label>
      ))}
    </div>
  )
}

export default function SettingsPage() {
  const { health, notify, refresh } = useApp()
  const { data, error, loading, reload } = useAsync(() => api.settings(), [])
  const [s, setS] = useState<AnalysisSettings | null>(null)
  const [saving, setSaving] = useState(false)
  const [errors, setErrors] = useState<string | null>(null)
  const [llm, setLlm] = useState<LlmStatus | null>(null)
  const [testing, setTesting] = useState(false)
  useEffect(() => { if (data) setS(structuredClone(data)) }, [data])
  if (loading && !s) return <Spinner />
  if (error) return <ErrorState error={error} onRetry={reload} />
  if (!s) return null
  const dirty = JSON.stringify(s) !== JSON.stringify(data)
  const set = <K extends keyof AnalysisSettings>(section: K, key: string, v: unknown) =>
    setS((cur) => cur && ({ ...cur, [section]: { ...cur[section], [key]: v } }))

  const test = async () => {
    setTesting(true)
    try { setLlm(await api.llmStatus(s.llm.ollama_base_url)) } catch (e) { notify('error', (e as Error).message) } finally { setTesting(false) }
  }
  const save = async () => {
    setSaving(true)
    setErrors(null)
    try {
      const saved = await api.saveSettings(s)
      setS(saved)
      setDisplayTimezone(saved.display.timezone)
      notify('success', 'Settings saved. Re-run correlation to apply analysis changes.')
      reload()
      refresh()
    } catch (e) { setErrors((e as Error).message); notify('error', 'Settings not saved – see validation errors') } finally { setSaving(false) }
  }
  const modelOptions = llm?.models.map((m) => m.name) ?? health?.llm.models ?? []

  return (
    <div className="space-y-4">
      <PageHeader eyebrow="Configure" title="Settings" subtitle="Validated before saving. Analysis changes apply on the next correlation run."
        actions={<>
          <Button onClick={async () => { if (!window.confirm('Reset all settings to defaults?')) return; await api.resetSettings(); reload(); refresh(); notify('info', 'Defaults restored') }}><RotateCcw size={14} aria-hidden />Defaults</Button>
          <Button variant="primary" disabled={!dirty || saving} onClick={save}><Save size={14} aria-hidden />{saving ? 'Saving…' : 'Save settings'}</Button>
        </>} />
      {errors && <div role="alert" className="rounded-lg border border-rose-500/40 bg-rose-500/10 p-3 text-sm text-rose-700">{errors}</div>}
      <Card title="System status" subtitle="Live health of the services this dashboard depends on.">
        <div className="flex flex-wrap gap-6 text-sm">
          {[['Backend API', !!health?.backend], ['Database', !!health?.database], ['Local LLM (Ollama)', !!health?.llm.available]].map(([l, ok]) => (
            <span key={String(l)} className="flex items-center gap-2 rounded-xl bg-ink-800 px-3 py-2">{ok ? <CheckCircle2 size={16} className="text-emerald-600" aria-hidden /> : <XCircle size={16} className="text-rose-600" aria-hidden />}{l}: {ok ? 'available' : 'unavailable'}</span>
          ))}
          <span className="text-muted">App v{health?.app_version}</span>
        </div>
        {health && !health.llm.available && <p className="mt-2 text-xs text-muted">The platform remains fully usable without Ollama: summaries fall back to the deterministic template. {health.llm.error}</p>}
      </Card>

      <Card title="Local LLM assistance" subtitle="Ollama only – no cloud APIs. Model names are configurable and checked against what is installed.">
        <div className="space-y-4">
          <fieldset className="flex flex-wrap gap-3">
            <legend className="mb-1 text-xs text-muted">AI operating mode</legend>
            {([['off', 'AI Off', 'deterministic templates only'], ['cached', 'Cached', 'reuse summaries while evidence is unchanged'], ['live', 'Live local AI', 'request new summaries from Ollama']] as const).map(([v, l, d]) => (
              <label key={v} className={cx('flex cursor-pointer items-start gap-2 rounded-xl border px-4 py-3 text-sm transition', s.llm.mode === v ? 'border-sky-400 bg-sky-50 ring-1 ring-sky-300' : 'border-ink-600 bg-white hover:border-sky-200')}>
                <input type="radio" name="mode" checked={s.llm.mode === v} onChange={() => set('llm', 'mode', v)} className="mt-1" />
                <span><b>{l}</b><span className="block text-xs text-muted">{d}</span></span>
              </label>
            ))}
          </fieldset>
          <div className="flex flex-wrap items-end gap-3">
            <label className="flex flex-1 flex-col gap-1 text-xs text-muted">Ollama base URL<input className={inputCls} value={s.llm.ollama_base_url} onChange={(e) => set('llm', 'ollama_base_url', e.target.value)} /></label>
            <Button onClick={test} disabled={testing}><PlugZap size={14} aria-hidden />{testing ? 'Checking…' : 'Test connection & discover models'}</Button>
          </div>
          {llm && (
            <div className={cx('rounded-lg border p-3 text-xs', llm.available ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-rose-500/30 bg-rose-500/5')}>
              {llm.available ? <>
                <div className="text-emerald-700">Connected to Ollama {llm.version} — {llm.models.length} model(s) installed.</div>
                <ul className="mono mt-1 text-muted">{llm.models.map((m) => <li key={m.name}>{m.name} {m.parameter_size && `· ${m.parameter_size}`} {m.quantization && `· ${m.quantization}`}</li>)}</ul>
                {!llm.primary_installed && <div className="mt-1 text-amber-700">Primary model “{llm.configured.primary}” is not installed: run <span className="mono">ollama pull {llm.configured.primary}</span></div>}
                {!llm.secondary_installed && <div className="text-amber-700">Secondary model “{llm.configured.secondary}” is not installed.</div>}
              </> : <div className="text-rose-700">{llm.error}</div>}
            </div>
          )}
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {(['primary_model', 'secondary_model'] as const).map((k) => (
              <label key={k} className="flex flex-col gap-1 text-xs text-muted">{k === 'primary_model' ? 'Primary model (e.g. Qwen)' : 'Secondary model (e.g. DeepSeek)'}
                <input className={inputCls} list="model-list" value={s.llm[k]} onChange={(e) => set('llm', k, e.target.value)} />
              </label>
            ))}
            <datalist id="model-list">{modelOptions.map((m) => <option key={m} value={m} />)}</datalist>
            <label className="flex flex-col gap-1 text-xs text-muted">Timeout (s)<input className={inputCls} type="number" value={s.llm.timeout_seconds} onChange={(e) => set('llm', 'timeout_seconds', Number(e.target.value))} /></label>
            <label className="flex flex-col gap-1 text-xs text-muted">Repair retries<input className={inputCls} type="number" min={0} max={3} value={s.llm.max_retries} onChange={(e) => set('llm', 'max_retries', Number(e.target.value))} /></label>
            <label className="flex flex-col gap-1 text-xs text-muted">Temperature<input className={inputCls} type="number" step={0.05} value={s.llm.temperature} onChange={(e) => set('llm', 'temperature', Number(e.target.value))} /></label>
            <label className="flex flex-col gap-1 text-xs text-muted">Max events per prompt<input className={inputCls} type="number" value={s.llm.max_events_in_prompt} onChange={(e) => set('llm', 'max_events_in_prompt', Number(e.target.value))} /></label>
          </div>
          <p className="text-xs text-faint">Summary cache: in Cached mode a stored summary is reused only while the incident's evidence hash is unchanged; otherwise a deterministic summary is shown until a live summary is requested.</p>
        </div>
      </Card>

      <Card title="Correlation" subtitle="Conservative defaults. Raising the threshold or lowering the window produces smaller, stricter incidents.">
        <NumGrid fields={CORR} values={s.correlation} onChange={(k, v) => set('correlation', k, v)} />
      </Card>
      <Card title="Behaviour detectors"><NumGrid fields={DETECT} values={s.correlation} onChange={(k, v) => set('correlation', k, v)} /></Card>
      <Card title="Risk scoring" subtitle="Weights are normalised so the maximum score is 100. Thresholds must satisfy critical > high > medium > low.">
        <NumGrid fields={RISK} values={s.risk} onChange={(k, v) => set('risk', k, v)} />
      </Card>
      <Card title="Display, ATT&CK and privacy">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <label className="flex flex-col gap-1 text-xs text-muted">Display timezone
            <input className={inputCls} list="tz-list" value={s.display.timezone} onChange={(e) => set('display', 'timezone', e.target.value)} />
            <datalist id="tz-list">{TIMEZONES.map((t) => <option key={t} value={t} />)}</datalist>
          </label>
          <label className="flex flex-col gap-1 text-xs text-muted">ATT&CK dataset version<input className={cx(inputCls, 'opacity-70')} readOnly value={s.display.attack_version} title="Bundled local catalog (data/mappings/attack_catalog.json)" /></label>
          <label className="flex items-center gap-2 pt-5 text-xs text-muted"><input type="checkbox" checked={s.display.retain_raw_payload} onChange={(e) => set('display', 'retain_raw_payload', e.target.checked)} />Retain full raw payloads on import</label>
          <label className="flex flex-col gap-1 text-xs text-muted">Max raw payload characters<input className={inputCls} type="number" value={s.display.max_raw_payload_chars} onChange={(e) => set('display', 'max_raw_payload_chars', Number(e.target.value))} /></label>
        </div>
        <p className="mt-3 text-xs text-faint">Timestamps are stored in UTC and rendered in the display timezone with its label. Uploaded records are never sent to third-party services.</p>
      </Card>
    </div>
  )
}
