import { CheckCircle2, DatabaseZap, FileJson, FileSpreadsheet, Layers, Loader2 } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api/client'
import type { TaskStatus, UwfInfo } from '../api/types'
import { useApp } from '../lib/app-context'
import { fmtBytes, fmtDuration, fmtInt } from '../lib/format'
import { Button, cx, ProgressBar } from './ui'

export const ALL_PARTS = ['2025', '2024', 'ait']

/** Plain-language name of a selection of bundled parts. */
export function partsLabel(parts: string[]) {
  const uwf = parts.filter((p) => p !== 'ait')
  const ait = parts.includes('ait')
  if (ait && uwf.length === 2) return 'hybrid dataset (UWF + AIT)'
  if (ait && uwf.length === 1) return `hybrid dataset (UWF ${uwf[0]} + AIT)`
  if (ait) return 'AIT-ADS alerts'
  if (uwf.length === 2) return 'full UWF dataset'
  return uwf.length ? `UWF ${uwf[0]} capture` : 'dataset'
}

/** Starts / resumes the bundled dataset import task and polls it until it finishes. */
export function useUwfImport() {
  const { refresh, notify } = useApp()
  const [task, setTask] = useState<TaskStatus | null>(null)
  const timer = useRef<ReturnType<typeof setInterval> | null>(null)

  const stop = () => { if (timer.current) { clearInterval(timer.current); timer.current = null } }
  const poll = useCallback((id: string) => {
    stop()
    timer.current = setInterval(async () => {
      try {
        const t = await api.task(id)
        setTask(t)
        if (t.status !== 'running') {
          stop()
          if (t.status === 'completed' && t.result) {
            const c = t.result.correlation
            notify('success', `${t.result.dataset?.name ?? 'Dataset'} ready: ${c.n_events.toLocaleString()} events → ${c.n_incidents.toLocaleString()} incidents`)
            if (t.result.settings_changed) notify('info', t.result.settings_changed)
          } else notify('error', t.error ?? 'Import failed')
          refresh()
        }
      } catch (e) { stop(); notify('error', (e as Error).message); setTask(null) }
    }, 1000)
  }, [notify, refresh])

  useEffect(() => stop, [])

  const start = async (parts: string[]) => {
    try {
      const t = await api.loadUwf(parts)
      setTask(t)
      poll(t.id)
    } catch (e) { notify('error', (e as Error).message) }
  }
  const resume = useCallback((t: TaskStatus) => { setTask(t); poll(t.id) }, [poll])
  return { task, running: task?.status === 'running', start, resume }
}

export function TaskProgress({ task }: { task: TaskStatus }) {
  return (
    <div role="status" className="space-y-2 rounded-xl border border-sky-200 bg-sky-50/60 p-3">
      <div className="flex items-center justify-between gap-3 text-xs">
        <span className="flex items-center gap-2 font-medium text-sky-800">
          {task.status === 'running' ? <Loader2 size={14} className="animate-spin" aria-hidden /> : <CheckCircle2 size={14} aria-hidden />}
          {task.status === 'running' ? task.message : task.status === 'completed' ? 'Import complete' : `Failed: ${task.error}`}
        </span>
        <span className="num text-faint">{Math.round(task.progress * 100)}% · {task.elapsed_s.toFixed(0)} s</span>
      </div>
      <ProgressBar value={task.progress} />
    </div>
  )
}

/** Compact one-click import (used on empty states). */
export function UwfImportButton({ label = 'Import hybrid dataset (UWF + AIT)', parts = ALL_PARTS }: { label?: string; parts?: string[] }) {
  const { task, running, start } = useUwfImport()
  return (
    <div className="flex w-full max-w-md flex-col items-center gap-3">
      <Button variant="primary" disabled={running} onClick={() => start(parts)}>
        {running ? <Loader2 size={14} className="animate-spin" aria-hidden /> : <DatabaseZap size={14} aria-hidden />}
        {running ? 'Importing & correlating…' : label}
      </Button>
      {task && <div className="w-full text-left"><TaskProgress task={task} /></div>}
    </div>
  )
}

/** Full import panel with part selection (Ingestion page). */
export function UwfImportPanel() {
  const { version } = useApp()
  const [info, setInfo] = useState<UwfInfo | null>(null)
  const [parts, setParts] = useState<string[]>(ALL_PARTS)
  const { task, running, start, resume } = useUwfImport()

  useEffect(() => {
    api.uwfInfo().then((i) => { setInfo(i); if (i.running_task) resume(i.running_task) }, () => setInfo(null))
  }, [version, resume])

  const toggle = (p: string) => setParts((cur) => cur.includes(p) ? cur.filter((x) => x !== p) : [...cur, p])
  const res = task?.status === 'completed' ? task.result : null

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="font-medium text-muted">Presets:</span>
        {[{ l: 'Hybrid (all)', p: ALL_PARTS }, { l: 'UWF only', p: ['2025', '2024'] }, { l: 'AIT only', p: ['ait'] }].map((x) => {
          const on = x.p.length === parts.length && x.p.every((v) => parts.includes(v))
          return (
            <button key={x.l} type="button" disabled={running} onClick={() => setParts(x.p)} aria-pressed={on}
              className={cx('rounded-full px-3 py-1 font-semibold ring-1 transition', on ? 'bg-espresso-900 text-sky-200 ring-espresso-900' : 'bg-white text-muted ring-ink-600 hover:ring-sky-300')}>
              {x.l}
            </button>
          )
        })}
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        {info?.parts.map((p) => {
          const on = parts.includes(p.id)
          return (
            <label key={p.id} className={cx('flex cursor-pointer flex-col gap-2 rounded-2xl border p-4 transition-all',
              on ? 'border-sky-400 bg-sky-50/70 ring-1 ring-sky-300' : 'border-ink-700 bg-white hover:border-sky-300')}>
              <div className="flex items-start gap-3">
                <input type="checkbox" className="mt-1 accent-[#8f6a10]" checked={on} onChange={() => toggle(p.id)} disabled={running} />
                <div className="min-w-0 flex-1">
                  <div className="font-display text-sm font-bold text-fg">{p.label}</div>
                  <div className="mt-0.5 text-xs leading-relaxed text-muted">{p.description}</div>
                </div>
                <span className="num shrink-0 rounded-full bg-white px-2 py-0.5 text-[11px] font-semibold text-sky-800 ring-1 ring-sky-200">{fmtBytes(p.bytes)}</span>
              </div>
              <div className="flex flex-wrap gap-1 pl-7">
                {p.files.map((f) => (
                  <span key={f.name} className="mono inline-flex items-center gap-1 rounded-md bg-white/80 px-1.5 py-0.5 text-[10px] text-muted ring-1 ring-ink-700">
                    {f.name.endsWith('.csv') ? <FileSpreadsheet size={10} aria-hidden /> : <FileJson size={10} aria-hidden />}
                    {f.name.replace(/^\d{4}_/, '').replace('.csv', '').replace('.jsonl.gz', '')}
                  </span>
                ))}
              </div>
            </label>
          )
        })}
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="primary" disabled={running || parts.length === 0 || !info} onClick={() => start(parts)}>
          {running ? <Loader2 size={14} className="animate-spin" aria-hidden /> : <DatabaseZap size={14} aria-hidden />}
          {running ? 'Importing…' : `Import ${partsLabel(parts)}`}
        </Button>
        <span className="text-xs text-faint">
          Selected parts become <b>one</b> dataset. Runs in the background (≈2–5 min for the hybrid set). Re-importing replaces the previous copy. Labels are kept apart for evaluation only.
        </span>
      </div>
      {task && <TaskProgress task={task} />}
      {res && (
        <div className="grid gap-2 rounded-xl border border-emerald-200 bg-emerald-50/60 p-3 text-xs text-emerald-800 sm:grid-cols-4">
          <div><div className="text-emerald-700/70">Events</div><div className="num text-base font-bold">{fmtInt(res.correlation.n_events)}</div></div>
          <div><div className="text-emerald-700/70">Signal events</div><div className="num text-base font-bold">{fmtInt(res.correlation.n_signal_events)}</div></div>
          <div><div className="text-emerald-700/70">Incidents</div><div className="num text-base font-bold">{fmtInt(res.correlation.n_incidents)}</div></div>
          <div><div className="text-emerald-700/70">Correlation time</div><div className="num text-base font-bold">{fmtDuration(res.correlation.duration_ms)}</div></div>
        </div>
      )}
      {info?.ait && parts.includes('ait') && (
        <p className="flex items-start gap-2 rounded-xl bg-ink-800/60 p-3 text-xs text-muted ring-1 ring-ink-700">
          <Layers size={14} className="mt-0.5 shrink-0 text-sky-700" aria-hidden />
          <span>AIT-ADS is bundled as a balanced subset: {fmtInt(info.ait.kept_total)} of {fmtInt(info.ait.original_total)} alerts. Every rare alert type is kept; large repetitive floods (e.g. 1.6 M identical “Web server 400 error” alerts from dirb) are thinned evenly over time. Source: {info.ait.source}.</span>
        </p>
      )}
      {info && info.loaded.length > 0 && (
        <p className="text-xs text-muted">Already imported: {info.loaded.map((d) => `${d.name} (${d.event_count.toLocaleString()} events)`).join(' · ')}</p>
      )}
    </div>
  )
}
