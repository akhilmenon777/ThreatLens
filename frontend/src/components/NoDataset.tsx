import { Database, Play, Upload } from 'lucide-react'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useApp } from '../lib/app-context'
import { Button, ErrorState } from './ui'
import { UwfImportButton } from './UwfImport'

export function isNoDataset(e: Error | null): boolean {
  return e instanceof ApiError && e.status === 404 && /No dataset/i.test(e.message)
}

export function LoadDemoButton({ label = 'Load synthetic demo' }: { label?: string }) {
  const { refresh, notify } = useApp()
  const [busy, setBusy] = useState(false)
  return (
    <Button disabled={busy} onClick={async () => {
      setBusy(true)
      try {
        const r = await api.loadDemo()
        notify('success', `Demo loaded: ${r.correlation.n_events.toLocaleString()} events → ${r.correlation.n_incidents} incidents`)
        refresh()
      } catch (e) {
        notify('error', (e as Error).message)
      } finally {
        setBusy(false)
      }
    }}>
      <Play size={14} aria-hidden />{busy ? 'Loading & correlating…' : label}
    </Button>
  )
}

export function DataGate({ error, onRetry }: { error: Error; onRetry: () => void }) {
  const nav = useNavigate()
  if (isNoDataset(error))
    return (
      <div className="hero-surface grid-pattern relative overflow-hidden rounded-3xl px-6 py-14 text-center text-white shadow-[var(--shadow-lift)] animate-fade-up">
        <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-white/10 ring-1 ring-white/20"><Database className="text-sky-300" aria-hidden /></div>
        <h2 className="mt-4 font-display text-2xl font-bold">No telemetry loaded yet</h2>
        <p className="mx-auto mt-2 max-w-xl text-sm text-ink-600">
          Import the bundled <b className="text-sky-200">hybrid dataset</b> — 153k labelled Zeek connections from the UWF cyber range plus
          171k Wazuh / Suricata / AMiner alerts from the AIT testbed, in one view — or load the synthetic demo / upload your own logs.
        </p>
        <div className="mt-6 flex flex-col items-center gap-3">
          <UwfImportButton />
          <div className="flex flex-wrap justify-center gap-2">
            <LoadDemoButton />
            <Button onClick={() => nav('/ingestion')}><Upload size={14} aria-hidden />Upload logs</Button>
          </div>
        </div>
      </div>
    )
  return <ErrorState error={error} onRetry={onRetry} />
}
