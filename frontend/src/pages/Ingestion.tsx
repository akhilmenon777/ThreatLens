import { CheckCircle2, DatabaseZap, FileUp, Layers, Plus, Trash2, UploadCloud, X } from 'lucide-react'
import { useRef, useState } from 'react'
import { api } from '../api/client'
import type { Job } from '../api/types'
import { LoadDemoButton } from '../components/NoDataset'
import { Button, Card, cx, Drawer, inputCls, PageHeader, ProgressBar, Spinner } from '../components/ui'
import { UwfImportPanel } from '../components/UwfImport'
import { useApp } from '../lib/app-context'
import { fmtBytes, fmtDuration, fmtInt, fmtTime } from '../lib/format'
import { useAsync } from '../lib/hooks'

function RejectedDrawer({ job, onClose }: { job: Job | null; onClose: () => void }) {
  const { data, loading } = useAsync(() => (job ? api.rejected(job.id) : Promise.resolve([])), [job?.id])
  return (
    <Drawer open={!!job} onClose={onClose} wide title={job && `Rejected records — ${job.filename}`}>
      {loading ? <Spinner /> : data && data.length === 0 ? <p className="text-sm text-muted">No rejected records.</p> : (
        <ul className="space-y-2">
          {data?.map((r) => (
            <li key={r.line_number} className="rounded-xl border border-ink-700 bg-white p-3 text-xs">
              <div className="flex gap-2"><span className="num text-faint">line {r.line_number}</span><span className="text-rose-700">{r.reason}</span></div>
              <pre className="mono mt-1 overflow-x-auto whitespace-pre-wrap break-all text-[11px] text-muted">{r.raw_excerpt}</pre>
            </li>
          ))}
        </ul>
      )}
    </Drawer>
  )
}

const STATUS_STYLE: Record<string, string> = {
  completed: 'bg-emerald-50 text-emerald-700 ring-emerald-200', failed: 'bg-rose-50 text-rose-700 ring-rose-200',
  empty: 'bg-slate-50 text-slate-600 ring-slate-200', running: 'bg-sky-50 text-sky-800 ring-sky-200',
}

export default function IngestionPage() {
  const { version, refresh, notify, dataset, datasets } = useApp()
  const jobs = useAsync(() => api.jobs().catch(() => [] as Job[]), [version])
  const schema = useAsync(() => api.schema(), [])
  const [files, setFiles] = useState<File[]>([])
  const [sensor, setSensor] = useState('auto')
  const [correlate, setCorrelate] = useState(true)
  const [busy, setBusy] = useState(false)
  const [progress, setProgress] = useState<{ i: number; n: number; text: string } | null>(null)
  const [results, setResults] = useState<string[]>([])
  const [rejectedFor, setRejectedFor] = useState<Job | null>(null)
  const [newName, setNewName] = useState('')
  const [drag, setDrag] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)
  const maxMb = schema.data?.max_upload_mb ?? 50

  const addFiles = (list: FileList | null) => {
    if (!list) return
    setFiles((cur) => [...cur, ...Array.from(list).filter((f) => !cur.some((c) => c.name === f.name && c.size === f.size))])
  }

  const upload = async () => {
    if (!files.length) return
    const tooBig = files.find((f) => f.size > maxMb * 1024 * 1024)
    if (tooBig) { notify('error', `${tooBig.name} is larger than the ${maxMb} MB limit`); return }
    setBusy(true)
    setResults([])
    const out: string[] = []
    try {
      for (let i = 0; i < files.length; i++) {
        const f = files[i]
        const last = i === files.length - 1
        setProgress({ i, n: files.length, text: `Uploading and parsing ${f.name} (${fmtBytes(f.size)})${last && correlate ? ' and correlating' : ''}…` })
        // correlate once, after the last file, so a multi-file import is analysed as a whole
        const r = await api.upload(f, sensor, correlate && last)
        const j = r.job
        out.push(`${j.filename}: ${fmtInt(j.accepted)} accepted, ${fmtInt(j.rejected)} rejected, ${fmtInt(j.duplicates)} duplicates` +
          (r.correlation ? ` · correlation: ${fmtInt(r.correlation.n_incidents)} incidents from ${fmtInt(r.correlation.n_events)} events in ${fmtDuration(r.correlation.duration_ms)}` : ''))
        setResults([...out])
        if (r.decode_warning) notify('info', `${f.name}: ${r.decode_warning}`)
      }
      notify('success', `Imported ${files.length} file${files.length > 1 ? 's' : ''}`)
      setFiles([])
      if (inputRef.current) inputRef.current.value = ''
      refresh()
    } catch (e) { notify('error', (e as Error).message); refresh() } finally { setBusy(false); setProgress(null) }
  }

  return (
    <div className="space-y-5">
      <PageHeader eyebrow="Configure" title="Data ingestion" subtitle="Import the bundled hybrid dataset (UWF-ZeekData24 + AIT-ADS), the synthetic demo, or your own Suricata / Zeek / Wazuh / AMiner / UWF CSV files." />

      <Card icon={<DatabaseZap size={15} />} title="Bundled datasets — UWF-ZeekData24 + AIT-ADS"
        subtitle="Network layer: real Zeek conn logs from the University of West Florida cyber range (ATT&CK-labelled). Host / IDS layer: Wazuh, Suricata and AMiner alerts from the AIT testbed (attack-phase labels). Select any combination – it is imported as ONE dataset.">
        <UwfImportPanel />
      </Card>

      <div className="grid gap-5 xl:grid-cols-[1.4fr_1fr]">
        <Card icon={<UploadCloud size={15} />} title="Upload files" subtitle={`Into the active dataset (${dataset?.name ?? 'a new dataset will be created'}). Max ${maxMb} MB per file; parsed in memory, never executed.`}>
          <div className="space-y-4">
            <label className={cx('flex cursor-pointer flex-col items-center gap-2 rounded-2xl border-2 border-dashed px-4 py-8 text-center text-sm transition',
              drag ? 'border-sky-400 bg-sky-50' : 'border-ink-600 bg-ink-900/60 hover:border-sky-300 hover:bg-sky-50/40')}
              onDragOver={(e) => { e.preventDefault(); setDrag(true) }} onDragLeave={() => setDrag(false)}
              onDrop={(e) => { e.preventDefault(); setDrag(false); addFiles(e.dataTransfer.files) }}>
              <div className="grid h-12 w-12 place-items-center rounded-2xl bg-white text-sky-700 shadow-sm ring-1 ring-ink-700"><FileUp size={22} aria-hidden /></div>
              <span className="font-medium text-fg">Drop files here or click to choose</span>
              <span className="text-xs text-faint">Suricata eve.json · Zeek conn/dns/http/ssl/ssh/notice/files (JSON or TSV) · UWF-ZeekData .csv parts · AIT-ADS *_wazuh.json / *_aminer.json — several files at once</span>
              <input ref={inputRef} type="file" multiple className="sr-only" accept=".json,.log,.txt,.tsv,.ndjson,.csv" onChange={(e) => addFiles(e.target.files)} />
            </label>
            {files.length > 0 && (
              <ul className="divide-y divide-ink-700 rounded-xl border border-ink-700 bg-white">
                {files.map((f, i) => (
                  <li key={f.name + f.size} className="flex items-center gap-3 px-3 py-2 text-xs">
                    {progress && progress.i > i ? <CheckCircle2 size={14} className="text-emerald-600" aria-hidden /> : <Layers size={14} className="text-faint" aria-hidden />}
                    <span className="mono min-w-0 flex-1 truncate">{f.name}</span>
                    <span className="num text-faint">{fmtBytes(f.size)}</span>
                    {!busy && <button aria-label={`Remove ${f.name}`} onClick={() => setFiles((c) => c.filter((x) => x !== f))} className="text-faint hover:text-rose-600"><X size={14} /></button>}
                  </li>
                ))}
              </ul>
            )}
            <div className="flex flex-wrap items-end gap-3">
              <label className="flex flex-col gap-1 text-xs font-medium text-muted">Format
                <select value={sensor} onChange={(e) => setSensor(e.target.value)} className={inputCls}>
                  <option value="auto">Auto-detect</option><option value="suricata">Suricata EVE JSON</option><option value="zeek">Zeek (JSON or TSV)</option><option value="uwf">UWF-ZeekData CSV</option><option value="ait">AIT-ADS alerts (Wazuh / AMiner JSON)</option>
                </select></label>
              <label className="flex items-center gap-2 pb-2.5 text-xs text-muted"><input type="checkbox" className="accent-[#8f6a10]" checked={correlate} onChange={(e) => setCorrelate(e.target.checked)} />Run correlation after import</label>
              <Button variant="primary" disabled={!files.length || busy} onClick={upload}>{busy ? 'Importing…' : `Import ${files.length || ''} file${files.length === 1 ? '' : 's'}`}</Button>
            </div>
            {progress && (
              <div role="status" className="space-y-2 rounded-xl border border-sky-200 bg-sky-50/60 p-3 text-xs text-sky-800">
                <div className="flex justify-between"><span>{progress.text}</span><span className="num">{progress.i + 1} / {progress.n}</span></div>
                <ProgressBar value={(progress.i + 0.5) / progress.n} />
              </div>
            )}
            {results.length > 0 && <ul className="space-y-1 rounded-xl border border-emerald-200 bg-emerald-50/60 p-3 text-xs text-emerald-800">{results.map((r) => <li key={r}>{r}</li>)}</ul>}
          </div>
        </Card>

        <Card title="Datasets" subtitle="Each dataset is analysed independently; the active one drives every page."
          actions={<LoadDemoButton />}>
          <ul className="space-y-2">
            {datasets.map((d) => (
              <li key={d.id} className={cx('flex items-center gap-3 rounded-xl border px-3 py-2.5 text-sm transition', d.is_active ? 'border-sky-300 bg-sky-50/60' : 'border-ink-700 bg-white hover:border-sky-200')}>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2"><span className="truncate font-medium">{d.name}</span>{d.is_active && <span className="rounded-full bg-sky-600 px-2 py-0.5 text-[10px] font-semibold text-white">active</span>}</div>
                  <div className="text-xs text-faint">{fmtInt(d.event_count)} events · {d.synthetic ? 'synthetic' : d.version && /UWF|AIT/.test(d.version) ? d.version : 'uploaded'}{d.has_labels ? ' · labelled' : ''}</div>
                </div>
                {!d.is_active && <Button size="sm" onClick={async () => { try { await api.activateDataset(d.id); refresh(); notify('info', `Activated ${d.name}`) } catch (e) { notify('error', (e as Error).message) } }}>Activate</Button>}
                <Button size="sm" variant="ghost" title="Delete dataset" onClick={async () => {
                  if (!window.confirm(`Delete dataset “${d.name}” and all its events and incidents?`)) return
                  try { await api.deleteDataset(d.id); notify('success', 'Dataset deleted'); refresh() } catch (e) { notify('error', (e as Error).message) }
                }}><Trash2 size={14} aria-label="Delete" /></Button>
              </li>
            ))}
            {datasets.length === 0 && <li className="text-sm text-muted">No datasets yet.</li>}
          </ul>
          <form className="mt-4 flex gap-2" onSubmit={async (e) => {
            e.preventDefault()
            if (!newName.trim()) return
            try { await api.createDataset(newName.trim()); setNewName(''); notify('success', 'Empty dataset created and activated – upload files into it'); refresh() }
            catch (err) { notify('error', (err as Error).message) }
          }}>
            <input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="New dataset name (e.g. Lab capture 21 Oct)" aria-label="New dataset name" className={cx(inputCls, 'flex-1')} />
            <Button type="submit" disabled={!newName.trim()}><Plus size={14} aria-hidden />Create</Button>
          </form>
        </Card>
      </div>

      <Card title="Import history" subtitle={`Jobs for ${dataset?.name ?? 'the active dataset'}. Malformed records are never dropped silently.`}>
        {jobs.loading && !jobs.data ? <Spinner /> : jobs.data && jobs.data.length === 0 ? <p className="text-sm text-muted">No imports yet.</p> : (
          <div className="overflow-x-auto">
            <table className="table-modern w-full text-xs">
              <thead><tr>
                <th className="px-3 py-2 text-left">File</th><th className="px-3 text-left">Format</th><th className="px-3 text-left">Status</th>
                <th className="px-3 text-right">Records</th><th className="px-3 text-right">Accepted</th><th className="px-3 text-right">Rejected</th>
                <th className="px-3 text-right">Duplicates</th><th className="px-3 text-right">Warnings</th><th className="px-3 text-left">Finished</th><th />
              </tr></thead>
              <tbody className="divide-y divide-ink-700/60">
                {jobs.data?.map((j) => (
                  <tr key={j.id} className="hover:bg-ink-800/40">
                    <td className="mono px-3 py-2">{j.filename}</td><td className="px-3 text-muted">{j.file_format}</td>
                    <td className="px-3"><span className={cx('rounded-full px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset', STATUS_STYLE[j.status] ?? STATUS_STYLE.empty)}>{j.status}</span></td>
                    <td className="num px-3 text-right">{fmtInt(j.total_records)}</td><td className="num px-3 text-right text-emerald-700">{fmtInt(j.accepted)}</td>
                    <td className="num px-3 text-right text-rose-700">{fmtInt(j.rejected)}</td><td className="num px-3 text-right">{fmtInt(j.duplicates)}</td>
                    <td className="num px-3 text-right text-amber-700">{fmtInt(j.with_warnings)}</td><td className="px-3 text-muted">{fmtTime(j.finished_at)}</td>
                    <td className="px-3">{j.rejected > 0 && <Button size="sm" variant="ghost" onClick={() => setRejectedFor(j)}>Why rejected?</Button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title="Supported formats & common schema" subtitle={schema.data ? `Event schema v${schema.data.schema_version}` : undefined}>
        {schema.data && (
          <div className="space-y-3 text-xs">
            <div className="grid gap-3 md:grid-cols-3">
              {Object.entries(schema.data.supported_inputs).map(([k, v]) => (
                <div key={k} className="rounded-xl border border-ink-700 bg-ink-900/50 p-3"><b className="text-sm uppercase tracking-wide text-fg">{k}</b><p className="mt-1 text-muted">{v}</p></div>
              ))}
            </div>
            <details><summary className="cursor-pointer font-medium text-sky-700">Field reference ({Object.keys(schema.data.fields).length} fields)</summary>
              <dl className="mt-2 grid grid-cols-[11rem_1fr] gap-x-3 gap-y-1">
                {Object.entries(schema.data.fields).map(([k, v]) => [<dt key={k} className="mono text-sky-700">{k}</dt>, <dd key={k + 'd'} className="text-muted">{v}</dd>])}
              </dl>
            </details>
            <p className="text-faint">Unavailable values stay empty – users, hosts and DNS names are never invented. The original record is preserved for inspection.</p>
          </div>
        )}
      </Card>
      <RejectedDrawer job={rejectedFor} onClose={() => setRejectedFor(null)} />
    </div>
  )
}
