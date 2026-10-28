import {
  BarChart3, ChevronDown, Database, FileDown, FlaskConical, LayoutDashboard, ListTree, Menu, PieChart, Settings,
  ShieldAlert, Upload, X,
} from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { NavLink, useLocation, useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import { cx } from '../components/ui'
import { useApp } from '../lib/app-context'

const NAV_GROUPS = [
  {
    label: 'Monitor', items: [
      { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
      { to: '/dataset', label: 'Dataset insights', icon: PieChart },
      { to: '/incidents', label: 'Incidents', icon: ShieldAlert },
      { to: '/events', label: 'Raw events', icon: ListTree },
      { to: '/attack', label: 'ATT&CK matrix', icon: BarChart3 },
    ],
  },
  {
    label: 'Analyse', items: [
      { to: '/evaluation', label: 'Evaluation lab', icon: FlaskConical },
      { to: '/reports', label: 'Reports', icon: FileDown },
    ],
  },
  {
    label: 'Configure', items: [
      { to: '/ingestion', label: 'Data ingestion', icon: Upload },
      { to: '/settings', label: 'Settings', icon: Settings },
    ],
  },
]
const TITLES: Record<string, string> = Object.fromEntries(NAV_GROUPS.flatMap((g) => g.items.map((i) => [i.to, i.label])))

function Logo() {
  return (
    <svg viewBox="0 0 32 32" className="h-9 w-9" aria-hidden>
      <defs>
        <linearGradient id="lg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#ebcb5b" /><stop offset="0.55" stopColor="#c9a227" /><stop offset="1" stopColor="#8f6a10" />
        </linearGradient>
      </defs>
      <rect width="32" height="32" rx="9" fill="url(#lg)" />
      <circle cx="14" cy="14" r="6.5" fill="none" stroke="#1f1a0e" strokeWidth="2.4" />
      <path d="M19 19 L24.5 24.5" stroke="#1f1a0e" strokeWidth="2.8" strokeLinecap="round" />
      <path d="M10.5 14.5 L12.5 14.5 L13.5 11.5 L15 17 L16 14.5 L17.5 14.5" fill="none" stroke="#1f1a0e" strokeWidth="1.4" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  )
}

function StatusDot({ ok, label }: { ok: boolean | null; label: string }) {
  return (
    <span title={label} className="inline-flex items-center gap-1.5 rounded-full bg-white/80 px-2.5 py-1 text-[11px] font-medium text-muted ring-1 ring-ink-600">
      <span className="relative flex h-2 w-2">
        {ok && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />}
        <span className={cx('relative inline-flex h-2 w-2 rounded-full', ok === null ? 'bg-slate-400' : ok ? 'bg-emerald-500' : 'bg-rose-500')} />
      </span>
      {label}
    </span>
  )
}

export function Shell({ children }: { children: ReactNode }) {
  const { health, healthError, dataset, datasets, refresh, notify, toasts, dismiss } = useApp()
  const [open, setOpen] = useState(false)
  const nav = useNavigate()
  const loc = useLocation()
  const mode = health?.llm.mode ?? 'cached'
  const pageTitle = loc.pathname.startsWith('/incidents/') ? 'Incident' : TITLES[loc.pathname] ?? 'ThreatLens'

  const sidebar = (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-3 px-5 pb-6 pt-5">
        <Logo />
        <div className="leading-tight">
          <div className="font-display text-[17px] font-bold tracking-tight text-white">ThreatLens</div>
          <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-sky-300/80">Threat correlation</div>
        </div>
      </div>
      <nav aria-label="Main" className="flex flex-1 flex-col gap-5 overflow-y-auto px-3 pb-4">
        {NAV_GROUPS.map((g) => (
          <div key={g.label}>
            <div className="mb-1.5 px-3 text-[10px] font-semibold uppercase tracking-[0.16em] text-ink-500/70">{g.label}</div>
            <div className="flex flex-col gap-0.5">
              {g.items.map(({ to, label, icon: Icon, end }) => (
                <NavLink key={to} to={to} end={end} onClick={() => setOpen(false)}
                  className={({ isActive }) => cx('group relative flex items-center gap-3 rounded-xl px-3 py-2 text-[13px] font-medium transition-all',
                    isActive ? 'bg-gradient-to-r from-sky-500/25 to-sky-500/5 text-white' : 'text-ink-600/90 hover:bg-white/5 hover:text-white')}>
                  {({ isActive }) => (<>
                    {isActive && <span className="absolute left-0 top-1/2 h-5 w-1 -translate-y-1/2 rounded-r-full bg-sky-400" aria-hidden />}
                    <Icon size={17} aria-hidden className={cx(isActive ? 'text-sky-300' : 'text-ink-500 group-hover:text-sky-300')} />{label}
                  </>)}
                </NavLink>
              ))}
            </div>
          </div>
        ))}
      </nav>
      <div className="m-3 rounded-2xl border border-white/10 bg-white/5 p-3">
        <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-sky-300/90"><Database size={13} aria-hidden />Active dataset</div>
        <div className="mt-1 truncate text-sm font-semibold text-white" title={dataset?.name}>{dataset?.name ?? 'None loaded'}</div>
        <div className="num text-[11px] text-ink-500">{dataset ? `${dataset.event_count.toLocaleString()} events${dataset.has_labels ? ' · labelled' : ''}` : 'Import data to begin'}</div>
      </div>
    </div>
  )

  return (
    <div className="flex h-full">
      <aside className="sidebar-surface hidden w-64 shrink-0 lg:block">{sidebar}</aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="glass sticky top-0 z-30 border-b border-ink-700/70">
          <div className="flex flex-wrap items-center gap-3 px-4 py-3 sm:px-6">
            <button className="-ml-1 rounded-lg p-2 text-muted hover:bg-sky-50 lg:hidden" onClick={() => setOpen(true)} aria-label="Open menu"><Menu size={20} /></button>
            <div className="min-w-0">
              <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-faint">ThreatLens</div>
              <div className="font-display text-[15px] font-bold leading-tight text-fg">{pageTitle}</div>
            </div>
            <div className="ml-2 hidden h-8 w-px bg-ink-700 sm:block" />
            <label className="sr-only" htmlFor="ds-select">Active dataset</label>
            <div className="relative">
              <Database size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-sky-700" aria-hidden />
              <select id="ds-select" value={dataset?.id ?? ''} onChange={async (e) => {
                try { await api.activateDataset(Number(e.target.value)); refresh(); notify('info', 'Dataset switched') } catch (err) { notify('error', (err as Error).message) }
              }} className="max-w-[18rem] appearance-none truncate rounded-xl border-0 bg-white py-2 pl-8 pr-8 text-xs font-semibold text-fg shadow-sm ring-1 ring-ink-600 focus:ring-2 focus:ring-sky-400">
                {!dataset && <option value="">No dataset loaded</option>}
                {datasets.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
              </select>
              <ChevronDown size={14} className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-faint" aria-hidden />
            </div>
            {dataset && <span className="num hidden text-xs text-faint md:inline">{dataset.event_count.toLocaleString()} events</span>}
            {!dataset && <button onClick={() => nav('/ingestion')} className="gold-gradient rounded-xl px-3 py-1.5 text-xs font-semibold text-white shadow-[var(--shadow-gold)]">Load data</button>}
            <div className="ml-auto flex flex-wrap items-center gap-1.5">
              <StatusDot ok={healthError ? false : health ? health.database : null} label={healthError ? 'API offline' : 'Database'} />
              <StatusDot ok={health ? health.llm.available : null} label="Ollama" />
              <span className="rounded-full bg-espresso-900 px-2.5 py-1 text-[11px] font-semibold text-sky-200">AI · {mode === 'off' ? 'Off' : mode === 'cached' ? 'Cached' : 'Live'}</span>
            </div>
          </div>
        </header>

        {open && (
          <div className="fixed inset-0 z-40 lg:hidden">
            <button aria-label="Close menu" className="absolute inset-0 bg-espresso-950/50" onClick={() => setOpen(false)} />
            <div className="sidebar-surface relative h-full w-72 shadow-2xl">
              <button className="absolute right-3 top-4 rounded-lg p-1.5 text-ink-500 hover:bg-white/10" onClick={() => setOpen(false)} aria-label="Close menu"><X size={18} /></button>
              {sidebar}
            </div>
          </div>
        )}

        <main className="min-w-0 flex-1 overflow-y-auto">
          {healthError && (
            <div role="alert" className="border-b border-rose-200 bg-rose-50 px-6 py-2 text-xs text-rose-700">{healthError}</div>
          )}
          <div key={loc.pathname} className="mx-auto max-w-[1480px] px-4 py-7 sm:px-8">{children}</div>
        </main>
      </div>

      <div aria-live="polite" className="pointer-events-none fixed bottom-5 right-5 z-[60] flex w-[22rem] flex-col gap-2">
        {toasts.map((t) => (
          <div key={t.id} className={cx('pointer-events-auto flex items-start gap-3 rounded-2xl border px-4 py-3 text-sm shadow-[var(--shadow-lift)] animate-fade-up',
            t.kind === 'success' ? 'border-emerald-200 bg-white text-emerald-800' : t.kind === 'error' ? 'border-rose-200 bg-white text-rose-800' : 'border-sky-200 bg-white text-fg')}>
            <span className={cx('mt-1.5 h-2 w-2 shrink-0 rounded-full', t.kind === 'success' ? 'bg-emerald-500' : t.kind === 'error' ? 'bg-rose-500' : 'bg-sky-500')} aria-hidden />
            <span className="flex-1">{t.text}</span>
            <button onClick={() => dismiss(t.id)} aria-label="Dismiss" className="text-faint hover:text-fg"><X size={14} /></button>
          </div>
        ))}
      </div>
    </div>
  )
}
