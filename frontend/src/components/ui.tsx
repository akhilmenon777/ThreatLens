import { AlertTriangle, CircleHelp, Eye, Inbox, Loader2, Telescope, X } from 'lucide-react'
import { useEffect, type ReactNode } from 'react'
import type { EvidenceStatus, IncidentStatus, Severity } from '../api/types'
import { STATUS_LABELS } from '../lib/format'

export function cx(...c: (string | false | null | undefined)[]) {
  return c.filter(Boolean).join(' ')
}

/** Shared Recharts tooltip look. */
export const tooltipStyle = {
  background: 'rgba(255,255,255,0.97)', border: '1px solid #ece4cd', borderRadius: 12, fontSize: 12,
  boxShadow: '0 12px 28px -10px rgba(61,52,38,0.28)', padding: '8px 12px',
}
export const CHART = {
  gold: '#c9a227', goldDark: '#8f6a10', goldLight: '#ebcb5b', espresso: '#3d3426', sand: '#ddd2b4',
  malicious: '#e11d48', benign: '#c2b48a', zeek: '#0d9488', suricata: '#7c3aed', wazuh: '#ea580c', aminer: '#db2777',
}
/** Colour and plain-language role of each telemetry source. */
export const SENSORS: Record<string, { color: string; name: string; layer: string }> = {
  zeek: { color: CHART.zeek, name: 'Zeek', layer: 'Network connections' },
  suricata: { color: CHART.suricata, name: 'Suricata', layer: 'Network IDS alerts' },
  wazuh: { color: CHART.wazuh, name: 'Wazuh', layer: 'Host / log alerts' },
  aminer: { color: CHART.aminer, name: 'AMiner', layer: 'Log anomaly detection' },
}
export const sensorColor = (s: string) => SENSORS[s]?.color ?? '#7a6f50'
/** Categorical palette for ATT&CK tactics (warm, readable on white). */
export const TACTIC_COLORS: Record<string, string> = {
  Reconnaissance: '#c9a227', 'Resource Development': '#a3a3a3', 'Initial Access': '#ea580c', Execution: '#b45309',
  Persistence: '#7c3aed', 'Privilege Escalation': '#db2777', 'Defense Evasion': '#0d9488', 'Credential Access': '#e11d48',
  Discovery: '#8f6a10', 'Lateral Movement': '#2563eb', Collection: '#65a30d', 'Command and Control': '#3d3426',
  Exfiltration: '#9f1239', Impact: '#991b1b',
}
export const tacticColor = (t: string) => TACTIC_COLORS[t] ?? '#7a6f50'

export function Card({ title, subtitle, actions, children, className, bodyClass, id, icon }: {
  title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClass?: string; id?: string; icon?: ReactNode
}) {
  return (
    <section id={id} className={cx('min-w-0 rounded-2xl border border-ink-700/80 bg-white shadow-[var(--shadow-card)] animate-fade-up', className)}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-3 px-5 pt-4 pb-1">
          <div className="flex min-w-0 items-start gap-2.5">
            {icon && <div className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-sky-50 text-sky-700 ring-1 ring-sky-200/70">{icon}</div>}
            <div className="min-w-0">
              {title && <h2 className="text-[15px] font-semibold text-fg">{title}</h2>}
              {subtitle && <p className="mt-0.5 text-xs leading-relaxed text-muted">{subtitle}</p>}
            </div>
          </div>
          {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cx('p-5', (title || actions) ? 'pt-3' : null, bodyClass)}>{children}</div>
    </section>
  )
}

const ACCENTS = {
  sky: 'from-sky-300 to-sky-600 text-white',
  blue: 'from-espresso-600 to-espresso-900 text-sky-200',
  rose: 'from-rose-400 to-rose-600 text-white',
  violet: 'from-violet-400 to-violet-600 text-white',
  teal: 'from-teal-400 to-teal-600 text-white',
  amber: 'from-amber-300 to-amber-600 text-white',
}

export function Stat({ label, value, hint, tone, icon, accent = 'sky' }: { label: string; value: ReactNode; hint?: ReactNode; tone?: string; icon?: ReactNode; accent?: keyof typeof ACCENTS }) {
  return (
    <div className="group relative flex min-w-0 items-start gap-3 overflow-hidden rounded-2xl border border-ink-700/80 bg-white px-4 py-4 shadow-[var(--shadow-card)] transition-all duration-200 hover:-translate-y-0.5 hover:shadow-[var(--shadow-lift)] animate-fade-up">
      <div className="pointer-events-none absolute -right-6 -top-6 h-20 w-20 rounded-full bg-sky-100/60 blur-2xl transition-opacity group-hover:opacity-100" />
      {icon && <div className={cx('relative grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-gradient-to-br shadow-sm', ACCENTS[accent])}>{icon}</div>}
      <div className="relative min-w-0">
        <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-faint">{label}</div>
        <div className={cx('num mt-0.5 whitespace-nowrap font-display text-[24px] font-bold leading-tight tracking-tight', tone ?? 'text-fg')}>{value}</div>
        {hint && <div className="mt-0.5 text-xs text-muted">{hint}</div>}
      </div>
    </div>
  )
}

const SEV_CLASS: Record<string, string> = {
  Critical: 'bg-rose-50 text-rose-700 ring-rose-200',
  High: 'bg-orange-50 text-orange-700 ring-orange-200',
  Medium: 'bg-yellow-50 text-yellow-800 ring-yellow-200',
  Low: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  Informational: 'bg-slate-50 text-slate-600 ring-slate-200',
}
export const SEV_COLOR: Record<string, string> = {
  Critical: '#e11d48', High: '#ea580c', Medium: '#ca8a04', Low: '#059669', Informational: '#64748b',
}

export function SeverityBadge({ severity, compact }: { severity: Severity | string; compact?: boolean }) {
  return (
    <span className={cx('inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[11px] font-semibold ring-1 ring-inset whitespace-nowrap', SEV_CLASS[severity] ?? SEV_CLASS.Informational)}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEV_COLOR[severity] ?? SEV_COLOR.Informational }} aria-hidden />
      {compact ? severity.slice(0, 4) : severity}
    </span>
  )
}

const STATUS_CLASS: Record<string, string> = {
  new: 'bg-sky-50 text-sky-800 ring-sky-200',
  in_progress: 'bg-violet-50 text-violet-700 ring-violet-200',
  escalated: 'bg-rose-50 text-rose-700 ring-rose-200',
  resolved: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  closed: 'bg-slate-50 text-slate-600 ring-slate-200',
}

export function StatusBadge({ status }: { status: IncidentStatus | string }) {
  return <span className={cx('inline-flex rounded-full px-2.5 py-0.5 text-[11px] font-medium ring-1 ring-inset whitespace-nowrap', STATUS_CLASS[status] ?? STATUS_CLASS.closed)}>{STATUS_LABELS[status] ?? status}</span>
}

/** Observed = solid with eye icon; Inferred = dashed outline with telescope icon; never colour alone. */
export function EvidenceBadge({ status, small }: { status: EvidenceStatus | string; small?: boolean }) {
  if (status === 'OBSERVED')
    return (
      <span title="Observed: directly present in the telemetry" className={cx('inline-flex items-center gap-1 rounded-full border border-observed/50 bg-observed/10 font-semibold text-espresso-800 whitespace-nowrap', small ? 'px-1.5 py-0 text-[10px]' : 'px-2.5 py-0.5 text-[11px]')}>
        <Eye size={small ? 10 : 12} aria-hidden />Observed
      </span>
    )
  if (status === 'INFERRED')
    return (
      <span title="Inferred: a hypothesis from indirect indicators" className={cx('inferred-outline inline-flex items-center gap-1 rounded-full border border-inferred/70 bg-amber-50/60 font-semibold text-amber-700 italic whitespace-nowrap', small ? 'px-1.5 py-0 text-[10px]' : 'px-2.5 py-0.5 text-[11px]')}>
        <Telescope size={small ? 10 : 12} aria-hidden />Inferred
      </span>
    )
  return (
    <span title="No supporting evidence in the telemetry" className={cx('inline-flex items-center gap-1 rounded-full border border-ink-600 text-faint whitespace-nowrap', small ? 'px-1.5 py-0 text-[10px]' : 'px-2.5 py-0.5 text-[11px]')}>
      Not observed
    </span>
  )
}

export function SensorBadge({ sensor }: { sensor: string }) {
  const known = SENSORS[sensor]
  if (!known) return <span className="inline-flex rounded-md px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-muted ring-1 ring-inset ring-ink-500">{sensor}</span>
  return (
    <span className="inline-flex rounded-md px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider ring-1 ring-inset"
      style={{ color: known.color, background: known.color + '1a', boxShadow: `inset 0 0 0 1px ${known.color}4d` }} title={known.layer}>{sensor}</span>
  )
}

export function TacticPill({ tactic, count }: { tactic: string; count?: number }) {
  const c = tacticColor(tactic)
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-medium whitespace-nowrap"
      style={{ borderColor: c + '55', background: c + '14', color: c }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: c }} aria-hidden />{tactic}{count !== undefined && <span className="num opacity-70">{count.toLocaleString()}</span>}
    </span>
  )
}

export function Chip({ children, title, className }: { children: ReactNode; title?: string; className?: string }) {
  return <span title={title} className={cx('inline-flex items-center rounded-md border border-ink-700 bg-ink-800 px-1.5 py-0.5 text-[11px] font-medium text-muted whitespace-nowrap', className)}>{children}</span>
}

export function Button({ children, onClick, variant = 'secondary', disabled, type = 'button', title, size = 'md', className }: {
  children: ReactNode; onClick?: () => void; variant?: 'primary' | 'secondary' | 'ghost' | 'danger' | 'dark'; disabled?: boolean
  type?: 'button' | 'submit'; title?: string; size?: 'sm' | 'md'; className?: string
}) {
  const v = {
    primary: 'gold-gradient text-white font-semibold shadow-[var(--shadow-gold)] hover:brightness-110 active:brightness-95',
    secondary: 'bg-white text-fg font-medium ring-1 ring-ink-600 shadow-sm hover:bg-sky-50 hover:ring-sky-300',
    ghost: 'text-muted font-medium hover:text-fg hover:bg-sky-50',
    danger: 'bg-rose-50 text-rose-700 font-medium ring-1 ring-rose-200 hover:bg-rose-100',
    dark: 'bg-espresso-900 text-sky-100 font-semibold shadow-sm hover:bg-espresso-800',
  }[variant]
  return (
    <button type={type} title={title} disabled={disabled} onClick={onClick}
      className={cx('inline-flex items-center justify-center gap-1.5 rounded-xl transition-all duration-150 disabled:cursor-not-allowed disabled:opacity-50 disabled:shadow-none',
        size === 'sm' ? 'px-3 py-1.5 text-xs' : 'px-4 py-2 text-sm', v, className)}>
      {children}
    </button>
  )
}

export function Spinner({ label = 'Loading…' }: { label?: string }) {
  return (
    <div role="status" className="flex items-center justify-center gap-2.5 py-14 text-sm text-muted">
      <Loader2 className="animate-spin text-sky-600" size={18} aria-hidden />{label}
    </div>
  )
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cx('skeleton rounded-xl', className)} aria-hidden />
}

export function ErrorState({ error, onRetry }: { error: Error | string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex flex-col items-center gap-3 rounded-2xl border border-rose-200 bg-rose-50/70 px-6 py-10 text-center">
      <div className="grid h-11 w-11 place-items-center rounded-full bg-rose-100"><AlertTriangle className="text-rose-600" size={20} aria-hidden /></div>
      <p className="max-w-lg text-sm text-rose-700">{typeof error === 'string' ? error : error.message}</p>
      {onRetry && <Button size="sm" onClick={onRetry}>Retry</Button>}
    </div>
  )
}

export function EmptyState({ title, children, icon }: { title: string; children?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-2xl border border-dashed border-ink-500/70 bg-white/70 px-6 py-14 text-center">
      <div className="grid h-12 w-12 place-items-center rounded-2xl bg-sky-50 text-sky-700 ring-1 ring-sky-200">{icon ?? <Inbox size={22} aria-hidden />}</div>
      <p className="font-display text-base font-semibold text-fg">{title}</p>
      {children && <div className="max-w-lg text-sm text-muted">{children}</div>}
    </div>
  )
}

export function HelpTip({ text }: { text: string }) {
  return (
    <span className="group relative inline-flex align-middle">
      <CircleHelp size={13} className="cursor-help text-faint group-hover:text-sky-700" aria-label={text} tabIndex={0} />
      <span role="tooltip" className="pointer-events-none absolute left-1/2 top-5 z-50 hidden w-64 -translate-x-1/2 rounded-xl bg-espresso-900 px-3 py-2 text-xs font-normal normal-case tracking-normal text-sky-50 shadow-xl group-hover:block group-focus-within:block">
        {text}
      </span>
    </span>
  )
}

export function Pagination({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 pt-3 text-xs text-muted">
      <span className="num">{total === 0 ? '0 results' : `${((page - 1) * pageSize + 1).toLocaleString()}–${Math.min(total, page * pageSize).toLocaleString()} of ${total.toLocaleString()}`}</span>
      <div className="flex items-center gap-1">
        <Button size="sm" variant="ghost" disabled={page <= 1} onClick={() => onPage(1)}>First</Button>
        <Button size="sm" variant="secondary" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</Button>
        <span className="num rounded-lg bg-ink-800 px-2.5 py-1 font-medium text-fg">{page} / {pages.toLocaleString()}</span>
        <Button size="sm" variant="secondary" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</Button>
        <Button size="sm" variant="ghost" disabled={page >= pages} onClick={() => onPage(pages)}>Last</Button>
      </div>
    </div>
  )
}

export function Drawer({ open, onClose, title, children, wide }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    if (!open) return
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [open, onClose])
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true">
      <button aria-label="Close" className="absolute inset-0 bg-espresso-950/40 backdrop-blur-[2px]" onClick={onClose} />
      <div className={cx('relative flex h-full w-full flex-col bg-ink-900 shadow-2xl animate-fade-up', wide ? 'max-w-3xl' : 'max-w-xl')}>
        <div className="flex items-center justify-between border-b border-ink-700 bg-white px-5 py-3.5">
          <div className="min-w-0 text-sm font-semibold">{title}</div>
          <Button variant="ghost" size="sm" onClick={onClose}><X size={16} aria-hidden /><span className="sr-only">Close</span></Button>
        </div>
        <div className="flex-1 overflow-y-auto p-5">{children}</div>
      </div>
    </div>
  )
}

export function JsonBlock({ value }: { value: unknown }) {
  let text: string
  if (typeof value === 'string') {
    try { text = JSON.stringify(JSON.parse(value), null, 2) } catch { text = value }
  } else text = JSON.stringify(value, null, 2)
  // rendered as text content: untrusted log values are never interpreted as HTML
  return <pre className="mono max-h-[60vh] overflow-auto whitespace-pre-wrap break-all rounded-xl bg-espresso-900 p-4 text-[11px] leading-relaxed text-sky-100">{text}</pre>
}

export function ScoreBar({ value, max = 100, color = '#c9a227', label }: { value: number; max?: number; color?: string; label?: string }) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100))
  return (
    <div className="flex items-center gap-2" aria-label={label}>
      <div className="h-1.5 w-full min-w-10 overflow-hidden rounded-full bg-ink-700">
        <div className="h-full rounded-full transition-[width] duration-500" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  )
}

export function ProgressBar({ value, className }: { value: number; className?: string }) {
  return (
    <div className={cx('h-2 w-full overflow-hidden rounded-full bg-ink-700', className)} role="progressbar" aria-valuenow={Math.round(value * 100)} aria-valuemin={0} aria-valuemax={100}>
      <div className="gold-gradient h-full rounded-full transition-[width] duration-500" style={{ width: `${Math.max(3, Math.min(100, value * 100))}%` }} />
    </div>
  )
}

export const inputCls = 'rounded-xl border-0 bg-white px-3 py-2 text-sm text-fg shadow-sm ring-1 ring-ink-600 transition focus:outline-none focus:ring-2 focus:ring-sky-400 placeholder:text-faint'

export function Select({ value, onChange, options, label, className }: {
  value: string; onChange: (v: string) => void; options: { value: string; label: string }[]; label: string; className?: string
}) {
  return (
    <label className={cx('flex flex-col gap-1 text-xs font-medium text-muted', className)}>
      <span>{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)} className={inputCls}>
        {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </label>
  )
}

export function TextInput({ value, onChange, label, placeholder, type = 'text', className, ariaLabel }: {
  value: string | number; onChange: (v: string) => void; label?: string; placeholder?: string; type?: string; className?: string; ariaLabel?: string
}) {
  return (
    <label className={cx('flex flex-col gap-1 text-xs font-medium text-muted', className)}>
      {label && <span>{label}</span>}
      <input type={type} value={value} placeholder={placeholder} aria-label={ariaLabel ?? label} onChange={(e) => onChange(e.target.value)} className={inputCls} />
    </label>
  )
}

export function PageHeader({ title, subtitle, actions, eyebrow }: { title: string; subtitle?: ReactNode; actions?: ReactNode; eyebrow?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4 animate-fade-up">
      <div className="min-w-0">
        {eyebrow && <div className="mb-1 text-[11px] font-semibold uppercase tracking-[0.14em] text-sky-700">{eyebrow}</div>}
        <h1 className="font-display text-[28px] font-bold leading-tight tracking-tight text-fg">{title}</h1>
        {subtitle && <p className="mt-1 line-clamp-3 max-w-4xl text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

/** Horizontal bar list (label · bar · value) – compact alternative to a chart. */
export function BarList({ items, color = CHART.gold, format = (n: number) => n.toLocaleString(), mono, empty = 'No data' }: {
  items: { key: string | number; value: number; color?: string; hint?: string }[]; color?: string; format?: (n: number) => string; mono?: boolean; empty?: string
}) {
  if (!items.length) return <p className="text-sm text-muted">{empty}</p>
  const max = Math.max(1, ...items.map((i) => i.value))
  return (
    <ul className="space-y-2">
      {items.map((i) => (
        <li key={String(i.key)} className="grid grid-cols-[minmax(0,9rem)_1fr_auto] items-center gap-3 text-xs" title={i.hint}>
          <span className={cx('truncate text-fg', mono && 'mono')}>{i.key}</span>
          <div className="h-2.5 overflow-hidden rounded-full bg-ink-800">
            <div className="h-full rounded-full transition-[width] duration-500" style={{ width: `${(i.value / max) * 100}%`, background: i.color ?? color }} />
          </div>
          <span className="num w-16 text-right font-medium text-muted">{format(i.value)}</span>
        </li>
      ))}
    </ul>
  )
}

/** Segmented control. */
export function Segmented<T extends string>({ value, onChange, options, label }: { value: T; onChange: (v: T) => void; options: { value: T; label: string }[]; label: string }) {
  return (
    <div role="group" aria-label={label} className="inline-flex rounded-xl bg-ink-800 p-1 ring-1 ring-ink-700">
      {options.map((o) => (
        <button key={o.value} aria-pressed={value === o.value} onClick={() => onChange(o.value)}
          className={cx('rounded-lg px-3 py-1 text-xs font-medium transition', value === o.value ? 'bg-white text-fg shadow-sm' : 'text-muted hover:text-fg')}>{o.label}</button>
      ))}
    </div>
  )
}
