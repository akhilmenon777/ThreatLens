// Formatting helpers. Timestamps arrive as UTC ISO strings ('...Z') and are rendered
// in the display timezone chosen in Settings (default UTC), always with the zone label.

let displayTz = 'UTC'
export const setDisplayTimezone = (tz: string) => { displayTz = tz || 'UTC' }
export const getDisplayTimezone = () => displayTz

function parts(iso: string | null | undefined) {
  if (!iso) return null
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? null : d
}

export function fmtTime(iso: string | null | undefined, opts: { seconds?: boolean; date?: boolean } = {}): string {
  const d = parts(iso)
  if (!d) return '—'
  const { seconds = true, date = true } = opts
  const f = new Intl.DateTimeFormat('en-GB', {
    timeZone: displayTz, year: date ? 'numeric' : undefined, month: date ? 'short' : undefined, day: date ? '2-digit' : undefined,
    hour: '2-digit', minute: '2-digit', second: seconds ? '2-digit' : undefined, hour12: false,
  })
  return f.format(d)
}

export function tzLabel(): string {
  return displayTz === 'UTC' ? 'UTC' : displayTz
}

export function fmtDay(iso: string): string {
  const d = parts(iso)
  if (!d) return ''
  return new Intl.DateTimeFormat('en-GB', { timeZone: displayTz, day: '2-digit', month: 'short', year: '2-digit' }).format(d)
}

export function fmtBucket(iso: string, granularity?: string): string {
  return granularity === 'day' ? fmtDay(iso) : fmtHour(iso)
}

export function fmtCompact(n: number | null | undefined): string {
  if (n === null || n === undefined) return '—'
  return new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 }).format(n)
}

export function fmtHour(iso: string): string {
  const d = parts(iso)
  if (!d) return ''
  return new Intl.DateTimeFormat('en-GB', { timeZone: displayTz, hour: '2-digit', minute: '2-digit', hour12: false }).format(d)
}

export const fmtInt = (n: number | null | undefined) => (n === null || n === undefined ? '—' : n.toLocaleString('en-US'))
export const fmtPct = (n: number | null | undefined, digits = 1) => (n === null || n === undefined ? '—' : `${n.toFixed(digits)}%`)
export const fmtScore = (n: number | null | undefined, digits = 2) => (n === null || n === undefined ? '—' : n.toFixed(digits))

export function fmtBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return '—'
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(v < 10 && i ? 1 : 0)} ${u[i]}`
}

export function fmtDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return '—'
  if (ms < 1000) return `${Math.round(ms)} ms`
  return `${(ms / 1000).toFixed(1)} s`
}

export function fmtSpan(a: string, b: string): string {
  const da = parts(a), db = parts(b)
  if (!da || !db) return '—'
  const s = Math.max(0, (db.getTime() - da.getTime()) / 1000)
  if (s < 60) return `${Math.round(s)}s`
  if (s < 3600) return `${Math.round(s / 60)} min`
  if (s < 172800) return `${(s / 3600).toFixed(1)} h`
  return `${(s / 86400).toFixed(1)} d`
}

export const STAGE_LABELS: Record<string, string> = {
  reconnaissance: 'Reconnaissance',
  scanning: 'Scanning',
  credential_access: 'Credential attack',
  initial_access: 'Access',
  privilege_escalation: 'Privilege escalation',
  lateral_movement: 'Lateral movement',
  command_and_control: 'Post-compromise / C2',
  exfiltration: 'Possible exfiltration',
}
export const STAGE_SHORT: Record<string, string> = {
  reconnaissance: 'Recon', scanning: 'Scan', credential_access: 'Cred', initial_access: 'Access',
  privilege_escalation: 'PrivEsc', lateral_movement: 'Lateral', command_and_control: 'C2', exfiltration: 'Exfil',
}
export const STAGES = Object.keys(STAGE_LABELS)

export const STATUS_LABELS: Record<string, string> = {
  new: 'New', in_progress: 'In progress', escalated: 'Escalated', resolved: 'Resolved', closed: 'Closed',
}
export const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational'] as const
