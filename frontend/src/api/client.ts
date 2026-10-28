import type {
  Analytics, TaskStatus, UwfInfo,
  AnalysisSettings, CorrelationRunOut, Dataset, EvaluationRun, EventDetail, EventItem, Health, IncidentDetail,
  IncidentListItem, Job, Link, LlmStatus, Matrix, Note, Overview, Page, Summary,
} from './types'

export class ApiError extends Error {
  status: number
  details?: unknown
  constructor(status: number, message: string, details?: unknown) {
    super(message)
    this.status = status
    this.details = details
  }
}

const BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? ''

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(BASE + path, init)
  } catch {
    throw new ApiError(0, 'Backend unreachable. Is the API running on port 8000?')
  }
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`
    let details: unknown
    try {
      const body = await res.json()
      details = body
      if (typeof body.detail === 'string') msg = body.detail
      if (Array.isArray(body.errors)) msg += ': ' + body.errors.map((e: { loc: string[]; msg: string }) => `${e.loc.slice(1).join('.')} ${e.msg}`).join('; ')
    } catch {
      /* non-JSON error */
    }
    throw new ApiError(res.status, msg, details)
  }
  const ct = res.headers.get('content-type') ?? ''
  return (ct.includes('application/json') ? res.json() : res.text()) as Promise<T>
}

const json = (method: string, body: unknown): RequestInit => ({
  method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
})

export type Query = Record<string, string | number | boolean | string[] | undefined | null>

export function qs(params: Query): string {
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue
    if (Array.isArray(v)) v.forEach((x) => u.append(k, x))
    else u.append(k, String(v))
  }
  const s = u.toString()
  return s ? `?${s}` : ''
}

export const api = {
  health: () => request<Health>('/api/health'),
  schema: () => request<{ schema_version: string; fields: Record<string, string>; supported_inputs: Record<string, string>; max_upload_mb: number; attack_catalog: { version: string; note: string } }>('/api/schema'),
  analysts: () => request<string[]>('/api/analysts'),
  datasets: () => request<Dataset[]>('/api/datasets'),
  activateDataset: (id: number) => request<Dataset>(`/api/datasets/${id}/activate`, { method: 'POST' }),
  deleteDataset: (id: number) => request<{ deleted: number }>(`/api/datasets/${id}`, { method: 'DELETE' }),
  createDataset: (name: string, description = '') => {
    const f = new FormData()
    f.append('name', name)
    f.append('description', description)
    return request<Dataset>('/api/datasets', { method: 'POST', body: f })
  },
  loadDemo: () => request<{ dataset: Dataset; jobs: Job[]; correlation: CorrelationRunOut }>('/api/demo/load', { method: 'POST' }),
  upload: (file: File, sensor: string, correlate: boolean) => {
    const f = new FormData()
    f.append('file', file)
    f.append('sensor', sensor)
    f.append('run_correlation_after', String(correlate))
    return request<{ job: Job; correlation?: CorrelationRunOut; decode_warning?: string | null }>('/api/ingest', { method: 'POST', body: f })
  },
  jobs: () => request<Job[]>('/api/ingest/jobs'),
  uwfInfo: () => request<UwfInfo>('/api/uwf'),
  loadUwf: (parts: string[]) => request<TaskStatus>('/api/uwf/load', json('POST', { parts })),
  task: (id: string) => request<TaskStatus>(`/api/tasks/${encodeURIComponent(id)}`),
  analytics: () => request<Analytics>('/api/analytics'),
  eventLabels: () => request<string[]>('/api/events/labels'),
  rejected: (jobId: number) => request<{ line_number: number; reason: string; raw_excerpt: string }[]>(`/api/ingest/jobs/${jobId}/rejected`),
  runCorrelation: () => request<CorrelationRunOut>('/api/correlation/run', { method: 'POST' }),
  overview: () => request<Overview>('/api/overview'),
  incidents: (p: Query) => request<Page<IncidentListItem>>('/api/incidents' + qs(p)),
  incident: (id: string) => request<IncidentDetail>(`/api/incidents/${encodeURIComponent(id)}`),
  incidentEvents: (id: string, p: Query) => request<Page<EventItem>>(`/api/incidents/${encodeURIComponent(id)}/events` + qs(p)),
  incidentLinks: (id: string, p: Query) => request<Page<Link>>(`/api/incidents/${encodeURIComponent(id)}/links` + qs(p)),
  linkSummary: (id: string) => request<{ rule: string; count: number; avg_score: number; min_score: number }[]>(`/api/incidents/${encodeURIComponent(id)}/link-summary`),
  updateIncident: (id: string, body: { status?: string; assignee?: string; suspected_false_positive?: boolean; actor: string; reason?: string }) =>
    request<IncidentDetail>(`/api/incidents/${encodeURIComponent(id)}`, json('PATCH', body)),
  addNote: (id: string, author: string, text: string) => request<Note>(`/api/incidents/${encodeURIComponent(id)}/notes`, json('POST', { author, text })),
  summarize: (id: string, mode?: string, model?: string) => request<Summary>(`/api/incidents/${encodeURIComponent(id)}/summary`, json('POST', { mode, model })),
  summaries: (id: string) => request<Summary[]>(`/api/incidents/${encodeURIComponent(id)}/summaries`),
  reportUrl: (id: string, format: 'json' | 'csv' | 'html') => `${BASE}/api/incidents/${encodeURIComponent(id)}/report?format=${format}`,
  incidentsCsvUrl: () => `${BASE}/api/reports/incidents.csv`,
  events: (p: Query) => request<Page<EventItem>>('/api/events' + qs(p)),
  eventTypes: () => request<{ event_type: string; count: number }[]>('/api/events/types'),
  event: (id: string) => request<EventDetail>(`/api/events/${encodeURIComponent(id)}`),
  matrix: () => request<Matrix>('/api/attack/matrix'),
  startEvaluation: (include_llm: boolean, models?: string[]) => request<{ id: number; status: string }>('/api/evaluation/run', json('POST', { include_llm, models })),
  evaluationRuns: () => request<EvaluationRun[]>('/api/evaluation/runs'),
  evaluationRun: (id: number) => request<EvaluationRun>(`/api/evaluation/runs/${id}`),
  evaluationExportUrl: (id: number, format: 'json' | 'md') => `${BASE}/api/evaluation/runs/${id}/export?format=${format}`,
  settings: () => request<AnalysisSettings>('/api/settings'),
  saveSettings: (s: AnalysisSettings) => request<AnalysisSettings>('/api/settings', json('PUT', s)),
  resetSettings: () => request<AnalysisSettings>('/api/settings/reset', { method: 'POST' }),
  llmStatus: (base_url?: string) => request<LlmStatus>('/api/llm/status' + qs({ base_url })),
}
