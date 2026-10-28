import { FileDown, FileJson, FileSpreadsheet } from 'lucide-react'
import { useState } from 'react'
import { api } from '../api/client'
import { DataGate } from '../components/NoDataset'
import { Card, PageHeader, SeverityBadge, Spinner, StatusBadge } from '../components/ui'
import { useApp } from '../lib/app-context'
import { fmtTime } from '../lib/format'
import { useAsync } from '../lib/hooks'

const linkCls = 'inline-flex items-center gap-1.5 rounded-xl bg-white px-3 py-1.5 text-xs font-medium shadow-sm ring-1 ring-ink-600 transition hover:bg-sky-50 hover:ring-sky-300'

export default function ReportsPage() {
  const { version } = useApp()
  const [page] = useState(1)
  const incidents = useAsync(() => api.incidents({ page, page_size: 200, sort: 'risk_score', order: 'desc' }), [version])
  const evals = useAsync(() => api.evaluationRuns().catch(() => []), [version])
  if (incidents.error) return <><PageHeader title="Reports" /><DataGate error={incidents.error} onRetry={incidents.reload} /></>
  return (
    <div className="space-y-4">
      <PageHeader eyebrow="Analyse" title="Reports" subtitle="Export incident reports and evaluation results. Reports carry the review disclaimer and synthetic-data label." />
      <Card title="All incidents" subtitle={`Top ${incidents.data?.items.length ?? 0} of ${(incidents.data?.total ?? 0).toLocaleString()} incidents by risk. The CSV contains every incident.`} actions={<a className={linkCls} href={api.incidentsCsvUrl()}><FileSpreadsheet size={13} aria-hidden />incidents.csv</a>}>
        {incidents.loading && !incidents.data ? <Spinner /> : (
          <div className="overflow-x-auto">
            <table className="table-modern w-full text-sm">
              <thead className="text-left"><tr>
                <th className="px-3 py-2 font-medium">Incident</th><th className="pr-3 font-medium">Severity</th><th className="pr-3 font-medium">Status</th><th className="pr-3 font-medium">First seen</th><th className="font-medium">Export</th>
              </tr></thead>
              <tbody className="divide-y divide-ink-700/60">
                {incidents.data?.items.map((i) => (
                  <tr key={i.id}>
                    <td className="max-w-md px-3 py-2"><div className="truncate font-medium">{i.title}</div><div className="mono text-[11px] text-faint">{i.id}</div></td>
                    <td className="pr-3"><SeverityBadge severity={i.severity} /></td><td className="pr-3"><StatusBadge status={i.status} /></td>
                    <td className="num pr-3 text-xs text-muted">{fmtTime(i.first_seen)}</td>
                    <td><div className="flex flex-wrap gap-1.5">
                      <a className={linkCls} href={api.reportUrl(i.id, 'html')}><FileDown size={12} aria-hidden />HTML</a>
                      <a className={linkCls} href={api.reportUrl(i.id, 'json')}><FileJson size={12} aria-hidden />JSON</a>
                      <a className={linkCls} href={api.reportUrl(i.id, 'csv')}><FileSpreadsheet size={12} aria-hidden />CSV timeline</a>
                    </div></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <Card title="Evaluation results" subtitle="Reproducible runs with their parameters, dataset version and measured results.">
        {evals.data && evals.data.length === 0 ? <p className="text-sm text-muted">No evaluation runs yet — start one in the Evaluation lab.</p> : (
          <ul className="divide-y divide-ink-700">
            {evals.data?.filter((r) => r.status === 'completed').map((r) => (
              <li key={r.id} className="flex items-center gap-3 py-2 text-sm">
                <span className="flex-1">Run #{r.id} · {fmtTime(r.created_at)}{r.summary && <span className="text-muted"> · {r.summary.incidents} incidents · F1 {r.summary.f1 ?? '—'}</span>}</span>
                <a className={linkCls} href={api.evaluationExportUrl(r.id, 'md')}><FileDown size={12} aria-hidden />Markdown</a>
                <a className={linkCls} href={api.evaluationExportUrl(r.id, 'json')}><FileJson size={12} aria-hidden />JSON</a>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  )
}
