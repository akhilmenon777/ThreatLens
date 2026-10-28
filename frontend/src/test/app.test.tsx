import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { qs } from '../api/client'
import { EvidenceBadge, Pagination, SeverityBadge } from '../components/ui'
import { fmtBytes, fmtPct, fmtTime, setDisplayTimezone } from '../lib/format'
import { AppProvider } from '../lib/app-context'
import IncidentsPage from '../pages/Incidents'

const incident = {
  id: 'INC-ABCDEF12', title: 'Multi-stage activity involving 192.168.56.101 → 10.10.0.20', severity: 'Critical', risk_score: 97.6,
  confidence: 0.86, first_seen: '2026-10-20T08:05:04Z', last_seen: '2026-10-20T14:38:17Z', event_count: 488,
  sensors: ['suricata', 'zeek'], entities: { internal_hosts: ['10.10.0.20'], external_ips: ['203.0.113.45'], source_ips: [], destination_ips: [], hostnames: [], dns_domains: [], users: [], ports: [] },
  tactics: ['Credential Access'], stages_present: ['credential_access', 'exfiltration'], status: 'new', assignee: null,
  suspected_false_positive: false, synthetic: true,
}

function mockFetch(handler: (url: string) => unknown) {
  const calls: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    calls.push(url)
    const body = handler(url)
    return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } })
  }))
  return calls
}

afterEach(() => vi.unstubAllGlobals())

describe('formatting', () => {
  it('renders UTC timestamps in the configured zone', () => {
    setDisplayTimezone('UTC')
    expect(fmtTime('2026-10-20T08:05:04Z')).toContain('08:05:04')
    setDisplayTimezone('Asia/Kolkata')
    expect(fmtTime('2026-10-20T08:05:04Z')).toContain('13:35:04')
    setDisplayTimezone('UTC')
    expect(fmtTime(null)).toBe('—')
  })
  it('formats numbers', () => {
    expect(fmtPct(99.123, 2)).toBe('99.12%')
    expect(fmtBytes(1536)).toBe('1.5 KB')
    expect(qs({ a: 1, b: ['x', 'y'], c: undefined, d: '' })).toBe('?a=1&b=x&b=y')
  })
})

describe('badges', () => {
  it('observed vs inferred are distinguishable without colour', () => {
    render(<><EvidenceBadge status="OBSERVED" /><EvidenceBadge status="INFERRED" /><EvidenceBadge status="NOT_OBSERVED" /></>)
    expect(screen.getByText('Observed')).toBeInTheDocument()
    expect(screen.getByText('Inferred').closest('span')?.className).toContain('inferred-outline')
    expect(screen.getByText('Not observed')).toBeInTheDocument()
  })
  it('severity badge shows the severity text', () => {
    render(<SeverityBadge severity="High" />)
    expect(screen.getByText('High')).toBeInTheDocument()
  })
  it('pagination calls back', () => {
    const onPage = vi.fn()
    render(<Pagination page={1} pageSize={20} total={45} onPage={onPage} />)
    expect(screen.getByText('1–20 of 45')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Next'))
    expect(onPage).toHaveBeenCalledWith(2)
  })
})

describe('incidents page', () => {
  const handler = (url: string) => {
    if (url.startsWith('/api/health')) return { status: 'ok', backend: true, database: true, app_version: '1', llm: { available: false, models: [], mode: 'cached', base_url: '' }, active_dataset: 'demo' }
    if (url.startsWith('/api/datasets')) return [{ id: 1, name: 'demo', version: '1', description: '', synthetic: true, is_active: true, created_at: '', has_labels: true, event_count: 10 }]
    if (url.startsWith('/api/settings')) return { display: { timezone: 'UTC' }, llm: {}, correlation: {}, risk: {} }
    if (url.startsWith('/api/incidents')) return url.includes('q=nomatch') ? { total: 0, page: 1, page_size: 20, items: [] } : { total: 1, page: 1, page_size: 20, items: [incident] }
    return {}
  }
  const renderPage = () => render(
    <MemoryRouter initialEntries={['/incidents']}>
      <AppProvider><Routes><Route path="/incidents" element={<IncidentsPage />} /><Route path="/incidents/:id" element={<div>detail page</div>} /></Routes></AppProvider>
    </MemoryRouter>)

  it('lists incidents and navigates to detail', async () => {
    mockFetch(handler)
    renderPage()
    expect(await screen.findByText(incident.title)).toBeInTheDocument()
    expect(screen.getAllByText('Critical').length).toBeGreaterThanOrEqual(2) // filter pill + badge
    fireEvent.click(screen.getByText(incident.title))
    expect(await screen.findByText('detail page')).toBeInTheDocument()
  })

  it('search and severity filters reach the API and show an empty state', async () => {
    const calls = mockFetch(handler)
    renderPage()
    await screen.findByText(incident.title)
    fireEvent.click(screen.getByRole('button', { name: 'High' }))
    await waitFor(() => expect(calls.some((c) => c.includes('severity=High'))).toBe(true))
    fireEvent.change(screen.getByPlaceholderText(/Search ID/), { target: { value: 'nomatch' } })
    expect(await screen.findByText('No incidents match these filters')).toBeInTheDocument()
  })

  it('shows an error state when the backend is down', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('network') }))
    renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent('Backend unreachable')
  })
})
