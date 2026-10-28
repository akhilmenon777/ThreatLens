import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import { api } from '../api/client'
import type { Dataset, Health } from '../api/types'
import { setDisplayTimezone } from './format'

interface Toast { id: number; kind: 'success' | 'error' | 'info'; text: string }

interface AppState {
  health: Health | null
  healthError: string | null
  dataset: Dataset | null
  datasets: Dataset[]
  timezone: string
  version: number            // bumped whenever data changes so pages refetch
  refresh: () => void
  notify: (kind: Toast['kind'], text: string) => void
  toasts: Toast[]
  dismiss: (id: number) => void
}

const Ctx = createContext<AppState | null>(null)

export function AppProvider({ children }: { children: ReactNode }) {
  const [health, setHealth] = useState<Health | null>(null)
  const [healthError, setHealthError] = useState<string | null>(null)
  const [datasets, setDatasets] = useState<Dataset[]>([])
  const [timezone, setTz] = useState('UTC')
  const [version, setVersion] = useState(0)
  const [toasts, setToasts] = useState<Toast[]>([])

  const load = useCallback(async () => {
    try {
      const [h, ds, s] = await Promise.all([api.health(), api.datasets(), api.settings()])
      setHealth(h)
      setHealthError(null)
      setDatasets(ds)
      setDisplayTimezone(s.display.timezone)
      setTz(s.display.timezone)
    } catch (e) {
      setHealthError((e as Error).message)
    }
  }, [])

  useEffect(() => { void load() }, [load, version])
  useEffect(() => {
    const t = setInterval(() => { api.health().then((h) => { setHealth(h); setHealthError(null) }, (e) => setHealthError(e.message)) }, 30000)
    return () => clearInterval(t)
  }, [])

  const notify = useCallback((kind: Toast['kind'], text: string) => {
    const id = Date.now() + Math.random()
    setToasts((t) => [...t, { id, kind, text }])
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), kind === 'error' ? 8000 : 4000)
  }, [])

  const value: AppState = {
    health, healthError, datasets, timezone, version, toasts,
    dataset: datasets.find((d) => d.is_active) ?? null,
    refresh: () => setVersion((v) => v + 1),
    notify,
    dismiss: (id) => setToasts((t) => t.filter((x) => x.id !== id)),
  }
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useApp(): AppState {
  const v = useContext(Ctx)
  if (!v) throw new Error('useApp outside AppProvider')
  return v
}
