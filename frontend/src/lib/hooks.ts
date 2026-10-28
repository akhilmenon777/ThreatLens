import { useCallback, useEffect, useRef, useState } from 'react'

export interface AsyncState<T> {
  data: T | null
  error: Error | null
  loading: boolean
  reload: () => void
  setData: (d: T) => void
}

/** Runs ``fn`` when ``deps`` change; exposes loading / error / data and a reload(). */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]): AsyncState<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<Error | null>(null)
  const [loading, setLoading] = useState(true)
  const [tick, setTick] = useState(0)
  const seq = useRef(0)
  useEffect(() => {
    const my = ++seq.current
    setLoading(true)
    setError(null)
    fn().then(
      (d) => { if (my === seq.current) { setData(d); setLoading(false) } },
      (e: Error) => { if (my === seq.current) { setError(e); setLoading(false) } },
    )
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick])
  const reload = useCallback(() => setTick((t) => t + 1), [])
  return { data, error, loading, reload, setData }
}

export function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms)
    return () => clearTimeout(t)
  }, [value, ms])
  return v
}
