import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

afterEach(() => cleanup())

// Recharts' ResponsiveContainer needs ResizeObserver in jsdom.
class RO { observe() {} unobserve() {} disconnect() {} }
;(globalThis as unknown as { ResizeObserver: typeof RO }).ResizeObserver = RO
