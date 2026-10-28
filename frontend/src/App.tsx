import { lazy, Suspense } from 'react'
import { Route, Routes } from 'react-router-dom'
import { EmptyState, Spinner } from './components/ui'
import { Shell } from './layouts/Shell'

// Route-level code splitting keeps the initial bundle small.
const OverviewPage = lazy(() => import('./pages/Overview'))
const DatasetPage = lazy(() => import('./pages/Dataset'))
const IncidentsPage = lazy(() => import('./pages/Incidents'))
const IncidentDetailPage = lazy(() => import('./pages/IncidentDetail'))
const EventsPage = lazy(() => import('./pages/Events'))
const AttackPage = lazy(() => import('./pages/Attack'))
const EvaluationPage = lazy(() => import('./pages/Evaluation'))
const IngestionPage = lazy(() => import('./pages/Ingestion'))
const ReportsPage = lazy(() => import('./pages/Reports'))
const SettingsPage = lazy(() => import('./pages/Settings'))

export default function App() {
  return (
    <Shell>
      <Suspense fallback={<Spinner />}>
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/dataset" element={<DatasetPage />} />
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/incidents/:id" element={<IncidentDetailPage />} />
          <Route path="/events" element={<EventsPage />} />
          <Route path="/attack" element={<AttackPage />} />
          <Route path="/evaluation" element={<EvaluationPage />} />
          <Route path="/ingestion" element={<IngestionPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<EmptyState title="Page not found">Use the navigation on the left.</EmptyState>} />
        </Routes>
      </Suspense>
    </Shell>
  )
}
