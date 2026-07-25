import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import './styles/global.css'
import AppShell from './layout/AppShell'
import LandingPage from './pages/LandingPage'
import CasesHub from './pages/CasesHub'
import StageIntake from './pages/StageIntake'
import CaseWorkspace from './pages/CaseWorkspace'
import SettingsPage from './pages/SettingsPage'
import HelpPage from './pages/HelpPage'
import OrchCommandCenter from './modules/orch/OrchCommandCenter'
import ArtifactsView from './modules/artifacts/ArtifactsView'
import HitlReview from './modules/hitl/HitlReview'
import ManualStages from './modules/manual/ManualStages'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<LandingPage />} />
          <Route path="cases" element={<CasesHub />} />
          <Route path="stage" element={<StageIntake />} />
          <Route path="help" element={<HelpPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="cases/:sha" element={<CaseWorkspace />}>
            <Route index element={<Navigate to="orch" replace />} />
            <Route path="orch" element={<OrchCommandCenter />} />
            <Route path="reports" element={<ArtifactsView key="reports" initialMode="reports" />} />
            <Route path="evidence" element={<ArtifactsView key="evidence" initialMode="evidence" />} />
            <Route path="artifacts" element={<Navigate to="../reports" replace />} />
            <Route path="review" element={<HitlReview />} />
            <Route path="manual" element={<ManualStages />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </StrictMode>,
)
