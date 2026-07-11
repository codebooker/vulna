import { useCallback, useEffect, useState } from 'react';
import { api } from './api/client';
import { useAuth } from './auth/useAuth';
import { GlobalSearch } from './components/GlobalSearch';
import { AddScoutPage } from './pages/AddScoutPage';
import { BackupCenterPage } from './pages/BackupCenterPage';
import { ChangesPage } from './pages/ChangesPage';
import { FeedsPage } from './pages/FeedsPage';
import { FindingsPage } from './pages/FindingsPage';
import { HealthPage } from './pages/HealthPage';
import { HelpPage } from './pages/HelpPage';
import { HomeDashboard } from './pages/HomeDashboard';
import { LoginPage } from './pages/LoginPage';
import { MaintenancePage } from './pages/MaintenancePage';
import { NetworkingPage } from './pages/NetworkingPage';
import { NotificationsPage } from './pages/NotificationsPage';
import { PrivacyPage } from './pages/PrivacyPage';
import { OnboardingWizard } from './pages/OnboardingWizard';
import { PresetsPage } from './pages/PresetsPage';
import { ReportsPage } from './pages/ReportsPage';
import { SitesPage } from './pages/SitesPage';
import { SystemHealthPage } from './pages/SystemHealthPage';
import { UpdateCenterPage } from './pages/UpdateCenterPage';
import type { OnboardingState } from './types/onboarding';

export function App() {
  const { user, token, initializing, logout } = useAuth();
  const [onboarding, setOnboarding] = useState<OnboardingState | null>(null);
  const [resume, setResume] = useState(false);

  const loadOnboarding = useCallback(async () => {
    if (!token) return;
    try {
      setOnboarding(await api.onboardingState(token));
    } catch {
      setOnboarding(null);
    }
  }, [token]);

  useEffect(() => {
    if (user && token) void loadOnboarding();
  }, [user, token, loadOnboarding]);

  const incomplete = onboarding !== null && onboarding.completed_at === null;
  const showWizard = incomplete && (!onboarding.dismissed || resume);

  return (
    <main className="app">
      <header className="brand">
        <img className="brand-mark" src="/vulna-mark.svg" alt="Vulna" width={44} height={42} />
        <h1>VulnaDash</h1>
        <span className="tag">Self-hosted security assessment across every site.</span>
        {user && <GlobalSearch />}
        {user && (
          <div className="session">
            {incomplete && onboarding.dismissed && !resume && (
              <button type="button" className="btn ghost" onClick={() => setResume(true)}>
                Resume setup
              </button>
            )}
            <span className="who">
              {user.email} · <em>{user.role}</em>
            </span>
            <button type="button" className="btn ghost" onClick={logout}>
              Sign out
            </button>
          </div>
        )}
      </header>

      {initializing ? (
        <div className="card">
          <p className="detail">Loading…</p>
        </div>
      ) : user ? (
        <>
          {showWizard && (
            <OnboardingWizard
              onFinished={() => {
                setResume(false);
                void loadOnboarding();
              }}
            />
          )}
          <HomeDashboard />
          <SystemHealthPage />
          <MaintenancePage />
          <NotificationsPage />
          <PrivacyPage />
          <HelpPage />
          <FindingsPage />
          <SitesPage />
          <PresetsPage />
          <AddScoutPage />
          <NetworkingPage />
          <UpdateCenterPage />
          <BackupCenterPage />
          <ChangesPage />
          <FeedsPage />
          <ReportsPage />
        </>
      ) : (
        <LoginPage />
      )}

      <HealthPage />

      <p className="footer">
        Authorized use only. See SECURITY.md and the project status in the README.
      </p>
    </main>
  );
}
