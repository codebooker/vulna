import { useCallback, useEffect, useState } from 'react';
import { api } from './api/client';
import { useAuth } from './auth/useAuth';
import { ChangesPage } from './pages/ChangesPage';
import { FeedsPage } from './pages/FeedsPage';
import { HealthPage } from './pages/HealthPage';
import { LoginPage } from './pages/LoginPage';
import { OnboardingWizard } from './pages/OnboardingWizard';
import { ReportsPage } from './pages/ReportsPage';
import { SitesPage } from './pages/SitesPage';
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
          <SitesPage />
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
