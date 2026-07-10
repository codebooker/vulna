import { useAuth } from './auth/useAuth';
import { ChangesPage } from './pages/ChangesPage';
import { FeedsPage } from './pages/FeedsPage';
import { HealthPage } from './pages/HealthPage';
import { LoginPage } from './pages/LoginPage';
import { ReportsPage } from './pages/ReportsPage';
import { SitesPage } from './pages/SitesPage';

export function App() {
  const { user, initializing, logout } = useAuth();

  return (
    <main className="app">
      <header className="brand">
        <img className="brand-mark" src="/vulna-mark.svg" alt="Vulna" width={44} height={42} />
        <h1>VulnaDash</h1>
        <span className="tag">Self-hosted security assessment across every site.</span>
        {user && (
          <div className="session">
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
