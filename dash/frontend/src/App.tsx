import { useAuth } from './auth/useAuth';
import { HealthPage } from './pages/HealthPage';
import { LoginPage } from './pages/LoginPage';
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
        <SitesPage />
      ) : (
        <LoginPage />
      )}

      <HealthPage />

      <p className="footer">
        Phase 1 — authentication and core inventory. Authorized use only. See SECURITY.md.
      </p>
    </main>
  );
}
