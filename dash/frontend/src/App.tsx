import { HealthPage } from './pages/HealthPage';

export function App() {
  return (
    <main className="app">
      <div className="brand">
        <img className="brand-mark" src="/vulna-mark.svg" alt="Vulna" width={44} height={42} />
        <h1>VulnaDash</h1>
        <span className="tag">Self-hosted security assessment across every site.</span>
      </div>

      <HealthPage />

      <p className="footer">
        Phase 0 — repository foundation. Authorized use only. See SECURITY.md.
      </p>
    </main>
  );
}
