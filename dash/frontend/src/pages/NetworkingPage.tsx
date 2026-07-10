import { useCallback, useEffect, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import type { BrowserTest, NetworkStatus, ValidateResult } from '../types/networking';

const MODE_LABEL: Record<string, string> = {
  localhost: 'Local host only',
  lan: 'Private LAN (IP / local name)',
  public_dns: 'Public DNS name with automatic TLS',
  existing_proxy: 'Behind my existing reverse proxy',
  manual_cert: 'Manually supplied certificate',
};

/** Networking / URL / TLS assistant: pick an access mode, validate hostname/DNS/
 *  certificate, generate a proxy snippet, and test reachability from this browser.
 *  Application TLS is kept separate from VulnaScout mutual TLS. Admins only. */
export function NetworkingPage() {
  const { token, user } = useAuth();
  const [status, setStatus] = useState<NetworkStatus | null>(null);
  const [mode, setMode] = useState('public_dns');
  const [hostname, setHostname] = useState('vulna.example.com');
  const [scheme, setScheme] = useState('https');
  const [result, setResult] = useState<ValidateResult | null>(null);
  const [browser, setBrowser] = useState<BrowserTest | null>(null);
  const [error, setError] = useState<string | null>(null);

  const isAdmin = user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    try {
      setStatus(await api.networkingStatus(token));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load networking status.');
    }
  }, [token]);

  useEffect(() => {
    if (isAdmin) void load();
  }, [isAdmin, load]);

  if (!isAdmin) return null;

  const validate = async () => {
    if (!token) return;
    setError(null);
    try {
      setResult(await api.validateNetworking(token, { mode, hostname, scheme }));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Validation failed.');
    }
  };

  const testThisBrowser = async () => {
    if (!token) return;
    setError(null);
    try {
      setBrowser(await api.testBrowser(token));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Test failed.');
    }
  };

  return (
    <section className="card" aria-label="Networking assistant">
      <h2>Networking &amp; access</h2>
      <p className="detail">
        Reach VulnaDash securely from the intended network. Application TLS is separate from
        VulnaScout mutual TLS — changing one never affects the other.
      </p>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}

      <div className="row">
        <label className="field">
          Access mode
          <select value={mode} onChange={(e) => setMode(e.target.value)}>
            {(status?.access_modes ?? Object.keys(MODE_LABEL)).map((m) => (
              <option key={m} value={m}>
                {MODE_LABEL[m] ?? m}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          Hostname
          <input value={hostname} onChange={(e) => setHostname(e.target.value)} />
        </label>
        <label className="field">
          Scheme
          <select value={scheme} onChange={(e) => setScheme(e.target.value)}>
            <option value="https">https</option>
            <option value="http">http</option>
          </select>
        </label>
      </div>
      <div className="row">
        <button type="button" className="btn" onClick={() => void validate()}>
          Validate
        </button>
        <button type="button" className="btn ghost" onClick={() => void testThisBrowser()}>
          Test from this browser
        </button>
      </div>

      {result && (
        <div className="preview">
          <p>
            {result.valid ? (
              <span className="ok">No problems detected.</span>
            ) : (
              <span className="bad">{result.issues.length} issue(s) found.</span>
            )}
          </p>
          {result.issues.map((i) => (
            <div key={i.code} className="issue">
              <p className="warn">⚠ {i.problem}</p>
              <p className="detail">→ {i.action}</p>
            </div>
          ))}
          {result.settings.warnings.map((w) => (
            <p key={w} className="detail">
              {w}
            </p>
          ))}
          {mode === 'existing_proxy' && (
            <details>
              <summary>Reverse-proxy snippet (nginx)</summary>
              <pre className="cmd">{result.proxy_snippet}</pre>
            </details>
          )}
        </div>
      )}

      {browser && (
        <div className="preview">
          <h3>What the server sees from this browser</h3>
          <ul className="status-list">
            <li>Reachable: {browser.reachable ? 'yes' : 'no'}</li>
            <li>Peer: {browser.peer ?? '—'}</li>
            <li>
              Peer is a trusted proxy:{' '}
              <span className={browser.peer_is_trusted_proxy ? 'ok' : 'pending'}>
                {browser.peer_is_trusted_proxy ? 'yes' : 'no'}
              </span>
            </li>
            <li>Forwarded proto: {browser.forwarded_proto ?? '—'}</li>
          </ul>
          <p className="detail">{browser.note}</p>
        </div>
      )}
    </section>
  );
}
