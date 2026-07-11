import { useCallback, useEffect, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import type { DiagnosticsResult, SupportBundle, TimelineEvent } from '../types/diagnostics';

/** System Health (Vulna Doctor): one place to see which component is failing,
 *  with impact, data-safety, and next step per check — plus an event timeline and
 *  a redacted support-bundle preview. Admins can run safe, confirmed repairs. */
export function SystemHealthPage() {
  const { token, user } = useAuth();
  const [diag, setDiag] = useState<DiagnosticsResult | null>(null);
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [bundle, setBundle] = useState<SupportBundle | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const isAdmin = user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    try {
      setDiag(await api.diagnostics(token));
      setEvents((await api.diagnosticsTimeline(token)).events);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load diagnostics.');
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const previewBundle = async () => {
    if (!token) return;
    setError(null);
    try {
      setBundle(await api.supportBundle(token));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to build the support bundle.');
    }
  };

  const runRepair = async (action: string) => {
    if (!token) return;
    if (!window.confirm(`Run the safe repair "${action}"?`)) return;
    setBusy(true);
    setError(null);
    try {
      await api.repair(token, action);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Repair failed.');
    } finally {
      setBusy(false);
    }
  };

  if (!diag) {
    return error ? (
      <section className="card" aria-label="System health">
        <h2>System health</h2>
        <p role="alert" className="error">
          {error}
        </p>
      </section>
    ) : null;
  }

  return (
    <section className="card" aria-label="System health">
      <h2>System health</h2>
      <p className="detail">
        {diag.summary.fail} failing, {diag.summary.warn} warning, {diag.summary.ok} ok.
      </p>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}

      <ul className="status-list">
        {diag.checks.map((c) => (
          <li key={c.component}>
            <span className={c.status === 'ok' ? 'ok' : c.status === 'fail' ? 'bad' : 'pending'}>
              {c.status}
            </span>{' '}
            <strong>{c.component.replace(/_/g, ' ')}</strong> — {c.summary}
            {c.status !== 'ok' && (
              <div className="detail">
                Impact: {c.impact}. Data: {c.data_safety}. Next: {c.next_step}
              </div>
            )}
          </li>
        ))}
      </ul>

      {isAdmin && (
        <div className="row">
          <button
            type="button"
            className="btn ghost"
            disabled={busy}
            onClick={() => void runRepair('recreate_storage_dirs')}
          >
            Repair: recreate storage dirs
          </button>
          <button type="button" className="btn ghost" onClick={() => void previewBundle()}>
            Preview support bundle
          </button>
        </div>
      )}

      {bundle && (
        <div className="preview">
          <p>
            Support bundle{' '}
            <span className={bundle.secret_scan.clean ? 'ok' : 'bad'}>
              {bundle.secret_scan.clean ? 'no secrets detected' : 'SECRETS DETECTED'}
            </span>{' '}
            — review before sharing. Included sections:{' '}
            {bundle.manifest.map((m) => m.section).join(', ')}.
          </p>
          <details>
            <summary>Bundle preview (redacted)</summary>
            <pre className="cmd">{JSON.stringify(bundle.bundle, null, 2)}</pre>
          </details>
        </div>
      )}

      <h3>Recent events</h3>
      <ul className="status-list">
        {events.slice(0, 8).map((e, i) => (
          <li key={i}>
            <span className="pending">{e.kind}</span> {e.summary}
          </li>
        ))}
      </ul>
    </section>
  );
}
