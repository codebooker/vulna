import { useCallback, useEffect, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import type { CleanupPreview, MaintenanceOverview, StorageBudgets } from '../types/maintenance';

function mb(bytes: number): string {
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Unified Maintenance Center: one place to see whether updates, backups, feeds,
 *  certificates, and storage are healthy, with a fail-closed retention cleanup
 *  that previews exactly what it will delete before anything is removed. */
export function MaintenancePage() {
  const { token, user } = useAuth();
  const [overview, setOverview] = useState<MaintenanceOverview | null>(null);
  const [storage, setStorage] = useState<StorageBudgets | null>(null);
  const [preview, setPreview] = useState<CleanupPreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const isAdmin = user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    try {
      setOverview(await api.maintenance(token));
      setStorage(await api.maintenanceStorage(token));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load maintenance.');
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const loadPreview = async () => {
    if (!token) return;
    setError(null);
    try {
      setPreview(await api.retentionPreview(token));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to build the cleanup preview.');
    }
  };

  const runCleanup = async () => {
    if (!token) return;
    const password = window.prompt('Re-enter your password to run cleanup:');
    if (!password) return;
    setBusy(true);
    setError(null);
    try {
      await api.runCleanup(token, password);
      setPreview(null);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Cleanup failed.');
    } finally {
      setBusy(false);
    }
  };

  if (!overview) {
    return error ? (
      <section className="card" aria-label="Maintenance">
        <h2>Maintenance</h2>
        <p role="alert" className="error">
          {error}
        </p>
      </section>
    ) : null;
  }

  return (
    <section className="card" aria-label="Maintenance">
      <h2>Maintenance</h2>
      <p className="detail">
        Overall: <strong>{overview.overall_state}</strong> — {overview.summary.action} action,{' '}
        {overview.summary.warn} warning, {overview.summary.ok} ok.
      </p>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}

      <ul className="status-list">
        {overview.items.map((i) => (
          <li key={i.domain}>
            <span className={i.state === 'ok' ? 'ok' : i.state === 'action' ? 'bad' : 'pending'}>
              {i.state}
            </span>{' '}
            <strong>{i.domain.replace(/_/g, ' ')}</strong> — {i.summary}
            {i.state !== 'ok' && i.action && <div className="detail">Next: {i.action}</div>}
          </li>
        ))}
      </ul>

      {storage && (
        <>
          <h3>Storage</h3>
          <p className="detail">{storage.disk.free_pct}% disk free.</p>
          <ul className="status-list">
            {storage.categories.map((c) => (
              <li key={c.category}>
                <strong>{c.category.replace(/_/g, ' ')}</strong>: {mb(c.bytes)}{' '}
                <span className="detail">
                  ({c.location}
                  {c.note ? ` — ${c.note}` : ''})
                </span>
              </li>
            ))}
          </ul>
        </>
      )}

      {isAdmin && (
        <>
          <h3>Retention cleanup</h3>
          <div className="row">
            <button type="button" className="btn ghost" onClick={() => void loadPreview()}>
              Preview cleanup
            </button>
            {preview && preview.eligible.length > 0 && (
              <button
                type="button"
                className="btn ghost"
                disabled={busy}
                onClick={() => void runCleanup()}
              >
                Run cleanup ({mb(preview.reclaimable_bytes)})
              </button>
            )}
          </div>
          {preview && (
            <div className="preview">
              <p>
                {preview.eligible.length} item(s) eligible ({mb(preview.reclaimable_bytes)}{' '}
                reclaimable); {preview.protected.length} protected and preserved.
              </p>
              {preview.protected.length > 0 && (
                <ul className="status-list">
                  {preview.protected.slice(0, 6).map((p) => (
                    <li key={`${p.kind}-${p.id}`}>
                      <span className="ok">kept</span> {p.kind} — {p.reason}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </>
      )}
    </section>
  );
}
