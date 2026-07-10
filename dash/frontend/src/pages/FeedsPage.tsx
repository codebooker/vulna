import { useCallback, useEffect, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import type { FeedHealth, FeedStatus } from '../types/intelligence';

const SOURCE_LABELS: Record<string, string> = {
  nvd: 'NVD (CVE)',
  kev: 'CISA KEV',
  epss: 'EPSS',
};

const STATUS_LABELS: Record<FeedStatus, string> = {
  ok: 'OK',
  degraded: 'Degraded',
  failed: 'Failed',
  stale: 'Stale',
  never_synced: 'Never synced',
};

function statusDot(status: FeedStatus): string {
  if (status === 'ok') return 'ok';
  if (status === 'failed') return 'bad';
  return 'pending';
}

function formatWhen(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString() : '—';
}

export function FeedsPage() {
  const { token, user, logout } = useAuth();
  const [feeds, setFeeds] = useState<FeedHealth[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [syncing, setSyncing] = useState<string | null>(null);

  const isAdmin = user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      setFeeds(await api.listFeedHealth(token));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        logout();
        return;
      }
      setError(err instanceof Error ? err.message : 'Failed to load feed health.');
    } finally {
      setLoading(false);
    }
  }, [token, logout]);

  useEffect(() => {
    void load();
  }, [load]);

  const sync = useCallback(
    async (source: string) => {
      if (!token) return;
      setSyncing(source);
      setError(null);
      try {
        await api.syncFeed(token, source);
        await load();
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          logout();
          return;
        }
        setError(err instanceof Error ? err.message : `Failed to sync ${source}.`);
      } finally {
        setSyncing(null);
      }
    },
    [token, logout, load],
  );

  return (
    <div className="card">
      <h2>Threat intelligence feeds</h2>
      {loading && <p className="detail">Loading feed health…</p>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {!loading && (
        <table className="table">
          <thead>
            <tr>
              <th>Source</th>
              <th>Status</th>
              <th>Last successful sync</th>
              <th>Records</th>
              {isAdmin && <th>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {feeds.map((f) => (
              <tr key={f.source}>
                <td>{SOURCE_LABELS[f.source] ?? f.source}</td>
                <td>
                  <span className="status-row">
                    <span className={`dot ${statusDot(f.status)}`} />
                    {STATUS_LABELS[f.status]}
                  </span>
                  {f.error && <p className="detail">{f.error}</p>}
                </td>
                <td>{formatWhen(f.last_success_at)}</td>
                <td>{f.records_processed.toLocaleString()}</td>
                {isAdmin && (
                  <td>
                    <button
                      type="button"
                      className="btn ghost"
                      disabled={syncing === f.source}
                      onClick={() => void sync(f.source)}
                    >
                      {syncing === f.source ? 'Syncing…' : 'Sync now'}
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
