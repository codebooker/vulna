import { useCallback, useEffect, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import type { ChangeEvent } from '../types/inventory';

const LABELS: Record<string, string> = {
  asset_discovered: 'Asset discovered',
  asset_disappeared: 'Asset disappeared',
  ip_changed: 'IP changed',
  new_port_opened: 'Port opened',
  port_closed: 'Port closed',
  service_version_changed: 'Version changed',
};

export function ChangesPage() {
  const { token, logout } = useAuth();
  const [changes, setChanges] = useState<ChangeEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const page = await api.listChanges(token);
      setChanges(page.items);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        logout();
        return;
      }
      setError(err instanceof Error ? err.message : 'Failed to load changes.');
    } finally {
      setLoading(false);
    }
  }, [token, logout]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="card">
      <h2>Recent changes</h2>
      {loading && <p className="detail">Loading changes…</p>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {!loading && changes.length === 0 && !error && (
        <p className="detail">No changes yet — run an assessment to populate the delta view.</p>
      )}
      {changes.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>Event</th>
              <th>Summary</th>
              <th>When</th>
            </tr>
          </thead>
          <tbody>
            {changes.map((c) => (
              <tr key={c.id}>
                <td>{LABELS[c.event_type] ?? c.event_type}</td>
                <td>{c.summary}</td>
                <td>{new Date(c.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
