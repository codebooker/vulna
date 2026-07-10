import { useCallback, useEffect, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import type { UpdateCenter } from '../types/update';

/** Update center (display only). The running app never fetches or applies
 *  releases; updates are checked and applied by the operator with the
 *  signature-verifying `vulna` CLI. */
export function UpdateCenterPage() {
  const { token, user } = useAuth();
  const [info, setInfo] = useState<UpdateCenter | null>(null);
  const [error, setError] = useState<string | null>(null);

  const isAdmin = user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    try {
      setInfo(await api.updateCenter(token));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load update info.');
    }
  }, [token]);

  useEffect(() => {
    if (isAdmin) void load();
  }, [isAdmin, load]);

  if (!isAdmin || !info) {
    return error ? (
      <section className="card" aria-label="Updates">
        <h2>Updates</h2>
        <p role="alert" className="error">
          {error}
        </p>
      </section>
    ) : null;
  }

  return (
    <section className="card" aria-label="Update center">
      <h2>Updates</h2>
      <p className="detail">
        Current version <code>{info.current_version}</code> on the <strong>{info.channel}</strong>{' '}
        channel. Updates are applied by an operator with the signature-verifying <code>vulna</code>{' '}
        CLI — the web UI only shows version info.
      </p>
      <ul className="status-list">
        <li>
          Check for updates: <code>{info.how_to_check}</code>
        </li>
        <li>
          Apply an update: <code>{info.how_to_apply}</code>
        </li>
      </ul>
      <p className="detail">
        These update types are kept separate: {info.update_types.join(', ')}.
      </p>
      <p className="detail">{info.note}</p>
    </section>
  );
}
