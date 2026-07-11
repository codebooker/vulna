import { useCallback, useEffect, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import type { BackupCenter } from '../types/backup';

/** Backup center (display only). Backups are created, verified, and restored by
 *  an operator with the `vulna backup` CLI using encrypted bundles and a
 *  user-controlled recovery passphrase; the web UI never handles the passphrase. */
export function BackupCenterPage() {
  const { token, user } = useAuth();
  const [info, setInfo] = useState<BackupCenter | null>(null);
  const [error, setError] = useState<string | null>(null);

  const isAdmin = user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    try {
      setInfo(await api.backupCenter(token));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load backup info.');
    }
  }, [token]);

  useEffect(() => {
    if (isAdmin) void load();
  }, [isAdmin, load]);

  if (!isAdmin || !info) {
    return error ? (
      <section className="card" aria-label="Backups">
        <h2>Backups</h2>
        <p role="alert" className="error">
          {error}
        </p>
      </section>
    ) : null;
  }

  return (
    <section className="card" aria-label="Backup center">
      <h2>Backups &amp; recovery</h2>
      <p className="warn">⚠ {info.warning}</p>
      <p className="detail">
        Default destination: {info.default_destination} (also supports{' '}
        {info.destinations.join(', ')}). Retention: {info.retention_days} days.
      </p>
      <p className="detail">Included: {info.contents.join(', ')}.</p>
      <p className="detail">Encryption: {info.encryption}.</p>
      <ul className="status-list">
        <li>
          Create: <code>{info.how_to_create}</code>
        </li>
        <li>
          Verify: <code>{info.how_to_verify}</code>
        </li>
        <li>
          Restore: <code>{info.how_to_restore}</code>
        </li>
      </ul>
    </section>
  );
}
