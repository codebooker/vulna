import { useCallback, useEffect, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { Card } from '../components/ui/card';
import { CodeBlock } from '../components/ui/misc';
import { InlineError } from '../components/ui/states';
import type { BackupCenter } from '../types/backup';

/** Backup center (display only). Backups are created, verified, and restored
 *  with the `vulna backup` CLI; the web UI never handles the passphrase. */
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
      <div aria-label="Backups">
        <h2 className="mb-2 text-[15px] font-semibold text-text">Backups</h2>
        <InlineError message={error} />
      </div>
    ) : null;
  }

  return (
    <div aria-label="Backup center">
      <h2 className="mb-1 text-[15px] font-semibold text-text">Backups &amp; recovery</h2>
      <p className="mb-3 rounded-lg border border-warn/30 bg-warn/10 px-3 py-2 text-xs text-warn">
        ⚠ {info.warning}
      </p>
      <p className="mb-1 text-[13px] text-muted">
        Default destination: {info.default_destination} (also supports{' '}
        {info.destinations.join(', ')}
        ). Retention: {info.retention_days} days.
      </p>
      <p className="mb-1 text-[13px] text-muted">Included: {info.contents.join(', ')}.</p>
      <p className="mb-4 text-[13px] text-muted">Encryption: {info.encryption}.</p>
      <Card className="p-4">
        <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">Create</p>
        <CodeBlock>{info.how_to_create}</CodeBlock>
        <p className="mb-1.5 mt-3 text-xs font-semibold uppercase tracking-wide text-muted">
          Verify
        </p>
        <CodeBlock>{info.how_to_verify}</CodeBlock>
        <p className="mb-1.5 mt-3 text-xs font-semibold uppercase tracking-wide text-muted">
          Restore
        </p>
        <CodeBlock>{info.how_to_restore}</CodeBlock>
      </Card>
    </div>
  );
}
