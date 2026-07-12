import { useCallback, useEffect, useState } from 'react';
import { Eraser, Eye } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useToast } from '../lib/toast';
import { humanize } from '../lib/utils';
import { StatusBadge } from '../components/app/badges';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { Field, Input } from '../components/ui/input';
import { Progress } from '../components/ui/misc';
import { Modal } from '../components/ui/overlay';
import { InlineError } from '../components/ui/states';
import type { CleanupPreview, MaintenanceOverview, StorageBudgets } from '../types/maintenance';

function mb(bytes: number): string {
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Maintenance: updates, backups, feeds, certificates, and storage health,
 *  with a fail-closed retention cleanup that previews before deleting. */
export function MaintenancePage() {
  const { token, user } = useAuth();
  const { toast } = useToast();
  const [overview, setOverview] = useState<MaintenanceOverview | null>(null);
  const [storage, setStorage] = useState<StorageBudgets | null>(null);
  const [preview, setPreview] = useState<CleanupPreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [password, setPassword] = useState('');

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
    if (!token || !password) return;
    setBusy(true);
    setError(null);
    try {
      await api.runCleanup(token, password);
      setPreview(null);
      setConfirmOpen(false);
      setPassword('');
      await load();
      toast('success', 'Cleanup completed.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Cleanup failed.');
    } finally {
      setBusy(false);
    }
  };

  if (!overview) {
    return error ? (
      <div aria-label="Maintenance">
        <h2 className="mb-2 text-[15px] font-semibold text-text">Maintenance</h2>
        <InlineError message={error} />
      </div>
    ) : null;
  }

  return (
    <div aria-label="Maintenance">
      <h2 className="mb-1 text-[15px] font-semibold text-text">Maintenance &amp; data retention</h2>
      <p className="mb-4 text-[13px] text-muted">
        Overall: <StatusBadge status={overview.overall_state} /> — {overview.summary.action} action,{' '}
        {overview.summary.warn} warning, {overview.summary.ok} ok.
      </p>

      {error && <InlineError message={error} className="mb-3" />}

      <Card className="mb-3 divide-y divide-border">
        {overview.items.map((i) => (
          <div key={i.domain} className="flex flex-wrap items-center gap-2.5 px-4 py-2.5">
            <StatusBadge status={i.state} />
            <span className="min-w-0 flex-1">
              <span className="block text-[13px] font-medium text-text">{humanize(i.domain)}</span>
              <span className="block text-xs text-muted">{i.summary}</span>
              {i.state !== 'ok' && i.action && (
                <span className="block text-xs text-warn">Next: {i.action}</span>
              )}
            </span>
          </div>
        ))}
      </Card>

      {storage && (
        <Card className="mb-3 p-4">
          <div className="mb-2.5 flex items-center justify-between">
            <h3 className="text-[13px] font-semibold text-text">Storage</h3>
            <Badge tone={storage.disk.free_pct > 20 ? 'ok' : 'warn'}>
              {storage.disk.free_pct}% disk free
            </Badge>
          </div>
          <Progress
            value={100 - storage.disk.free_pct}
            tone={storage.disk.free_pct > 20 ? 'accent' : 'warn'}
            label="Disk usage"
            className="mb-3"
          />
          <ul className="flex flex-col gap-1.5">
            {storage.categories.map((c) => (
              <li key={c.category} className="flex items-center justify-between gap-2 text-[13px]">
                <span className="text-text">{c.category.replace(/_/g, ' ')}</span>
                <span className="text-xs text-muted">
                  {mb(c.bytes)}
                  <span className="text-faint">
                    {' '}
                    ({c.location}
                    {c.note ? ` — ${c.note}` : ''})
                  </span>
                </span>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {isAdmin && (
        <Card className="p-4">
          <h3 className="mb-1 text-[13px] font-semibold text-text">Retention cleanup</h3>
          <p className="mb-3 text-xs text-muted">
            Fail-closed: nothing is removed until you preview exactly what is eligible and confirm
            with your password.
          </p>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={() => void loadPreview()}>
              <Eye size={14} aria-hidden /> Preview cleanup
            </Button>
            {preview && preview.eligible.length > 0 && (
              <Button variant="destructive" disabled={busy} onClick={() => setConfirmOpen(true)}>
                <Eraser size={14} aria-hidden /> Run cleanup ({mb(preview.reclaimable_bytes)})
              </Button>
            )}
          </div>
          {preview && (
            <div className="mt-3 rounded-lg border border-border bg-surface-2 p-3">
              <p className="text-xs text-text">
                {preview.eligible.length} item(s) eligible ({mb(preview.reclaimable_bytes)}{' '}
                reclaimable); {preview.protected.length} protected and preserved.
              </p>
              {preview.protected.length > 0 && (
                <ul className="mt-2 flex flex-col gap-1">
                  {preview.protected.slice(0, 6).map((p) => (
                    <li
                      key={`${p.kind}-${p.id}`}
                      className="flex items-center gap-2 text-xs text-muted"
                    >
                      <Badge tone="ok">kept</Badge> {p.kind} — {p.reason}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </Card>
      )}

      <Modal
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        title="Confirm retention cleanup"
        description="Re-enter your password to run the cleanup. Protected items are always preserved."
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              loading={busy}
              disabled={!password}
              onClick={() => void runCleanup()}
            >
              Run cleanup
            </Button>
          </>
        }
      >
        <Field label="Password" htmlFor="cleanup-password">
          <Input
            id="cleanup-password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </Field>
      </Modal>
    </div>
  );
}
