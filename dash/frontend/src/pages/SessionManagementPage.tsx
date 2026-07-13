import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { LogOut, RefreshCw, ShieldCheck, Smartphone } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { PageHeader } from '../components/app/page-header';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Field, Input } from '../components/ui/input';
import { CardSkeleton, InlineError } from '../components/ui/states';
import { useToast } from '../lib/toast';
import { formatWhenFull } from '../lib/utils';
import type { SessionPolicy, UserSession } from '../types/auth';

const POLICY_FIELDS: Array<{
  key: keyof SessionPolicy;
  label: string;
  min: number;
  max: number;
}> = [
  { key: 'idle_timeout_hours', label: 'Idle timeout (hours)', min: 1, max: 168 },
  { key: 'absolute_lifetime_days', label: 'Absolute lifetime (days)', min: 1, max: 365 },
  {
    key: 'privileged_window_minutes',
    label: 'Re-authentication window (minutes)',
    min: 1,
    max: 120,
  },
  { key: 'max_concurrent_sessions', label: 'Maximum concurrent sessions', min: 1, max: 100 },
  { key: 'trusted_device_days', label: 'Trusted-device duration (days)', min: 1, max: 365 },
];

export function SessionManagementPage() {
  const { token, user, logout } = useAuth();
  const { toast } = useToast();
  const [sessions, setSessions] = useState<UserSession[]>([]);
  const [policy, setPolicy] = useState<SessionPolicy | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [sessionRows, sessionPolicy] = await Promise.all([
        api.listMySessions(token),
        user?.role === 'administrator' ? api.sessionPolicy(token) : Promise.resolve(null),
      ]);
      setSessions(sessionRows);
      setPolicy(sessionPolicy);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load sessions.');
    } finally {
      setLoading(false);
    }
  }, [token, user?.role]);

  useEffect(() => {
    void load();
  }, [load]);

  async function revoke(session: UserSession) {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await api.revokeMySession(token, session.id);
      if (session.current) {
        await logout();
        return;
      }
      toast('success', 'Session revoked.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not revoke this session.');
    } finally {
      setBusy(false);
    }
  }

  async function revokeAll() {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await api.logoutAll(token);
      await logout();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not sign out all sessions.');
      setBusy(false);
    }
  }

  async function savePolicy(event: FormEvent) {
    event.preventDefault();
    if (!token || !policy) return;
    setBusy(true);
    setError(null);
    try {
      const updated = await api.updateSessionPolicy(token, policy);
      setPolicy(updated);
      toast('success', 'Session policy updated. Existing sessions keep their issued limits.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not update the session policy.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div aria-label="Sessions">
      <PageHeader
        crumbs={[{ label: 'Administration' }, { label: 'Sessions' }]}
        title="Sessions"
        description="Review signed-in devices and immediately revoke access."
        actions={
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => void load()} disabled={busy}>
              <RefreshCw size={14} aria-hidden /> Refresh
            </Button>
            <Button variant="destructive" onClick={() => void revokeAll()} loading={busy}>
              <LogOut size={14} aria-hidden /> Sign out everywhere
            </Button>
          </div>
        }
      />
      {error && <InlineError message={error} className="mb-4" />}
      {loading ? (
        <div className="rounded-xl border border-border bg-surface">
          <CardSkeleton lines={4} />
        </div>
      ) : (
        <div className="grid gap-3">
          {sessions.length === 0 && (
            <p className="rounded-lg border border-border p-4 text-sm text-faint">
              No session records are available.
            </p>
          )}
          {sessions.map((session) => (
            <section
              key={session.id}
              className="flex flex-col gap-3 rounded-xl border border-border bg-surface p-4 sm:flex-row sm:items-center sm:justify-between"
            >
              <div className="flex min-w-0 gap-3">
                <Smartphone className="mt-0.5 shrink-0 text-muted" size={18} aria-hidden />
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="text-sm font-semibold text-text">
                      {session.device_name || 'Unnamed device'}
                    </h2>
                    {session.current && <Badge tone="accent">Current</Badge>}
                    <Badge tone={session.active ? 'ok' : 'neutral'}>
                      {session.active ? 'Active' : 'Revoked or expired'}
                    </Badge>
                    {session.trusted_until && <Badge tone="neutral">Trusted device</Badge>}
                    {(session.authentication_methods ?? []).length > 0 && (
                      <Badge tone="ok">{session.authentication_methods.join(' + ')}</Badge>
                    )}
                  </div>
                  <p className="mt-1 break-words text-xs text-muted">
                    {session.source_ip || 'Unknown IP'} · Last seen{' '}
                    {formatWhenFull(session.last_seen_at)}
                  </p>
                  <p className="mt-1 break-words text-xs text-faint">
                    {session.user_agent || 'Unknown browser'} · Absolute expiry{' '}
                    {formatWhenFull(session.absolute_expires_at)}
                  </p>
                </div>
              </div>
              {session.active && (
                <Button
                  variant="outline"
                  size="sm"
                  loading={busy}
                  onClick={() => void revoke(session)}
                >
                  Revoke
                </Button>
              )}
            </section>
          ))}
        </div>
      )}
      {user?.role === 'administrator' && policy && (
        <section className="mt-6 rounded-xl border border-border bg-surface p-4">
          <div className="mb-4 flex items-start gap-3">
            <ShieldCheck className="mt-0.5 shrink-0 text-accent" size={18} aria-hidden />
            <div>
              <h2 className="text-sm font-semibold text-text">Organization session policy</h2>
              <p className="mt-1 text-xs text-muted">
                These limits apply when new sessions are issued. Revocation is always immediate.
              </p>
            </div>
          </div>
          <form className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3" onSubmit={savePolicy}>
            {POLICY_FIELDS.map((field) => (
              <Field key={field.key} label={field.label} htmlFor={`session-${field.key}`}>
                <Input
                  id={`session-${field.key}`}
                  type="number"
                  min={field.min}
                  max={field.max}
                  required
                  value={policy[field.key]}
                  onChange={(event) =>
                    setPolicy((current) =>
                      current ? { ...current, [field.key]: Number(event.target.value) } : current,
                    )
                  }
                />
              </Field>
            ))}
            <div className="flex items-end justify-end sm:col-span-2 lg:col-span-3">
              <Button type="submit" variant="primary" loading={busy}>
                Save session policy
              </Button>
            </div>
          </form>
        </section>
      )}
    </div>
  );
}
