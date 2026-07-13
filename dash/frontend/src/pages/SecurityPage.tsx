import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { KeyRound, RefreshCw, ShieldCheck, Trash2 } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { PageHeader } from '../components/app/page-header';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Field, Input, Select } from '../components/ui/input';
import { CardSkeleton, InlineError } from '../components/ui/states';
import { formatWhenFull } from '../lib/utils';
import type { MfaPolicy, MfaStatus, RecoveryCodes, WebAuthnCredentialSummary } from '../types/auth';
import { MfaEnrollment, RecoveryCodeDisplay } from './MfaChallengePage';

export function SecurityPage() {
  const { token, user, completeMfa } = useAuth();
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [credentials, setCredentials] = useState<WebAuthnCredentialSummary[]>([]);
  const [policy, setPolicy] = useState<MfaPolicy | null>(null);
  const [enrolling, setEnrolling] = useState(false);
  const [recovery, setRecovery] = useState<RecoveryCodes | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [mfaStatus, keys, organizationPolicy] = await Promise.all([
        api.mfaStatus(token),
        api.listWebAuthnCredentials(token),
        user?.role === 'administrator' ? api.mfaPolicy(token) : Promise.resolve(null),
      ]);
      setStatus(mfaStatus);
      setCredentials(keys);
      setPolicy(organizationPolicy);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load security settings.');
    } finally {
      setLoading(false);
    }
  }, [token, user?.role]);

  useEffect(() => {
    void load();
  }, [load]);

  async function removeTotp() {
    if (!token) return;
    setBusy(true);
    try {
      await api.disableTotp(token);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not remove the authenticator.');
    } finally {
      setBusy(false);
    }
  }

  async function removeCredential(id: string) {
    if (!token) return;
    setBusy(true);
    try {
      await api.disableWebAuthnCredential(token, id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not remove the credential.');
    } finally {
      setBusy(false);
    }
  }

  async function regenerate() {
    if (!token) return;
    setBusy(true);
    try {
      setRecovery(await api.regenerateRecoveryCodes(token));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not replace recovery codes.');
    } finally {
      setBusy(false);
    }
  }

  async function savePolicy(event: FormEvent) {
    event.preventDefault();
    if (!token || !policy) return;
    setBusy(true);
    try {
      setPolicy(await api.updateMfaPolicy(token, policy));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not update MFA policy.');
    } finally {
      setBusy(false);
    }
  }

  if (recovery) {
    return (
      <div className="mx-auto max-w-xl rounded-xl border border-border bg-surface p-5">
        <RecoveryCodeDisplay recovery={recovery} onContinue={() => setRecovery(null)} />
      </div>
    );
  }

  return (
    <div aria-label="Account security">
      <PageHeader
        crumbs={[{ label: 'Administration' }, { label: 'Security' }]}
        title="Account security"
        description="Manage authenticator apps, passkeys, recovery codes, and organization MFA enforcement."
        actions={
          <Button variant="outline" onClick={() => void load()} disabled={busy}>
            <RefreshCw size={14} /> Refresh
          </Button>
        }
      />
      {error && <InlineError message={error} className="mb-4" />}
      {loading ? (
        <CardSkeleton lines={5} />
      ) : enrolling ? (
        <section className="mx-auto max-w-xl rounded-xl border border-border bg-surface p-5">
          <MfaEnrollment
            onComplete={(verification) => {
              void completeMfa(verification).then(() => {
                setEnrolling(false);
                void load();
              });
            }}
          />
          <Button variant="ghost" className="mt-3" onClick={() => setEnrolling(false)}>
            Cancel
          </Button>
        </section>
      ) : (
        <div className="space-y-4">
          <section className="rounded-xl border border-border bg-surface p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <div className="flex items-center gap-2">
                  <ShieldCheck size={18} className="text-accent" />
                  <h2 className="text-sm font-semibold text-text">Multi-factor authentication</h2>
                  <Badge tone={status?.enrolled ? 'ok' : status?.required ? 'warn' : 'neutral'}>
                    {status?.enrolled ? 'Enrolled' : status?.required ? 'Required' : 'Optional'}
                  </Badge>
                </div>
                <p className="mt-2 text-xs text-muted">
                  {status?.recovery_codes_remaining ?? 0} unused recovery codes remain.
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button variant="outline" onClick={() => setEnrolling(true)}>
                  Add method
                </Button>
                {status?.enrolled && (
                  <Button variant="outline" loading={busy} onClick={() => void regenerate()}>
                    Replace recovery codes
                  </Button>
                )}
              </div>
            </div>
          </section>

          <section className="rounded-xl border border-border bg-surface p-4">
            <h2 className="mb-3 text-sm font-semibold text-text">Authentication methods</h2>
            <div className="space-y-2">
              {status?.totp && (
                <div className="flex items-center justify-between rounded-lg border border-border p-3 text-xs">
                  <span>
                    <ShieldCheck size={14} className="mr-2 inline text-accent" />
                    Authenticator app
                  </span>
                  <Button
                    size="sm"
                    variant="outline"
                    loading={busy}
                    onClick={() => void removeTotp()}
                  >
                    <Trash2 size={13} /> Remove
                  </Button>
                </div>
              )}
              {credentials.map((credential) => (
                <div
                  key={credential.id}
                  className="flex items-center justify-between rounded-lg border border-border p-3 text-xs"
                >
                  <span>
                    <KeyRound size={14} className="mr-2 inline text-accent" />
                    {credential.label} · Added {formatWhenFull(credential.created_at)}
                  </span>
                  <Button
                    size="sm"
                    variant="outline"
                    loading={busy}
                    onClick={() => void removeCredential(credential.id)}
                  >
                    <Trash2 size={13} /> Remove
                  </Button>
                </div>
              ))}
              {!status?.totp && credentials.length === 0 && (
                <p className="text-xs text-faint">No MFA method is enrolled.</p>
              )}
            </div>
          </section>

          {user?.role === 'administrator' && policy && (
            <section className="rounded-xl border border-border bg-surface p-4">
              <h2 className="text-sm font-semibold text-text">Organization MFA policy</h2>
              <p className="mt-1 text-xs text-muted">
                Required users receive an enrollment grace period; access fails closed after it
                expires.
              </p>
              <form className="mt-4 grid gap-3 sm:grid-cols-2" onSubmit={savePolicy}>
                <Field label="Enforcement" htmlFor="mfa-policy-mode">
                  <Select
                    id="mfa-policy-mode"
                    value={policy.mode}
                    onChange={(event) =>
                      setPolicy({ ...policy, mode: event.target.value as MfaPolicy['mode'] })
                    }
                  >
                    <option value="optional">Optional</option>
                    <option value="required">Required</option>
                  </Select>
                </Field>
                <Field label="Grace period (days)" htmlFor="mfa-grace-days">
                  <Input
                    id="mfa-grace-days"
                    type="number"
                    min={1}
                    max={30}
                    value={policy.grace_period_days}
                    onChange={(event) =>
                      setPolicy({ ...policy, grace_period_days: Number(event.target.value) })
                    }
                  />
                </Field>
                <div className="flex justify-end sm:col-span-2">
                  <Button type="submit" variant="primary" loading={busy}>
                    Save MFA policy
                  </Button>
                </div>
              </form>
            </section>
          )}
        </div>
      )}
    </div>
  );
}
