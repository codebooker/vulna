import { useState, type FormEvent } from 'react';
import { api } from '../api/client';
import { Button } from '../components/ui/button';
import { Field, Input } from '../components/ui/input';
import { InlineError } from '../components/ui/states';

export function AccountSetupScreen({
  mode,
  token,
}: {
  mode: 'invitation' | 'password-reset';
  token: string | null;
}) {
  const [fullName, setFullName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [complete, setComplete] = useState(false);
  const invitation = mode === 'invitation';

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!token) {
      setError('This link is missing its one-time token. Ask an administrator for a new link.');
      return;
    }
    if (password !== confirmation) {
      setError('Passwords do not match.');
      return;
    }
    setError(null);
    setSubmitting(true);
    try {
      if (invitation) await api.acceptInvitation(token, password, fullName.trim());
      else await api.completePasswordReset(token, password);
      setComplete(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The one-time link could not be used.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg px-4">
      <div className="w-full max-w-sm">
        <div className="mb-5 flex items-center justify-center gap-2.5">
          <img src="/vulna-mark.svg" alt="" width={32} height={32} />
          <h1 className="text-xl font-bold text-text">
            Vulna<span className="text-accent">Dash</span>
          </h1>
        </div>
        <div className="rounded-xl border border-border bg-surface p-5 shadow-[var(--shadow-md)]">
          <h2 className="text-base font-semibold text-text">
            {complete
              ? 'Password saved'
              : invitation
                ? 'Accept your invitation'
                : 'Choose a new password'}
          </h2>
          {complete ? (
            <div className="mt-3 flex flex-col gap-4">
              <p className="text-[13px] text-muted">
                {invitation
                  ? 'Your account is active. You can now sign in.'
                  : 'Your password was updated and existing access credentials were revoked.'}
              </p>
              <Button
                variant="primary"
                className="justify-center"
                onClick={() => {
                  window.location.hash = '';
                }}
              >
                Continue to sign in
              </Button>
            </div>
          ) : (
            <form className="mt-3 flex flex-col gap-3" onSubmit={submit}>
              {invitation && (
                <Field label="Full name" htmlFor="account-full-name" hint="Optional">
                  <Input
                    id="account-full-name"
                    autoComplete="name"
                    value={fullName}
                    onChange={(event) => setFullName(event.target.value)}
                  />
                </Field>
              )}
              <Field label="New password" htmlFor="account-password" hint="At least 12 characters">
                <Input
                  id="account-password"
                  type="password"
                  autoComplete="new-password"
                  minLength={12}
                  required
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                />
              </Field>
              <Field label="Confirm password" htmlFor="account-password-confirmation">
                <Input
                  id="account-password-confirmation"
                  type="password"
                  autoComplete="new-password"
                  minLength={12}
                  required
                  value={confirmation}
                  onChange={(event) => setConfirmation(event.target.value)}
                />
              </Field>
              {error && <InlineError message={error} />}
              <Button
                type="submit"
                variant="primary"
                loading={submitting}
                className="justify-center"
              >
                {invitation ? 'Activate account' : 'Update password'}
              </Button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
