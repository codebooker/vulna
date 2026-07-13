import { useState, type FormEvent } from 'react';
import { KeyRound, ShieldCheck } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { Button } from '../components/ui/button';
import { Field, Input } from '../components/ui/input';
import { InlineError } from '../components/ui/states';
import { createWebAuthnCredential, getWebAuthnCredential } from '../lib/webauthn';
import type { MfaVerification, RecoveryCodes, TotpSetup } from '../types/auth';

export function RecoveryCodeDisplay({
  recovery,
  onContinue,
}: {
  recovery: RecoveryCodes;
  onContinue: () => void;
}) {
  return (
    <div>
      <h2 className="text-base font-semibold text-text">Save your recovery codes</h2>
      <p className="mt-1 text-xs text-muted">
        Each code works once. These values are shown only now and cannot be recovered later.
      </p>
      <pre className="my-4 grid grid-cols-2 gap-2 rounded-lg border border-border bg-bg p-3 text-xs text-text">
        {recovery.codes.map((code) => (
          <span key={code}>{code}</span>
        ))}
      </pre>
      <Button variant="primary" className="w-full justify-center" onClick={onContinue}>
        I saved these codes
      </Button>
    </div>
  );
}

export function MfaEnrollment({ onComplete }: { onComplete: (value: MfaVerification) => void }) {
  const { token } = useAuth();
  const [setup, setSetup] = useState<TotpSetup | null>(null);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [completion, setCompletion] = useState<{
    verification: MfaVerification;
    recovery: RecoveryCodes | null;
  } | null>(null);

  if (completion?.recovery) {
    return (
      <RecoveryCodeDisplay
        recovery={completion.recovery}
        onContinue={() => onComplete(completion.verification)}
      />
    );
  }

  async function beginTotp() {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      setSetup(await api.beginTotp(token));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start enrollment.');
    } finally {
      setBusy(false);
    }
  }

  async function confirm(event: FormEvent) {
    event.preventDefault();
    if (!token || !setup) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.confirmTotp(token, setup.factor_id, code);
      setCompletion({ verification: result.verification, recovery: result.recovery_codes });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The verification code was rejected.');
    } finally {
      setBusy(false);
    }
  }

  async function registerWebAuthn() {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      const begin = await api.beginWebAuthnRegistration(token);
      const credential = await createWebAuthnCredential(begin.public_key);
      const result = await api.finishWebAuthnRegistration(
        token,
        begin.challenge_id,
        credential,
        'Security key',
      );
      if (result.recovery_codes) {
        setCompletion({ verification: result.verification, recovery: result.recovery_codes });
      } else {
        onComplete(result.verification);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Security-key enrollment failed.');
    } finally {
      setBusy(false);
    }
  }

  if (setup) {
    return (
      <form onSubmit={confirm}>
        <h2 className="text-base font-semibold text-text">Add an authenticator app</h2>
        <p className="mt-1 text-xs text-muted">
          Scan the QR-compatible URI or enter this one-time secret in your authenticator.
        </p>
        <code className="my-3 block break-all rounded-lg border border-border bg-bg p-3 text-xs">
          {setup.secret}
        </code>
        <Field label="Six-digit code" htmlFor="mfa-enrollment-code">
          <Input
            id="mfa-enrollment-code"
            inputMode="numeric"
            autoComplete="one-time-code"
            value={code}
            onChange={(event) => setCode(event.target.value)}
            required
          />
        </Field>
        {error && <InlineError message={error} className="mt-3" />}
        <Button
          type="submit"
          variant="primary"
          loading={busy}
          className="mt-3 w-full justify-center"
        >
          Verify and enable
        </Button>
      </form>
    );
  }

  return (
    <div>
      <h2 className="text-base font-semibold text-text">Set up multi-factor authentication</h2>
      <p className="mt-1 text-xs text-muted">
        Add an authenticator app or a passkey/security key. Security controls remain active in every
        experience profile.
      </p>
      {error && <InlineError message={error} className="mt-3" />}
      <div className="mt-4 grid gap-2">
        <Button variant="outline" loading={busy} onClick={() => void beginTotp()}>
          <ShieldCheck size={15} /> Authenticator app
        </Button>
        <Button variant="outline" loading={busy} onClick={() => void registerWebAuthn()}>
          <KeyRound size={15} /> Passkey or security key
        </Button>
      </div>
    </div>
  );
}

export function MfaChallengePage() {
  const { token, pendingMfa, completeMfa, logout } = useAuth();
  const [method, setMethod] = useState<'totp' | 'recovery_code'>('totp');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!pendingMfa) return null;
  if (
    pendingMfa.enrollmentRequired &&
    !pendingMfa.methods.some((item) => item !== 'recovery_code')
  ) {
    return <MfaEnrollment onComplete={(result) => void completeMfa(result)} />;
  }

  async function verify(event: FormEvent) {
    event.preventDefault();
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      const result =
        method === 'totp'
          ? await api.verifyTotp(token, code)
          : await api.verifyRecoveryCode(token, code);
      await completeMfa(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed.');
    } finally {
      setBusy(false);
    }
  }

  async function verifyWebAuthn() {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      const begin = await api.beginWebAuthnAuthentication(token);
      const credential = await getWebAuthnCredential(begin.public_key);
      await completeMfa(
        await api.finishWebAuthnAuthentication(token, begin.challenge_id, credential),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Security-key verification failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h2 className="text-base font-semibold text-text">Verify your identity</h2>
      <p className="mt-1 text-xs text-muted">Complete multi-factor authentication to continue.</p>
      {pendingMfa.methods.includes('webauthn') && (
        <Button
          className="mt-4 w-full justify-center"
          loading={busy}
          onClick={() => void verifyWebAuthn()}
        >
          <KeyRound size={15} /> Use a passkey or security key
        </Button>
      )}
      {(pendingMfa.methods.includes('totp') || pendingMfa.methods.includes('recovery_code')) && (
        <form className="mt-4" onSubmit={verify}>
          <Field
            label={method === 'totp' ? 'Authenticator code' : 'Recovery code'}
            htmlFor="mfa-login-code"
          >
            <Input
              id="mfa-login-code"
              autoComplete="one-time-code"
              value={code}
              onChange={(event) => setCode(event.target.value)}
              required
            />
          </Field>
          {error && <InlineError message={error} className="mt-3" />}
          <Button
            type="submit"
            variant="primary"
            loading={busy}
            className="mt-3 w-full justify-center"
          >
            Verify
          </Button>
          {pendingMfa.methods.includes('recovery_code') && (
            <Button
              variant="ghost"
              className="mt-1 w-full justify-center"
              onClick={() => setMethod(method === 'totp' ? 'recovery_code' : 'totp')}
            >
              {method === 'totp' ? 'Use a recovery code' : 'Use an authenticator code'}
            </Button>
          )}
        </form>
      )}
      <Button variant="ghost" className="mt-2 w-full justify-center" onClick={() => void logout()}>
        Cancel sign-in
      </Button>
    </div>
  );
}
