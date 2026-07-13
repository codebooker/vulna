import { useEffect, useState, type FormEvent } from 'react';
import { KeyRound } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { Button } from '../components/ui/button';
import { Field, Input } from '../components/ui/input';
import { InlineError } from '../components/ui/states';
import { HealthPage } from './HealthPage';
import { MfaChallengePage } from './MfaChallengePage';
import type { PublicIdentityProvider } from '../types/sso';

/** Sign-in form (kept as its own component; also rendered by tests). */
export function LoginPage() {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [trustDevice, setTrustDevice] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [providers, setProviders] = useState<PublicIdentityProvider[]>([]);
  const [ssoProviderId, setSsoProviderId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void api
      .publicIdentityProviders()
      .then((value) => {
        if (!cancelled) setProviders(value);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(email, password, trustDevice);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setError('Invalid email or password.');
      } else {
        setError(err instanceof Error ? err.message : 'Login failed.');
      }
    } finally {
      setSubmitting(false);
    }
  }

  async function handleSso(provider: PublicIdentityProvider) {
    setError(null);
    setSsoProviderId(provider.id);
    try {
      const start = await api.startSso(provider.id);
      window.location.assign(start.authorization_url);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'SSO sign-in could not be started.');
      setSsoProviderId(null);
    }
  }

  return (
    <div>
      <h2 className="mb-3 text-base font-semibold text-text">Sign in</h2>
      <form className="flex flex-col gap-3" onSubmit={handleSubmit}>
        <Field label="Email" htmlFor="login-email">
          <Input
            id="login-email"
            type="email"
            autoComplete="username"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </Field>
        <Field label="Password" htmlFor="login-password">
          <Input
            id="login-password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </Field>
        <label className="flex items-center gap-2 text-xs text-muted">
          <input
            type="checkbox"
            checked={trustDevice}
            onChange={(event) => setTrustDevice(event.target.checked)}
          />
          Trust this device for future authentication checks
        </label>
        {error && <InlineError message={error} />}
        <Button
          type="submit"
          variant="primary"
          loading={submitting}
          className="mt-1 w-full justify-center"
        >
          {submitting ? 'Signing in…' : 'Sign in'}
        </Button>
      </form>
      {providers.length > 0 && (
        <div className="mt-4 border-t border-border pt-4">
          <p className="mb-2 text-center text-[11px] font-medium uppercase tracking-wide text-faint">
            Organization sign-in
          </p>
          <div className="flex flex-col gap-2">
            {providers.map((provider) => (
              <Button
                key={provider.id}
                type="button"
                variant="outline"
                loading={ssoProviderId === provider.id}
                disabled={ssoProviderId !== null}
                className="w-full justify-center"
                onClick={() => void handleSso(provider)}
              >
                <KeyRound size={14} aria-hidden /> Sign in with {provider.name}
              </Button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/** Full-screen login layout with brand and backend status. */
export function LoginScreen() {
  const { pendingMfa } = useAuth();
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
          {pendingMfa ? <MfaChallengePage /> : <LoginPage />}
          <div className="mt-4 border-t border-border pt-3">
            <HealthPage />
          </div>
        </div>
        <p className="mt-4 text-center text-xs text-faint">
          Self-hosted security assessment across every site.
        </p>
      </div>
    </div>
  );
}
