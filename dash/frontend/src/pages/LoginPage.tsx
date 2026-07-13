import { useState, type FormEvent } from 'react';
import { ApiError } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { Button } from '../components/ui/button';
import { Field, Input } from '../components/ui/input';
import { InlineError } from '../components/ui/states';
import { HealthPage } from './HealthPage';

/** Sign-in form (kept as its own component; also rendered by tests). */
export function LoginPage() {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [trustDevice, setTrustDevice] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

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
    </div>
  );
}

/** Full-screen login layout with brand and backend status. */
export function LoginScreen() {
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
          <LoginPage />
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
