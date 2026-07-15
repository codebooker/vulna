import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api, setStepUpHandler } from '../api/client';
import { Button } from '../components/ui/button';
import { Field, Input } from '../components/ui/input';
import { Modal } from '../components/ui/overlay';
import { InlineError } from '../components/ui/states';
import type { CurrentUser, MfaVerification, TokenResponse } from '../types/auth';
import { AuthContext, type AuthContextValue, type PendingMfa } from './AuthContext';

const LEGACY_TOKEN_KEY = 'vulna.token';

function takeTestToken(): string | null {
  try {
    const value = import.meta.env.MODE === 'test' ? localStorage.getItem(LEGACY_TOKEN_KEY) : null;
    // Phase 35 intentionally rejects persisted stateless JWTs after upgrade.
    localStorage.removeItem(LEGACY_TOKEN_KEY);
    return value;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(() => takeTestToken());
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [expiresAt, setExpiresAt] = useState<number | null>(null);
  const [initializing, setInitializing] = useState(true);
  const [pendingMfa, setPendingMfa] = useState<PendingMfa | null>(null);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [stepUpPassword, setStepUpPassword] = useState('');
  const [stepUpError, setStepUpError] = useState<string | null>(null);
  const [stepUpBusy, setStepUpBusy] = useState(false);
  const stepUpPromise = useRef<{
    promise: Promise<void>;
    resolve: () => void;
    reject: (error: Error) => void;
  } | null>(null);

  const clear = useCallback(() => {
    stepUpPromise.current?.reject(new Error('Authentication session ended.'));
    stepUpPromise.current = null;
    setToken(null);
    setUser(null);
    setExpiresAt(null);
    setPendingMfa(null);
    setStepUpOpen(false);
    setStepUpPassword('');
    setStepUpError(null);
  }, []);

  const requestStepUp = useCallback(() => {
    if (stepUpPromise.current) return stepUpPromise.current.promise;
    let resolve!: () => void;
    let reject!: (error: Error) => void;
    const promise = new Promise<void>((onResolve, onReject) => {
      resolve = onResolve;
      reject = onReject;
    });
    stepUpPromise.current = { promise, resolve, reject };
    setStepUpPassword('');
    setStepUpError(null);
    setStepUpOpen(true);
    return promise;
  }, []);

  useEffect(() => {
    setStepUpHandler(requestStepUp);
    return () => setStepUpHandler(null);
  }, [requestStepUp]);

  const cancelStepUp = useCallback(() => {
    stepUpPromise.current?.reject(new Error('Recent authentication was cancelled.'));
    stepUpPromise.current = null;
    setStepUpOpen(false);
    setStepUpPassword('');
    setStepUpError(null);
  }, []);

  const submitStepUp = useCallback(async () => {
    if (!token || !stepUpPassword) return;
    setStepUpBusy(true);
    setStepUpError(null);
    try {
      await api.reauthenticate(token, stepUpPassword);
      const pending = stepUpPromise.current;
      stepUpPromise.current = null;
      setStepUpOpen(false);
      setStepUpPassword('');
      pending?.resolve();
    } catch (error) {
      setStepUpError(error instanceof Error ? error.message : 'Authentication failed.');
    } finally {
      setStepUpBusy(false);
    }
  }, [stepUpPassword, token]);

  const applyToken = useCallback((response: TokenResponse) => {
    setToken(response.access_token);
    setExpiresAt(Date.now() + response.expires_in * 1000);
  }, []);

  const logout = useCallback(async () => {
    const current = token;
    clear();
    if (current) await api.logout(current).catch(() => undefined);
  }, [clear, token]);

  useEffect(() => {
    let cancelled = false;
    async function restore() {
      try {
        if (token) {
          const current = await api.me(token);
          if (!cancelled) setUser(current);
          return;
        }
        const refreshed = await api.refreshAccess();
        const current = await api.me(refreshed.access_token);
        if (!cancelled) {
          applyToken(refreshed);
          setUser(current);
        }
      } catch {
        if (!cancelled) clear();
      } finally {
        if (!cancelled) setInitializing(false);
      }
    }
    void restore();
    return () => {
      cancelled = true;
    };
    // Initial cookie bootstrap runs once; later refreshes use the timer below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!token || expiresAt === null || pendingMfa) return;
    const delay = Math.max(1_000, expiresAt - Date.now() - 60_000);
    const timer = window.setTimeout(() => {
      void api.refreshAccess().then(applyToken).catch(clear);
    }, delay);
    return () => window.clearTimeout(timer);
  }, [applyToken, clear, expiresAt, pendingMfa, token]);

  const login = useCallback(
    async (email: string, password: string, trustDevice = false) => {
      const response = await api.login(email, password, trustDevice);
      applyToken(response);
      if (response.mfa_required) {
        setUser(null);
        setPendingMfa({
          enrollmentRequired: response.mfa_enrollment_required,
          methods: response.mfa_methods,
          graceExpiresAt: response.mfa_grace_expires_at,
        });
        return;
      }
      try {
        const current = await api.me(response.access_token);
        setUser(current);
      } catch (error) {
        await api.logout(response.access_token).catch(() => undefined);
        throw error;
      }
    },
    [applyToken],
  );

  const completeMfa = useCallback(
    async (verification: MfaVerification) => {
      const response: TokenResponse = {
        access_token: verification.access_token,
        token_type: verification.token_type,
        expires_in: verification.expires_in,
        session_id: null,
        mfa_required: false,
        mfa_enrollment_required: false,
        mfa_methods: [verification.method],
        mfa_grace_expires_at: null,
      };
      const current = await api.me(verification.access_token);
      applyToken(response);
      setPendingMfa(null);
      setUser(current);
    },
    [applyToken],
  );

  const value = useMemo<AuthContextValue>(
    () => ({ user, token, initializing, login, pendingMfa, completeMfa, logout }),
    [user, token, initializing, login, pendingMfa, completeMfa, logout],
  );

  return (
    <AuthContext.Provider value={value}>
      {children}
      <Modal
        open={stepUpOpen}
        onClose={cancelStepUp}
        title="Confirm your identity"
        description="This security-sensitive action requires your password again."
        footer={
          user?.authentication_source === 'local' ? (
            <>
              <Button variant="ghost" onClick={cancelStepUp}>
                Cancel
              </Button>
              <Button
                variant="primary"
                loading={stepUpBusy}
                disabled={!stepUpPassword}
                onClick={() => void submitStepUp()}
              >
                Continue
              </Button>
            </>
          ) : (
            <>
              <Button variant="ghost" onClick={cancelStepUp}>
                Cancel
              </Button>
              <Button
                variant="primary"
                onClick={() => {
                  cancelStepUp();
                  void logout();
                }}
              >
                Sign out to reauthenticate
              </Button>
            </>
          )
        }
      >
        <div className="flex flex-col gap-3">
          {user?.authentication_source === 'local' ? (
            <Field label="Password" htmlFor="step-up-password">
              <Input
                id="step-up-password"
                type="password"
                autoComplete="current-password"
                value={stepUpPassword}
                onChange={(event) => setStepUpPassword(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter') void submitStepUp();
                }}
              />
            </Field>
          ) : (
            <p className="text-xs text-muted">
              Accounts without a local password must sign out and authenticate with their identity
              provider again.
            </p>
          )}
          {stepUpError && <InlineError message={stepUpError} />}
        </div>
      </Modal>
    </AuthContext.Provider>
  );
}
