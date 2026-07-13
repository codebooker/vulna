import { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../api/client';
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

  const clear = useCallback(() => {
    setToken(null);
    setUser(null);
    setExpiresAt(null);
    setPendingMfa(null);
  }, []);

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

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
