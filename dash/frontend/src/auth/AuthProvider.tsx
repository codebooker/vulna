import { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../api/client';
import type { CurrentUser, TokenResponse } from '../types/auth';
import { AuthContext, type AuthContextValue } from './AuthContext';

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

  const clear = useCallback(() => {
    setToken(null);
    setUser(null);
    setExpiresAt(null);
  }, []);

  const applyToken = useCallback((response: TokenResponse) => {
    setToken(response.access_token);
    setExpiresAt(Date.now() + response.expires_in * 1000);
  }, []);

  const logout = useCallback(() => {
    const current = token;
    clear();
    if (current) void api.logout(current).catch(() => undefined);
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
    if (!token || expiresAt === null) return;
    const delay = Math.max(1_000, expiresAt - Date.now() - 60_000);
    const timer = window.setTimeout(() => {
      void api.refreshAccess().then(applyToken).catch(clear);
    }, delay);
    return () => window.clearTimeout(timer);
  }, [applyToken, clear, expiresAt, token]);

  const login = useCallback(
    async (email: string, password: string, trustDevice = false) => {
      const response = await api.login(email, password, trustDevice);
      try {
        const current = await api.me(response.access_token);
        applyToken(response);
        setUser(current);
      } catch (error) {
        await api.logout(response.access_token).catch(() => undefined);
        throw error;
      }
    },
    [applyToken],
  );

  const value = useMemo<AuthContextValue>(
    () => ({ user, token, initializing, login, logout }),
    [user, token, initializing, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
