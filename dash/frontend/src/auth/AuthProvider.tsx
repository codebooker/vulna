import { useCallback, useEffect, useMemo, useState } from 'react';
import { ApiError, api } from '../api/client';
import type { CurrentUser } from '../types/auth';
import { AuthContext, TOKEN_STORAGE_KEY, type AuthContextValue } from './AuthContext';

function readStoredToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    return null;
  }
}

function persistToken(token: string | null): void {
  try {
    if (token) {
      localStorage.setItem(TOKEN_STORAGE_KEY, token);
    } else {
      localStorage.removeItem(TOKEN_STORAGE_KEY);
    }
  } catch {
    // Storage may be unavailable (private mode); the session still works in-memory.
  }
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(() => readStoredToken());
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [initializing, setInitializing] = useState(true);

  const logout = useCallback(() => {
    setToken(null);
    setUser(null);
    persistToken(null);
  }, []);

  // On mount, if a token was restored from storage, verify it and load the user.
  useEffect(() => {
    let cancelled = false;
    async function restore() {
      if (!token) {
        setInitializing(false);
        return;
      }
      try {
        const me = await api.me(token);
        if (!cancelled) {
          setUser(me);
        }
      } catch (err) {
        if (!cancelled && err instanceof ApiError && err.status === 401) {
          logout();
        }
      } finally {
        if (!cancelled) {
          setInitializing(false);
        }
      }
    }
    void restore();
    return () => {
      cancelled = true;
    };
    // Run once on mount for the restored token.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const { access_token } = await api.login(email, password);
    const me = await api.me(access_token);
    setToken(access_token);
    setUser(me);
    persistToken(access_token);
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({ user, token, initializing, login, logout }),
    [user, token, initializing, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
