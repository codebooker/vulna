import { createContext } from 'react';
import type { CurrentUser, MfaVerification } from '../types/auth';

export interface PendingMfa {
  enrollmentRequired: boolean;
  methods: string[];
  graceExpiresAt: string | null;
}

export interface AuthContextValue {
  user: CurrentUser | null;
  token: string | null;
  /** True while the initial token-restore check is in flight. */
  initializing: boolean;
  login: (email: string, password: string, trustDevice?: boolean) => Promise<void>;
  pendingMfa: PendingMfa | null;
  completeMfa: (verification: MfaVerification) => Promise<void>;
  logout: () => Promise<void>;
}

export const AuthContext = createContext<AuthContextValue | null>(null);
