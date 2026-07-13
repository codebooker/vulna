import { createContext } from 'react';
import type { CurrentUser } from '../types/auth';

export interface AuthContextValue {
  user: CurrentUser | null;
  token: string | null;
  /** True while the initial token-restore check is in flight. */
  initializing: boolean;
  login: (email: string, password: string, trustDevice?: boolean) => Promise<void>;
  logout: () => void;
}

export const AuthContext = createContext<AuthContextValue | null>(null);
