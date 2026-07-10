import type { CurrentUser, TokenResponse } from '../types/auth';
import type { NetworkScope, NewScope, NewSite, Page, Site } from '../types/inventory';
import type { HealthResponse, SystemInfoResponse } from '../types/system';

// In development, Vite proxies /api to the backend (see vite.config.ts).
// In production the frontend is served behind the same reverse proxy as the API.
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? '';

/** Error carrying the HTTP status so callers can react (e.g. 401 -> logout). */
export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

interface RequestOptions {
  method?: string;
  token?: string | null;
  body?: unknown;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', token, body } = options;
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const data = (await response.json()) as { detail?: string };
      if (typeof data.detail === 'string') {
        detail = data.detail;
      }
    } catch {
      // Non-JSON error body; fall back to the status text.
    }
    throw new ApiError(response.status, detail);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export const api = {
  login(email: string, password: string): Promise<TokenResponse> {
    return request<TokenResponse>('/api/v1/auth/login', {
      method: 'POST',
      body: { email, password },
    });
  },
  me(token: string): Promise<CurrentUser> {
    return request<CurrentUser>('/api/v1/auth/me', { token });
  },
  listSites(token: string): Promise<Page<Site>> {
    return request<Page<Site>>('/api/v1/sites', { token });
  },
  createSite(token: string, payload: NewSite): Promise<Site> {
    return request<Site>('/api/v1/sites', { method: 'POST', token, body: payload });
  },
  listScopes(token: string, siteId?: string): Promise<Page<NetworkScope>> {
    const query = siteId ? `?site_id=${encodeURIComponent(siteId)}` : '';
    return request<Page<NetworkScope>>(`/api/v1/scopes${query}`, { token });
  },
  createScope(token: string, payload: NewScope): Promise<NetworkScope> {
    return request<NetworkScope>('/api/v1/scopes', { method: 'POST', token, body: payload });
  },
};

// --- Unauthenticated health/system endpoints (used by HealthPage) ---

export function fetchHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/health');
}

export function fetchSystemInfo(): Promise<SystemInfoResponse> {
  return request<SystemInfoResponse>('/api/v1/system/info');
}
