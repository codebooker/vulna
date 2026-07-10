import type { HealthResponse, SystemInfoResponse } from '../types/system';

// In development, Vite proxies /api to the backend (see vite.config.ts).
// In production the frontend is served behind the same reverse proxy as the API.
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? '';

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { Accept: 'application/json' },
  });
  if (!response.ok) {
    throw new Error(`Request to ${path} failed with status ${response.status}`);
  }
  return (await response.json()) as T;
}

export function fetchHealth(): Promise<HealthResponse> {
  return getJson<HealthResponse>('/health');
}

export function fetchSystemInfo(): Promise<SystemInfoResponse> {
  return getJson<SystemInfoResponse>('/api/v1/system/info');
}
