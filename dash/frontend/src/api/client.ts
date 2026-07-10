import type { CurrentUser, TokenResponse } from '../types/auth';
import type { ChangeEvent, NetworkScope, NewScope, NewSite, Page, Site } from '../types/inventory';
import type { FeedHealth, SyncResult } from '../types/intelligence';
import type {
  ComponentHealth,
  CompleteStepPayload,
  DemoTarget,
  JobSummary,
  NetworkCandidates,
  OnboardingState,
  ProbeSummary,
  RecoveryCodes,
  ScanPreset,
  ScanSummary,
  ScopePreview,
} from '../types/onboarding';
import type { Preset, PresetPreview } from '../types/presets';
import type { EnrollmentCommand } from '../types/remote';
import type { Report } from '../types/report';
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
  listChanges(token: string, limit = 20): Promise<Page<ChangeEvent>> {
    return request<Page<ChangeEvent>>(`/api/v1/changes?limit=${limit}`, { token });
  },
  listFeedHealth(token: string): Promise<FeedHealth[]> {
    return request<FeedHealth[]>('/api/v1/feeds/health', { token });
  },
  syncFeed(token: string, source: string): Promise<SyncResult> {
    return request<SyncResult>(`/api/v1/feeds/${encodeURIComponent(source)}/sync`, {
      method: 'POST',
      token,
    });
  },
  listReports(token: string, limit = 50): Promise<Page<Report>> {
    return request<Page<Report>>(`/api/v1/reports?limit=${limit}`, { token });
  },
  async downloadReport(token: string, id: string): Promise<Blob> {
    const response = await fetch(`${API_BASE}/api/v1/reports/${encodeURIComponent(id)}/download`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) {
      throw new ApiError(response.status, response.statusText);
    }
    return response.blob();
  },

  // --- Guided first-run (onboarding) ---
  onboardingState(token: string): Promise<OnboardingState> {
    return request<OnboardingState>('/api/v1/onboarding/state', { token });
  },
  completeOnboardingStep(token: string, payload: CompleteStepPayload): Promise<OnboardingState> {
    return request<OnboardingState>('/api/v1/onboarding/state/complete-step', {
      method: 'POST',
      token,
      body: payload,
    });
  },
  dismissOnboarding(token: string): Promise<OnboardingState> {
    return request<OnboardingState>('/api/v1/onboarding/state/dismiss', { method: 'POST', token });
  },
  generateRecoveryCodes(token: string): Promise<RecoveryCodes> {
    return request<RecoveryCodes>('/api/v1/onboarding/recovery-codes', { method: 'POST', token });
  },
  networkCandidates(token: string): Promise<NetworkCandidates> {
    return request<NetworkCandidates>('/api/v1/onboarding/network-candidates', { token });
  },
  scopePreview(token: string, cidr: string, allowPublic = false): Promise<ScopePreview> {
    return request<ScopePreview>('/api/v1/onboarding/scope-preview', {
      method: 'POST',
      token,
      body: { cidr, allow_public: allowPublic },
    });
  },
  scanPresets(token: string): Promise<{ presets: ScanPreset[] }> {
    return request<{ presets: ScanPreset[] }>('/api/v1/onboarding/scan-presets', { token });
  },
  scanSummary(
    token: string,
    preset: string,
    targets: string[],
    demo = false,
  ): Promise<ScanSummary> {
    return request<ScanSummary>('/api/v1/onboarding/scan-summary', {
      method: 'POST',
      token,
      body: { preset, targets, demo },
    });
  },
  demoTarget(token: string): Promise<DemoTarget> {
    return request<DemoTarget>('/api/v1/onboarding/demo-target', { token });
  },
  componentHealth(token: string): Promise<ComponentHealth> {
    return request<ComponentHealth>('/api/v1/system/component-health', { token });
  },
  listProbes(token: string): Promise<Page<ProbeSummary>> {
    return request<Page<ProbeSummary>>('/api/v1/probes', { token });
  },
  createJob(token: string, probeId: string, targets: string[]): Promise<JobSummary> {
    return request<JobSummary>('/api/v1/jobs', {
      method: 'POST',
      token,
      body: { probe_id: probeId, targets, mode: 'vulnerability_assessment' },
    });
  },

  // --- Scan presets (Phase 21) ---
  listPresets(token: string): Promise<{ presets: Preset[] }> {
    return request<{ presets: Preset[] }>('/api/v1/presets', { token });
  },
  previewPreset(token: string, presetKey: string, hostCount = 1): Promise<PresetPreview> {
    return request<PresetPreview>('/api/v1/presets/preview', {
      method: 'POST',
      token,
      body: { preset_key: presetKey, host_count: hostCount },
    });
  },

  // --- Add VulnaScout (remote enrollment) ---
  addScout(token: string, siteId: string, probeName = 'remote-scout'): Promise<EnrollmentCommand> {
    return request<EnrollmentCommand>('/api/v1/probes/enrollment-command', {
      method: 'POST',
      token,
      body: { site_id: siteId, probe_name: probeName },
    });
  },
};

// --- Unauthenticated health/system endpoints (used by HealthPage) ---

export function fetchHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/health');
}

export function fetchSystemInfo(): Promise<SystemInfoResponse> {
  return request<SystemInfoResponse>('/api/v1/system/info');
}
