import type { CurrentUser, TokenResponse } from '../types/auth';
import type { ChangeEvent, NetworkScope, NewScope, NewSite, Page, Site } from '../types/inventory';
import type { Network, NewNetwork } from '../types/network';
import type { PentestSession, RulesOfEngagement } from '../types/pentest';
import type { NewSchedule, ScanSchedule } from '../types/schedule';
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
import type { BackupCenter } from '../types/backup';
import type { DashboardSummary, SearchResults } from '../types/dashboard';
import type { DiagnosticsResult, SupportBundle, TimelineEvent } from '../types/diagnostics';
import type { CleanupPreview, MaintenanceOverview, StorageBudgets } from '../types/maintenance';
import type {
  NewChannel,
  NotificationChannel,
  NotificationDelivery,
  NotificationEventDef,
} from '../types/notifications';
import type { DemoStatus, HelpTopic } from '../types/help';
import type {
  OutboundConnection,
  PrivacySettings,
  SecretItem,
  TelemetryPreview,
} from '../types/privacy';
import type { Relay, RelayEnrollment } from '../types/relay';
import type { Finding, Page as FindingPage } from '../types/finding';
import type { BrowserTest, NetworkStatus, ValidateResult } from '../types/networking';
import type { Preset, PresetPreview } from '../types/presets';
import type { EnrollmentCommand } from '../types/remote';
import type { Report } from '../types/report';
import type { HealthResponse, SystemInfoResponse } from '../types/system';
import type { UpdateCenter } from '../types/update';

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
  // --- Networks (named range groups bound to scouts) ---
  listNetworks(token: string): Promise<Network[]> {
    return request<Network[]>('/api/v1/networks', { token });
  },
  createNetwork(token: string, payload: NewNetwork): Promise<Network> {
    return request<Network>('/api/v1/networks', { method: 'POST', token, body: payload });
  },
  addNetworkRange(token: string, networkId: string, cidr: string): Promise<Network> {
    return request<Network>(`/api/v1/networks/${networkId}/ranges`, {
      method: 'POST',
      token,
      body: { cidr },
    });
  },
  bindNetworkScout(
    token: string,
    networkId: string,
    probeId: string,
    isPrimary: boolean,
  ): Promise<Network> {
    return request<Network>(`/api/v1/networks/${networkId}/scouts`, {
      method: 'POST',
      token,
      body: { probe_id: probeId, is_primary: isPrimary },
    });
  },
  unbindNetworkScout(token: string, networkId: string, probeId: string): Promise<Network> {
    return request<Network>(`/api/v1/networks/${networkId}/scouts/${probeId}`, {
      method: 'DELETE',
      token,
    });
  },
  deleteNetwork(token: string, networkId: string): Promise<void> {
    return request<void>(`/api/v1/networks/${networkId}`, { method: 'DELETE', token });
  },
  // --- Scheduled scans ---
  listSchedules(token: string): Promise<ScanSchedule[]> {
    return request<ScanSchedule[]>('/api/v1/schedules', { token });
  },
  createSchedule(token: string, payload: NewSchedule): Promise<ScanSchedule> {
    return request<ScanSchedule>('/api/v1/schedules', { method: 'POST', token, body: payload });
  },
  updateSchedule(
    token: string,
    id: string,
    patch: { enabled?: boolean; interval_minutes?: number; name?: string },
  ): Promise<ScanSchedule> {
    return request<ScanSchedule>(`/api/v1/schedules/${id}`, {
      method: 'PATCH',
      token,
      body: patch,
    });
  },
  runSchedule(token: string, id: string): Promise<ScanSchedule> {
    return request<ScanSchedule>(`/api/v1/schedules/${id}/run`, { method: 'POST', token });
  },
  deleteSchedule(token: string, id: string): Promise<void> {
    return request<void>(`/api/v1/schedules/${id}`, { method: 'DELETE', token });
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
  setProbePentest(token: string, probeId: string, enabled: boolean): Promise<ProbeSummary> {
    return request<ProbeSummary>(`/api/v1/probes/${probeId}/pentest`, {
      method: 'POST',
      token,
      body: { enabled },
    });
  },
  // --- Controlled pentest ---
  listRoE(token: string): Promise<RulesOfEngagement[]> {
    return request<RulesOfEngagement[]>('/api/v1/pentest/rules-of-engagement', { token });
  },
  createRoE(
    token: string,
    payload: { name: string; allowed_actions: string[]; cleanup_required: boolean },
  ): Promise<RulesOfEngagement> {
    return request<RulesOfEngagement>('/api/v1/pentest/rules-of-engagement', {
      method: 'POST',
      token,
      body: payload,
    });
  },
  listPentestSessions(token: string): Promise<Page<PentestSession>> {
    return request<Page<PentestSession>>('/api/v1/pentest/sessions', { token });
  },
  decidePentestSession(token: string, id: string, approve: boolean): Promise<PentestSession> {
    return request<PentestSession>(`/api/v1/pentest/sessions/${id}`, {
      method: 'PATCH',
      token,
      body: { approve },
    });
  },
  createJob(token: string, probeId: string, targets: string[]): Promise<JobSummary> {
    return request<JobSummary>('/api/v1/jobs', {
      method: 'POST',
      token,
      body: { probe_id: probeId, targets, mode: 'vulnerability_assessment' },
    });
  },

  // --- Update center (Phase 24, display only) ---
  updateCenter(token: string): Promise<UpdateCenter> {
    return request<UpdateCenter>('/api/v1/system/update', { token });
  },

  // --- Backup center (Phase 25, display only) ---
  backupCenter(token: string): Promise<BackupCenter> {
    return request<BackupCenter>('/api/v1/system/backups', { token });
  },

  // --- Diagnostics / Vulna Doctor (Phase 26) ---
  diagnostics(token: string): Promise<DiagnosticsResult> {
    return request<DiagnosticsResult>('/api/v1/diagnostics', { token });
  },
  diagnosticsTimeline(token: string): Promise<{ events: TimelineEvent[] }> {
    return request<{ events: TimelineEvent[] }>('/api/v1/diagnostics/timeline', { token });
  },
  supportBundle(token: string): Promise<SupportBundle> {
    return request<SupportBundle>('/api/v1/diagnostics/support-bundle', { token });
  },
  repair(token: string, action: string): Promise<unknown> {
    return request<unknown>('/api/v1/diagnostics/repair', {
      method: 'POST',
      token,
      body: { action, confirm: true },
    });
  },

  // --- Maintenance center (Phase 28) ---
  maintenance(token: string): Promise<MaintenanceOverview> {
    return request<MaintenanceOverview>('/api/v1/maintenance', { token });
  },
  maintenanceStorage(token: string): Promise<StorageBudgets> {
    return request<StorageBudgets>('/api/v1/maintenance/storage', { token });
  },
  retentionPreview(token: string): Promise<CleanupPreview> {
    return request<CleanupPreview>('/api/v1/maintenance/retention/preview', { token });
  },
  runCleanup(token: string, password: string): Promise<unknown> {
    return request<unknown>('/api/v1/maintenance/retention/cleanup', {
      method: 'POST',
      token,
      body: { confirm: true, password },
    });
  },

  // --- Notifications (Phase 29) ---
  notificationEvents(
    token: string,
  ): Promise<{ events: NotificationEventDef[]; policies: string[] }> {
    return request<{ events: NotificationEventDef[]; policies: string[] }>(
      '/api/v1/notifications/events',
      { token },
    );
  },
  listChannels(token: string): Promise<{ channels: NotificationChannel[] }> {
    return request<{ channels: NotificationChannel[] }>('/api/v1/notifications/channels', {
      token,
    });
  },
  createChannel(token: string, body: NewChannel): Promise<NotificationChannel> {
    return request<NotificationChannel>('/api/v1/notifications/channels', {
      method: 'POST',
      token,
      body,
    });
  },
  testChannel(token: string, id: string): Promise<unknown> {
    return request<unknown>(`/api/v1/notifications/channels/${id}/test`, { method: 'POST', token });
  },
  listDeliveries(token: string): Promise<{ deliveries: NotificationDelivery[] }> {
    return request<{ deliveries: NotificationDelivery[] }>('/api/v1/notifications/deliveries', {
      token,
    });
  },

  // --- Help & demo (Phase 30) ---
  helpTopics(token: string): Promise<{ topics: HelpTopic[] }> {
    return request<{ topics: HelpTopic[] }>('/api/v1/help/topics', { token });
  },
  exposureChecklist(token: string): Promise<{ checklist: string[] }> {
    return request<{ checklist: string[] }>('/api/v1/help/exposure-checklist', { token });
  },
  demoStatus(token: string): Promise<DemoStatus> {
    return request<DemoStatus>('/api/v1/demo/status', { token });
  },
  enableDemo(token: string): Promise<DemoStatus> {
    return request<DemoStatus>('/api/v1/demo/enable', { method: 'POST', token });
  },
  disableDemo(token: string): Promise<DemoStatus> {
    return request<DemoStatus>('/api/v1/demo/disable', { method: 'POST', token });
  },

  // --- Privacy & portability (Phase 31) ---
  privacyOutbound(token: string): Promise<{ connections: OutboundConnection[] }> {
    return request<{ connections: OutboundConnection[] }>('/api/v1/privacy/outbound', { token });
  },
  privacySecrets(token: string): Promise<{ secrets: SecretItem[] }> {
    return request<{ secrets: SecretItem[] }>('/api/v1/privacy/secrets', { token });
  },
  privacySettings(token: string): Promise<{ settings: PrivacySettings }> {
    return request<{ settings: PrivacySettings }>('/api/v1/privacy/settings', { token });
  },
  updatePrivacySettings(
    token: string,
    changes: Partial<PrivacySettings>,
  ): Promise<{ settings: PrivacySettings }> {
    return request<{ settings: PrivacySettings }>('/api/v1/privacy/settings', {
      method: 'POST',
      token,
      body: changes,
    });
  },
  telemetryPreview(token: string): Promise<TelemetryPreview> {
    return request<TelemetryPreview>('/api/v1/privacy/telemetry/preview', { token });
  },
  exportData(token: string): Promise<Record<string, unknown>> {
    return request<Record<string, unknown>>('/api/v1/portability/export', { token });
  },

  // --- VulnaRelay (Phase 16, opt-in) ---
  relaySettings(token: string): Promise<{ enabled: boolean }> {
    return request<{ enabled: boolean }>('/api/v1/relays/settings', { token });
  },
  setRelayEnabled(token: string, enabled: boolean): Promise<{ enabled: boolean }> {
    return request<{ enabled: boolean }>('/api/v1/relays/settings', {
      method: 'POST',
      token,
      body: { enabled },
    });
  },
  listRelays(token: string): Promise<{ relays: Relay[] }> {
    return request<{ relays: Relay[] }>('/api/v1/relays', { token });
  },
  relayEnrollmentCommand(token: string, name: string): Promise<RelayEnrollment> {
    return request<RelayEnrollment>('/api/v1/relays/enrollment-command', {
      method: 'POST',
      token,
      body: { name },
    });
  },
  killRelay(token: string, id: string): Promise<Relay> {
    return request<Relay>(`/api/v1/relays/${id}/kill`, { method: 'POST', token });
  },

  // --- Networking assistant (Phase 23) ---
  networkingStatus(token: string): Promise<NetworkStatus> {
    return request<NetworkStatus>('/api/v1/networking/status', { token });
  },
  validateNetworking(
    token: string,
    body: { mode: string; hostname: string; scheme: string; certificate_pem?: string },
  ): Promise<ValidateResult> {
    return request<ValidateResult>('/api/v1/networking/validate', { method: 'POST', token, body });
  },
  testBrowser(token: string): Promise<BrowserTest> {
    return request<BrowserTest>('/api/v1/networking/test-browser', { token });
  },

  // --- Everyday UX (Phase 22) ---
  dashboardSummary(token: string): Promise<DashboardSummary> {
    return request<DashboardSummary>('/api/v1/dashboard/summary', { token });
  },
  search(token: string, q: string): Promise<SearchResults> {
    return request<SearchResults>(`/api/v1/search?q=${encodeURIComponent(q)}`, { token });
  },
  listFindings(token: string, limit = 50): Promise<FindingPage<Finding>> {
    return request<FindingPage<Finding>>(`/api/v1/findings?limit=${limit}`, { token });
  },
  getFinding(token: string, id: string): Promise<Finding> {
    return request<Finding>(`/api/v1/findings/${encodeURIComponent(id)}`, { token });
  },
  updateFinding(token: string, id: string, patch: Record<string, unknown>): Promise<Finding> {
    return request<Finding>(`/api/v1/findings/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      token,
      body: patch,
    });
  },
  rescanFinding(token: string, id: string): Promise<unknown> {
    return request<unknown>(`/api/v1/findings/${encodeURIComponent(id)}/rescan`, {
      method: 'POST',
      token,
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
