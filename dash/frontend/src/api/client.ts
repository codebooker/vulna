import type {
  AccountStatus,
  CurrentUser,
  InvitationIssued,
  InviteUserPayload,
  InvitedUser,
  LifecycleEvent,
  LoginHistoryEvent,
  MfaPolicy,
  MfaStatus,
  MfaVerification,
  PasswordResetIssued,
  RecoveryCodes as MfaRecoveryCodes,
  Role,
  SiteAccessMode,
  SessionPolicy,
  TokenResponse,
  TotpSetup,
  UserSession,
  UserSummary,
  WebAuthnBegin,
  WebAuthnCredentialSummary,
} from '../types/auth';
import type { Experience, ExperienceChange, ExperiencePreview } from '../types/experience';
import type {
  Asset,
  AssetBulkPayload,
  AssetBulkResult,
  AssetContextPatch,
  AssetDetail,
  AssetFilters,
  AssetGroup,
  AssetTag,
  ChangeEvent,
  DepartmentOwner,
  GroupPreview,
  NetworkScope,
  NewScope,
  NewSite,
  OwnershipHistory,
  OwnershipResolution,
  Page,
  Site,
} from '../types/inventory';
import type { Network, NewNetwork } from '../types/network';
import type { PentestCandidate, PentestSession, RulesOfEngagement } from '../types/pentest';
import type { Job, JobDiagnostics, NewSchedule, ScanSchedule } from '../types/schedule';
import type { FeedHealth, SyncResult } from '../types/intelligence';
import type {
  ComponentHealth,
  CompleteStepPayload,
  DemoTarget,
  JobSummary,
  NetworkCandidates,
  OnboardingState,
  ProfilePlan,
  ProbeDetail,
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
import type { HealthResponse } from '../types/system';
import type { UpdateCenter } from '../types/update';
import type {
  GroupMapping,
  IdentityProvider,
  IdentityProviderCreate,
  PublicIdentityProvider,
  SsoPolicy,
  SsoPolicyMode,
  SsoStart,
} from '../types/sso';
import type {
  ScimGroupMapping,
  ScimLogPage,
  ScimMappingPayload,
  ScimMappingPreview,
  ScimToken,
  ScimTokenIssued,
} from '../types/scim';
import type {
  ApiTokenCreate,
  ApiTokenIssued,
  ApiTokenSummary,
  AuthorizationRole,
  GrantScopeType,
  PermissionDefinition,
  PrincipalType,
  ScopedGrant,
  ServiceAccount,
} from '../types/authorization';
import type { BackgroundTask, TaskHealth, TaskPage } from '../types/task';
import type { FindingDecision, FindingScore, RemediationUnit, RiskProfile } from '../types/risk';
import type {
  Credential,
  CredentialAssignment,
  CredentialAssignmentPage,
  CredentialCreate,
  CredentialPage,
  CredentialProtocol,
  CredentialResolution,
  CredentialTargetType,
  CredentialUsagePage,
  SoftwarePage,
} from '../types/credentials';
import type {
  SlaMetrics,
  SlaPolicy,
  TicketConnector,
  TicketConnectorTest,
  TicketConnectorType,
  TicketSync,
} from '../types/sla-ticketing';
import type {
  ConnectorRun,
  InventoryConnector,
  InventoryDashboard,
  PassiveConnectorType,
  ReconciliationCandidate,
  ReportTemplate,
  ReportTemplateRun,
  UnifiSite,
} from '../types/passive-inventory';

// In development, Vite proxies /api to the backend (see vite.config.ts).
// In production the frontend is served behind the same reverse proxy as the API.
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? '';

/** Error carrying the HTTP status so callers can react (e.g. 401 -> logout). */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string | null;
  readonly detail: unknown;

  constructor(status: number, message: string, code: string | null = null, detail?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.detail = detail;
  }
}

type StepUpHandler = () => Promise<void>;

let stepUpHandler: StepUpHandler | null = null;
let pendingStepUp: Promise<void> | null = null;

/** Register the interactive recent-authentication prompt owned by AuthProvider. */
export function setStepUpHandler(handler: StepUpHandler | null): void {
  stepUpHandler = handler;
}

function performStepUp(): Promise<void> {
  if (!stepUpHandler) return Promise.reject(new Error('Recent authentication is required.'));
  if (!pendingStepUp) {
    pendingStepUp = stepUpHandler().finally(() => {
      pendingStepUp = null;
    });
  }
  return pendingStepUp;
}

function errorMessage(detail: unknown, fallback: string): { message: string; code: string | null } {
  if (typeof detail === 'string') return { message: detail, code: null };
  if (detail && typeof detail === 'object' && !Array.isArray(detail)) {
    const value = detail as { message?: unknown; code?: unknown };
    return {
      message: typeof value.message === 'string' ? value.message : fallback,
      code: typeof value.code === 'string' ? value.code : null,
    };
  }
  if (Array.isArray(detail)) {
    const messages = detail
      .map((entry) =>
        entry && typeof entry === 'object' && typeof (entry as { msg?: unknown }).msg === 'string'
          ? (entry as { msg: string }).msg
          : null,
      )
      .filter((value): value is string => value !== null);
    if (messages.length > 0) return { message: messages.join('; '), code: null };
  }
  return { message: fallback, code: null };
}

interface RequestOptions {
  method?: string;
  token?: string | null;
  body?: unknown;
  rawBody?: BodyInit;
  contentType?: string;
  headers?: Record<string, string>;
}

async function request<T>(
  path: string,
  options: RequestOptions = {},
  retryAfterStepUp = true,
): Promise<T> {
  const { method = 'GET', token, body, rawBody, contentType, headers: extraHeaders } = options;
  if (body !== undefined && rawBody !== undefined) {
    throw new Error('API requests cannot include both JSON and raw bodies.');
  }
  const headers: Record<string, string> = { Accept: 'application/json', ...extraHeaders };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  } else if (rawBody !== undefined && contentType) {
    headers['Content-Type'] = contentType;
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: rawBody ?? (body !== undefined ? JSON.stringify(body) : undefined),
    credentials: 'include',
  });

  if (!response.ok) {
    let rawDetail: unknown = response.statusText;
    try {
      const data = (await response.json()) as { detail?: unknown };
      rawDetail = data.detail ?? response.statusText;
    } catch {
      // Non-JSON error body; fall back to the status text.
    }
    const parsed = errorMessage(rawDetail, response.statusText);
    if (response.status === 403 && parsed.code === 'step_up_required' && retryAfterStepUp) {
      await performStepUp();
      return request<T>(path, options, false);
    }
    throw new ApiError(response.status, parsed.message, parsed.code, rawDetail);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

async function collectPages<T>(loadPage: (offset: number) => Promise<Page<T>>): Promise<Page<T>> {
  const items: T[] = [];
  let total = 0;
  let offset = 0;
  do {
    const page = await loadPage(offset);
    total = page.total;
    items.push(...page.items);
    if (page.items.length === 0) break;
    offset += page.items.length;
  } while (offset < total);
  return { items, total, limit: items.length, offset: 0 };
}

export const api = {
  login(email: string, password: string, trustDevice = false): Promise<TokenResponse> {
    return request<TokenResponse>('/api/v1/auth/login', {
      method: 'POST',
      body: { email, password, trust_device: trustDevice },
    });
  },
  publicIdentityProviders(organization?: string): Promise<PublicIdentityProvider[]> {
    const query = organization ? `?organization=${encodeURIComponent(organization)}` : '';
    return request<PublicIdentityProvider[]>(`/api/v1/sso/providers${query}`);
  },
  startSso(providerId: string, returnPath = '/#overview'): Promise<SsoStart> {
    return request<SsoStart>(`/api/v1/sso/providers/${providerId}/start`, {
      method: 'POST',
      body: { return_path: returnPath },
    });
  },
  refreshAccess(): Promise<TokenResponse> {
    return request<TokenResponse>('/api/v1/auth/refresh', { method: 'POST' });
  },
  logout(token: string): Promise<void> {
    return request<void>('/api/v1/auth/logout', { method: 'POST', token });
  },
  logoutAll(token: string): Promise<void> {
    return request<void>('/api/v1/auth/logout-all', { method: 'POST', token });
  },
  listMySessions(token: string): Promise<UserSession[]> {
    return request<UserSession[]>('/api/v1/auth/sessions', { token });
  },
  revokeMySession(token: string, sessionId: string): Promise<void> {
    return request<void>(`/api/v1/auth/sessions/${sessionId}`, { method: 'DELETE', token });
  },
  reauthenticate(
    token: string,
    password: string,
  ): Promise<{ authenticated_at: string; privileged_until: string }> {
    return request('/api/v1/auth/reauthenticate', {
      method: 'POST',
      token,
      body: { password },
    });
  },
  sessionPolicy(token: string): Promise<SessionPolicy> {
    return request<SessionPolicy>('/api/v1/organizations/current/session-policy', { token });
  },
  updateSessionPolicy(token: string, payload: Partial<SessionPolicy>): Promise<SessionPolicy> {
    return request<SessionPolicy>('/api/v1/organizations/current/session-policy', {
      method: 'PATCH',
      token,
      body: payload,
    });
  },

  // --- Identity federation (Phase 37) ---
  listIdentityProviders(token: string): Promise<IdentityProvider[]> {
    return request<IdentityProvider[]>('/api/v1/identity/providers', { token });
  },
  createIdentityProvider(
    token: string,
    payload: IdentityProviderCreate,
  ): Promise<IdentityProvider> {
    return request<IdentityProvider>('/api/v1/identity/providers', {
      method: 'POST',
      token,
      body: payload,
    });
  },
  updateIdentityProvider(
    token: string,
    providerId: string,
    payload: Record<string, unknown>,
  ): Promise<IdentityProvider> {
    return request<IdentityProvider>(`/api/v1/identity/providers/${providerId}`, {
      method: 'PATCH',
      token,
      body: payload,
    });
  },
  deleteIdentityProvider(token: string, providerId: string): Promise<void> {
    return request<void>(`/api/v1/identity/providers/${providerId}`, {
      method: 'DELETE',
      token,
    });
  },
  validateIdentityProvider(token: string, providerId: string): Promise<IdentityProvider> {
    return request<IdentityProvider>(`/api/v1/identity/providers/${providerId}/validate`, {
      method: 'POST',
      token,
    });
  },
  importSamlMetadata(
    token: string,
    providerId: string,
    metadataXml: string,
  ): Promise<IdentityProvider> {
    return request<IdentityProvider>(`/api/v1/identity/providers/${providerId}/saml-metadata`, {
      method: 'POST',
      token,
      body: { metadata_xml: metadataXml },
    });
  },
  testIdentityProvider(
    token: string,
    providerId: string,
    returnPath = '/#identity',
  ): Promise<SsoStart> {
    return request<SsoStart>(`/api/v1/identity/providers/${providerId}/test`, {
      method: 'POST',
      token,
      body: { return_path: returnPath },
    });
  },
  enableIdentityProvider(
    token: string,
    providerId: string,
    enabled: boolean,
  ): Promise<IdentityProvider> {
    return request<IdentityProvider>(`/api/v1/identity/providers/${providerId}/enabled`, {
      method: 'PUT',
      token,
      body: { enabled },
    });
  },
  identityGroupMappings(token: string, providerId: string): Promise<GroupMapping[]> {
    return request<GroupMapping[]>(`/api/v1/identity/providers/${providerId}/group-mappings`, {
      token,
    });
  },
  replaceIdentityGroupMappings(
    token: string,
    providerId: string,
    mappings: Array<Omit<GroupMapping, 'id'>>,
  ): Promise<GroupMapping[]> {
    return request<GroupMapping[]>(`/api/v1/identity/providers/${providerId}/group-mappings`, {
      method: 'PUT',
      token,
      body: mappings,
    });
  },
  ssoPolicy(token: string): Promise<SsoPolicy> {
    return request<SsoPolicy>('/api/v1/identity/policy', { token });
  },
  updateSsoPolicy(
    token: string,
    mode: SsoPolicyMode,
    providerId: string | null,
  ): Promise<SsoPolicy> {
    return request<SsoPolicy>('/api/v1/identity/policy', {
      method: 'PUT',
      token,
      body: { mode, identity_provider_id: providerId },
    });
  },
  setBreakGlass(token: string, userId: string, enabled: boolean): Promise<SsoPolicy> {
    return request<SsoPolicy>(`/api/v1/identity/break-glass/${userId}`, {
      method: 'PUT',
      token,
      body: { enabled },
    });
  },

  // --- SCIM provisioning (Phase 38) ---
  listScimTokens(token: string): Promise<ScimToken[]> {
    return request<ScimToken[]>('/api/v1/scim/tokens', { token });
  },
  createScimToken(token: string, name: string): Promise<ScimTokenIssued> {
    return request<ScimTokenIssued>('/api/v1/scim/tokens', {
      method: 'POST',
      token,
      body: { name },
    });
  },
  rotateScimToken(token: string, tokenId: string): Promise<ScimTokenIssued> {
    return request<ScimTokenIssued>(`/api/v1/scim/tokens/${tokenId}/rotate`, {
      method: 'POST',
      token,
    });
  },
  revokeScimToken(token: string, tokenId: string): Promise<void> {
    return request<void>(`/api/v1/scim/tokens/${tokenId}`, { method: 'DELETE', token });
  },
  listScimGroups(token: string): Promise<ScimGroupMapping[]> {
    return request<ScimGroupMapping[]>('/api/v1/scim/groups', { token });
  },
  previewScimGroupMapping(
    token: string,
    groupId: string,
    payload: ScimMappingPayload,
  ): Promise<ScimMappingPreview> {
    return request<ScimMappingPreview>(`/api/v1/scim/groups/${groupId}/mapping/preview`, {
      method: 'POST',
      token,
      body: payload,
    });
  },
  updateScimGroupMapping(
    token: string,
    groupId: string,
    payload: ScimMappingPayload,
  ): Promise<ScimGroupMapping> {
    return request<ScimGroupMapping>(`/api/v1/scim/groups/${groupId}/mapping`, {
      method: 'PUT',
      token,
      body: payload,
    });
  },
  scimProvisioningLogs(token: string): Promise<ScimLogPage> {
    return request<ScimLogPage>('/api/v1/scim/logs?limit=50', { token });
  },
  me(token: string): Promise<CurrentUser> {
    return request<CurrentUser>('/api/v1/auth/me', { token });
  },
  permissionCatalogue(token: string): Promise<PermissionDefinition[]> {
    return request<PermissionDefinition[]>('/api/v1/permissions', { token });
  },
  listAuthorizationRoles(token: string): Promise<AuthorizationRole[]> {
    return request<AuthorizationRole[]>('/api/v1/roles', { token });
  },
  createAuthorizationRole(
    token: string,
    payload: { key: string; name: string; description?: string; permission_keys: string[] },
  ): Promise<AuthorizationRole> {
    return request<AuthorizationRole>('/api/v1/roles', { method: 'POST', token, body: payload });
  },
  listScopedGrants(token: string): Promise<ScopedGrant[]> {
    return request<ScopedGrant[]>('/api/v1/grants', { token });
  },
  createScopedGrant(
    token: string,
    payload: {
      principal_type: PrincipalType;
      principal_id: string;
      role_id: string;
      scope_type: GrantScopeType;
      scope_id: string;
    },
  ): Promise<ScopedGrant> {
    return request<ScopedGrant>('/api/v1/grants', { method: 'POST', token, body: payload });
  },
  deleteScopedGrant(token: string, grantId: string): Promise<void> {
    return request<void>(`/api/v1/grants/${grantId}`, { method: 'DELETE', token });
  },
  listServiceAccounts(token: string): Promise<ServiceAccount[]> {
    return request<ServiceAccount[]>('/api/v1/service-accounts', { token });
  },
  createServiceAccount(
    token: string,
    payload: { name: string; description?: string },
  ): Promise<ServiceAccount> {
    return request<ServiceAccount>('/api/v1/service-accounts', {
      method: 'POST',
      token,
      body: payload,
    });
  },
  suspendServiceAccount(token: string, accountId: string): Promise<void> {
    return request<void>(`/api/v1/service-accounts/${accountId}`, {
      method: 'DELETE',
      token,
    });
  },
  listPersonalApiTokens(token: string): Promise<ApiTokenSummary[]> {
    return request<ApiTokenSummary[]>('/api/v1/tokens', { token });
  },
  createPersonalApiToken(token: string, payload: ApiTokenCreate): Promise<ApiTokenIssued> {
    return request<ApiTokenIssued>('/api/v1/tokens', { method: 'POST', token, body: payload });
  },
  revokePersonalApiToken(token: string, tokenId: string): Promise<void> {
    return request<void>(`/api/v1/tokens/${tokenId}`, { method: 'DELETE', token });
  },
  listServiceApiTokens(token: string, accountId: string): Promise<ApiTokenSummary[]> {
    return request<ApiTokenSummary[]>(`/api/v1/service-accounts/${accountId}/tokens`, { token });
  },
  createServiceApiToken(
    token: string,
    accountId: string,
    payload: ApiTokenCreate,
  ): Promise<ApiTokenIssued> {
    return request<ApiTokenIssued>(`/api/v1/service-accounts/${accountId}/tokens`, {
      method: 'POST',
      token,
      body: payload,
    });
  },
  revokeServiceApiToken(token: string, accountId: string, tokenId: string): Promise<void> {
    return request<void>(`/api/v1/service-accounts/${accountId}/tokens/${tokenId}`, {
      method: 'DELETE',
      token,
    });
  },
  mfaStatus(token: string): Promise<MfaStatus> {
    return request<MfaStatus>('/api/v1/mfa/status', { token });
  },
  beginTotp(token: string): Promise<TotpSetup> {
    return request<TotpSetup>('/api/v1/mfa/totp/setup', { method: 'POST', token });
  },
  confirmTotp(
    token: string,
    factorId: string,
    code: string,
  ): Promise<{ verification: MfaVerification; recovery_codes: MfaRecoveryCodes }> {
    return request('/api/v1/mfa/totp/confirm', {
      method: 'POST',
      token,
      body: { factor_id: factorId, code },
    });
  },
  verifyTotp(token: string, code: string): Promise<MfaVerification> {
    return request<MfaVerification>('/api/v1/mfa/totp/verify', {
      method: 'POST',
      token,
      body: { code },
    });
  },
  verifyRecoveryCode(token: string, code: string): Promise<MfaVerification> {
    return request<MfaVerification>('/api/v1/mfa/recovery/verify', {
      method: 'POST',
      token,
      body: { code },
    });
  },
  regenerateRecoveryCodes(token: string): Promise<MfaRecoveryCodes> {
    return request<MfaRecoveryCodes>('/api/v1/mfa/recovery/regenerate', {
      method: 'POST',
      token,
    });
  },
  disableTotp(token: string): Promise<void> {
    return request<void>('/api/v1/mfa/totp', { method: 'DELETE', token });
  },
  listWebAuthnCredentials(token: string): Promise<WebAuthnCredentialSummary[]> {
    return request<WebAuthnCredentialSummary[]>('/api/v1/mfa/webauthn/credentials', { token });
  },
  beginWebAuthnRegistration(token: string): Promise<WebAuthnBegin> {
    return request<WebAuthnBegin>('/api/v1/mfa/webauthn/register/options', {
      method: 'POST',
      token,
    });
  },
  finishWebAuthnRegistration(
    token: string,
    challengeId: string,
    credential: Record<string, unknown>,
    label: string,
  ): Promise<{
    credential: WebAuthnCredentialSummary;
    verification: MfaVerification;
    recovery_codes: MfaRecoveryCodes | null;
  }> {
    return request('/api/v1/mfa/webauthn/register/verify', {
      method: 'POST',
      token,
      body: { challenge_id: challengeId, credential, label },
    });
  },
  beginWebAuthnAuthentication(token: string): Promise<WebAuthnBegin> {
    return request<WebAuthnBegin>('/api/v1/mfa/webauthn/authenticate/options', {
      method: 'POST',
      token,
    });
  },
  finishWebAuthnAuthentication(
    token: string,
    challengeId: string,
    credential: Record<string, unknown>,
  ): Promise<MfaVerification> {
    return request<MfaVerification>('/api/v1/mfa/webauthn/authenticate/verify', {
      method: 'POST',
      token,
      body: { challenge_id: challengeId, credential },
    });
  },
  disableWebAuthnCredential(token: string, credentialId: string): Promise<void> {
    return request<void>(`/api/v1/mfa/webauthn/credentials/${credentialId}`, {
      method: 'DELETE',
      token,
    });
  },
  mfaPolicy(token: string): Promise<MfaPolicy> {
    return request<MfaPolicy>('/api/v1/mfa/policy', { token });
  },
  updateMfaPolicy(token: string, payload: Partial<MfaPolicy>): Promise<MfaPolicy> {
    return request<MfaPolicy>('/api/v1/mfa/policy', { method: 'PATCH', token, body: payload });
  },
  experience(token: string): Promise<Experience> {
    return request<Experience>('/api/v1/organizations/current/experience', { token });
  },
  previewExperience(token: string, payload: ExperienceChange): Promise<ExperiencePreview> {
    return request<ExperiencePreview>('/api/v1/organizations/current/experience/preview', {
      method: 'POST',
      token,
      body: payload,
    });
  },
  updateExperience(token: string, payload: ExperienceChange): Promise<Experience> {
    return request<Experience>('/api/v1/organizations/current/experience', {
      method: 'PATCH',
      token,
      body: payload,
    });
  },
  listUsers(token: string): Promise<Page<UserSummary>> {
    return request<Page<UserSummary>>('/api/v1/users', { token });
  },
  inviteUser(token: string, payload: InviteUserPayload): Promise<InvitedUser> {
    return request<InvitedUser>('/api/v1/users', { method: 'POST', token, body: payload });
  },
  updateUser(
    token: string,
    userId: string,
    payload: { full_name?: string | null; role?: Role },
  ): Promise<UserSummary> {
    return request<UserSummary>(`/api/v1/users/${userId}`, {
      method: 'PATCH',
      token,
      body: payload,
    });
  },
  updateUserStatus(
    token: string,
    userId: string,
    status: AccountStatus,
    reason: string,
  ): Promise<UserSummary> {
    return request<UserSummary>(`/api/v1/users/${userId}/status`, {
      method: 'PUT',
      token,
      body: { status, reason },
    });
  },
  updateUserSiteAccess(
    token: string,
    userId: string,
    mode: SiteAccessMode,
    siteIds: string[],
    reason?: string,
  ): Promise<UserSummary> {
    return request<UserSummary>(`/api/v1/users/${userId}/site-access`, {
      method: 'PUT',
      token,
      body: { mode, site_ids: siteIds, reason },
    });
  },
  issueInvitation(token: string, userId: string): Promise<InvitationIssued> {
    return request<InvitationIssued>(`/api/v1/users/${userId}/invitation`, {
      method: 'POST',
      token,
    });
  },
  issuePasswordReset(token: string, userId: string): Promise<PasswordResetIssued> {
    return request<PasswordResetIssued>(`/api/v1/users/${userId}/password-reset`, {
      method: 'POST',
      token,
    });
  },
  userLifecycle(token: string, userId: string): Promise<Page<LifecycleEvent>> {
    return request<Page<LifecycleEvent>>(`/api/v1/users/${userId}/lifecycle`, { token });
  },
  userLoginHistory(token: string, userId: string): Promise<Page<LoginHistoryEvent>> {
    return request<Page<LoginHistoryEvent>>(`/api/v1/users/${userId}/login-history`, { token });
  },
  userSessions(token: string, userId: string): Promise<UserSession[]> {
    return request<UserSession[]>(`/api/v1/users/${userId}/sessions`, { token });
  },
  revokeUserSession(token: string, userId: string, sessionId: string): Promise<void> {
    return request<void>(
      `/api/v1/users/${userId}/sessions/${sessionId}?reason=${encodeURIComponent('administrator revoked session')}`,
      { method: 'DELETE', token },
    );
  },
  acceptInvitation(
    secret: string,
    password: string,
    fullName?: string,
  ): Promise<{ status: string }> {
    return request<{ status: string }>('/api/v1/auth/invitations/accept', {
      method: 'POST',
      body: { token: secret, password, full_name: fullName || null },
    });
  },
  completePasswordReset(secret: string, password: string): Promise<{ status: string }> {
    return request<{ status: string }>('/api/v1/auth/password-resets/complete', {
      method: 'POST',
      body: { token: secret, password },
    });
  },
  listSites(token: string, limit?: number, offset = 0): Promise<Page<Site>> {
    const query = limit === undefined ? '' : `?limit=${limit}&offset=${offset}`;
    return request<Page<Site>>(`/api/v1/sites${query}`, { token });
  },
  async listAllSites(token: string): Promise<Page<Site>> {
    const first = await api.listSites(token);
    if (first.items.length >= first.total) return first;
    const rest = await collectPages((relativeOffset) =>
      api.listSites(token, 200, first.items.length + relativeOffset),
    );
    return {
      items: [...first.items, ...rest.items],
      total: first.total,
      limit: first.total,
      offset: 0,
    };
  },
  createSite(token: string, payload: NewSite): Promise<Site> {
    return request<Site>('/api/v1/sites', { method: 'POST', token, body: payload });
  },
  updateSite(
    token: string,
    siteId: string,
    patch: {
      name?: string;
      code?: string;
      description?: string | null;
      address?: string | null;
      owner_user_id?: string | null;
    },
  ): Promise<Site> {
    return request<Site>(`/api/v1/sites/${siteId}`, { method: 'PATCH', token, body: patch });
  },
  deleteSite(token: string, siteId: string): Promise<void> {
    return request<void>(`/api/v1/sites/${siteId}`, { method: 'DELETE', token });
  },
  listAssets(
    token: string,
    limit = 200,
    siteId?: string,
    filters: AssetFilters = {},
    offset = 0,
  ): Promise<Page<Asset>> {
    const params = new URLSearchParams({
      limit: String(Math.min(limit, 200)),
      offset: String(offset),
    });
    if (siteId) params.set('site_id', siteId);
    for (const [key, value] of Object.entries(filters)) {
      if (value !== undefined && value !== '') params.set(key, String(value));
    }
    return request<Page<Asset>>(`/api/v1/assets?${params.toString()}`, { token });
  },
  listAllAssets(token: string, siteId?: string, filters: AssetFilters = {}): Promise<Page<Asset>> {
    return collectPages((offset) => api.listAssets(token, 200, siteId, filters, offset));
  },
  getAsset(token: string, assetId: string): Promise<AssetDetail> {
    return request<AssetDetail>(`/api/v1/assets/${encodeURIComponent(assetId)}`, { token });
  },
  updateAssetContext(
    token: string,
    assetId: string,
    patch: AssetContextPatch,
  ): Promise<Record<string, unknown>> {
    return request(`/api/v1/assets/${assetId}/context`, {
      method: 'PATCH',
      token,
      body: patch,
    });
  },
  bulkUpdateAssets(token: string, payload: AssetBulkPayload): Promise<AssetBulkResult> {
    return request<AssetBulkResult>('/api/v1/assets/bulk', {
      method: 'POST',
      token,
      body: payload,
    });
  },
  assetOwnership(token: string, assetId: string): Promise<OwnershipResolution> {
    return request<OwnershipResolution>(`/api/v1/assets/${assetId}/ownership`, { token });
  },
  assetOwnershipHistory(token: string, assetId: string): Promise<Page<OwnershipHistory>> {
    return request<Page<OwnershipHistory>>(`/api/v1/assets/${assetId}/ownership-history?limit=20`, {
      token,
    });
  },
  listDepartmentOwners(token: string): Promise<DepartmentOwner[]> {
    return request<DepartmentOwner[]>('/api/v1/department-owners', { token });
  },
  upsertDepartmentOwner(
    token: string,
    payload: { department: string; owner_user_id: string },
  ): Promise<DepartmentOwner> {
    return request<DepartmentOwner>('/api/v1/department-owners', {
      method: 'PUT',
      token,
      body: payload,
    });
  },
  deleteDepartmentOwner(token: string, departmentOwnerId: string): Promise<void> {
    return request<void>(`/api/v1/department-owners/${departmentOwnerId}`, {
      method: 'DELETE',
      token,
    });
  },
  listAssetTags(token: string): Promise<Page<AssetTag>> {
    return request<Page<AssetTag>>('/api/v1/asset-tags?limit=500', { token });
  },
  createAssetTag(
    token: string,
    payload: { name: string; description?: string | null; color?: string | null },
  ): Promise<AssetTag> {
    return request<AssetTag>('/api/v1/asset-tags', {
      method: 'POST',
      token,
      body: payload,
    });
  },
  addAssetTag(token: string, assetId: string, tagId: string): Promise<unknown> {
    return request(`/api/v1/assets/${assetId}/tags/${tagId}`, { method: 'PUT', token });
  },
  removeAssetTag(token: string, assetId: string, tagId: string): Promise<void> {
    return request<void>(`/api/v1/assets/${assetId}/tags/${tagId}`, {
      method: 'DELETE',
      token,
    });
  },
  listAssetGroups(token: string): Promise<Page<AssetGroup>> {
    return request<Page<AssetGroup>>('/api/v1/asset-groups?limit=500', { token });
  },
  createAssetGroup(
    token: string,
    payload: {
      name: string;
      description?: string | null;
      group_type: 'static' | 'dynamic';
      site_id?: string | null;
      rule_json?: Record<string, unknown> | null;
      priority?: number;
      owner_user_id?: string | null;
    },
  ): Promise<AssetGroup> {
    return request<AssetGroup>('/api/v1/asset-groups', {
      method: 'POST',
      token,
      body: payload,
    });
  },
  previewAssetGroup(
    token: string,
    ruleJson: Record<string, unknown>,
    siteId?: string | null,
  ): Promise<GroupPreview> {
    return request<GroupPreview>('/api/v1/asset-groups/preview', {
      method: 'POST',
      token,
      body: { rule_json: ruleJson, site_id: siteId ?? null },
    });
  },
  addAssetGroupMembers(token: string, groupId: string, assetIds: string[]): Promise<AssetGroup> {
    return request<AssetGroup>(`/api/v1/asset-groups/${groupId}/members`, {
      method: 'PUT',
      token,
      body: { asset_ids: assetIds },
    });
  },
  listScopes(token: string, siteId?: string): Promise<Page<NetworkScope>> {
    const query = siteId ? `?site_id=${encodeURIComponent(siteId)}` : '';
    return request<Page<NetworkScope>>(`/api/v1/scopes${query}`, { token });
  },
  listAllScopes(token: string, siteId?: string): Promise<Page<NetworkScope>> {
    return collectPages((offset) => {
      const params = new URLSearchParams({ limit: '200', offset: String(offset) });
      if (siteId) params.set('site_id', siteId);
      return request<Page<NetworkScope>>(`/api/v1/scopes?${params.toString()}`, { token });
    });
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
  addNetworkRange(
    token: string,
    networkId: string,
    cidr: string,
    allowPublic = false,
  ): Promise<Network> {
    return request<Network>(`/api/v1/networks/${networkId}/ranges`, {
      method: 'POST',
      token,
      body: { cidr, allow_public_addresses: allowPublic },
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
  updateNetwork(
    token: string,
    networkId: string,
    patch: { name?: string; description?: string | null; enabled?: boolean },
  ): Promise<Network> {
    return request<Network>(`/api/v1/networks/${networkId}`, {
      method: 'PATCH',
      token,
      body: patch,
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
  listReports(token: string, limit = 50, offset = 0): Promise<Page<Report>> {
    return request<Page<Report>>(`/api/v1/reports?limit=${limit}&offset=${offset}`, { token });
  },
  listAllReports(token: string): Promise<Page<Report>> {
    return collectPages((offset) => api.listReports(token, 200, offset));
  },
  createReports(
    token: string,
    scanJobId: string,
    reportTypes?: string[],
    filters: { assetTagIds?: string[]; assetGroupIds?: string[] } = {},
  ): Promise<Report[]> {
    return request<Report[]>('/api/v1/reports', {
      method: 'POST',
      token,
      body: {
        scan_job_id: scanJobId,
        ...(reportTypes ? { report_types: reportTypes } : {}),
        asset_tag_ids: filters.assetTagIds ?? [],
        asset_group_ids: filters.assetGroupIds ?? [],
      },
    });
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
  profilePlan(token: string): Promise<ProfilePlan> {
    return request<ProfilePlan>('/api/v1/onboarding/profile-plan', { token });
  },
  updateProfilePlan(token: string, answers: Record<string, unknown>): Promise<ProfilePlan> {
    return request<ProfilePlan>('/api/v1/onboarding/profile-plan', {
      method: 'PUT',
      token,
      body: { answers },
    });
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
  getProbe(token: string, probeId: string): Promise<ProbeDetail> {
    return request<ProbeDetail>(`/api/v1/probes/${probeId}`, { token });
  },
  updateProbe(
    token: string,
    probeId: string,
    patch: { name?: string; description?: string },
  ): Promise<ProbeDetail> {
    return request<ProbeDetail>(`/api/v1/probes/${probeId}`, {
      method: 'PATCH',
      token,
      body: patch,
    });
  },
  probeLifecycle(
    token: string,
    probeId: string,
    action: 'approve' | 'disable' | 'revoke',
  ): Promise<ProbeDetail> {
    return request<ProbeDetail>(`/api/v1/probes/${probeId}/${action}`, { method: 'POST', token });
  },
  setProbePentest(token: string, probeId: string, enabled: boolean): Promise<ProbeSummary> {
    return request<ProbeSummary>(`/api/v1/probes/${probeId}/pentest`, {
      method: 'POST',
      token,
      body: { enabled },
    });
  },
  setProbeCredentialedScanning(
    token: string,
    probeId: string,
    enabled: boolean,
  ): Promise<ProbeSummary> {
    return request<ProbeSummary>(`/api/v1/probes/${probeId}/credentialed-scans`, {
      method: 'POST',
      token,
      body: { enabled },
    });
  },
  // --- Authenticated inventory (Phase 42) ---
  listCredentials(token: string): Promise<CredentialPage> {
    return request<CredentialPage>('/api/v1/credentials?limit=200', { token });
  },
  createCredential(token: string, payload: CredentialCreate): Promise<Credential> {
    return request<Credential>('/api/v1/credentials', { method: 'POST', token, body: payload });
  },
  updateCredential(
    token: string,
    credentialId: string,
    payload: Partial<Pick<Credential, 'name' | 'description' | 'username' | 'is_active'>>,
  ): Promise<Credential> {
    return request<Credential>(`/api/v1/credentials/${credentialId}`, {
      method: 'PATCH',
      token,
      body: payload,
    });
  },
  rotateCredential(token: string, credentialId: string, secret: string): Promise<Credential> {
    return request<Credential>(`/api/v1/credentials/${credentialId}/rotate`, {
      method: 'POST',
      token,
      body: { secret },
    });
  },
  listCredentialAssignments(token: string): Promise<CredentialAssignmentPage> {
    return request<CredentialAssignmentPage>('/api/v1/credentials/assignments?limit=500', {
      token,
    });
  },
  createCredentialAssignment(
    token: string,
    credentialId: string,
    targetType: CredentialTargetType,
    targetId: string,
  ): Promise<CredentialAssignment> {
    return request<CredentialAssignment>(`/api/v1/credentials/${credentialId}/assignments`, {
      method: 'POST',
      token,
      body: { target_type: targetType, target_id: targetId },
    });
  },
  deleteCredentialAssignment(token: string, assignmentId: string): Promise<void> {
    return request<void>(`/api/v1/credentials/assignments/${assignmentId}`, {
      method: 'DELETE',
      token,
    });
  },
  resolveCredentials(
    token: string,
    assetId: string,
    protocols: CredentialProtocol[],
  ): Promise<CredentialResolution[]> {
    return request<CredentialResolution[]>('/api/v1/credentials/resolve-preview', {
      method: 'POST',
      token,
      body: { asset_id: assetId, protocols },
    });
  },
  credentialUsage(token: string): Promise<CredentialUsagePage> {
    return request<CredentialUsagePage>('/api/v1/credentials/usage?limit=100', { token });
  },
  listSoftware(token: string, assetId?: string): Promise<SoftwarePage> {
    const query = assetId ? `&asset_id=${encodeURIComponent(assetId)}` : '';
    return request<SoftwarePage>(`/api/v1/software?limit=500${query}`, { token });
  },
  createEolOverride(
    token: string,
    softwareId: string,
    payload: {
      status: string;
      reason: string;
      eol_date?: string | null;
      expires_at?: string | null;
    },
  ): Promise<unknown> {
    return request(`/api/v1/software/${softwareId}/eol-overrides`, {
      method: 'POST',
      token,
      body: payload,
    });
  },
  createAuthenticatedJob(
    token: string,
    payload: {
      probe_id: string;
      asset_id: string;
      network_id?: string;
      targets: string[];
      authenticated_protocols: CredentialProtocol[];
    },
  ): Promise<JobSummary> {
    return request<JobSummary>('/api/v1/jobs/authenticated', {
      method: 'POST',
      token,
      body: { ...payload, mode: 'vulnerability_assessment' },
    });
  },
  listSlaPolicies(token: string): Promise<SlaPolicy[]> {
    return request<SlaPolicy[]>('/api/v1/sla/policies', { token });
  },
  slaMetrics(token: string): Promise<SlaMetrics> {
    return request<SlaMetrics>('/api/v1/sla/metrics', { token });
  },
  createSlaPolicy(
    token: string,
    payload: {
      name: string;
      priority: number;
      match: Record<string, unknown>;
      due_days: Record<string, number>;
      pause_on_risk_acceptance: boolean;
    },
  ): Promise<SlaPolicy> {
    return request<SlaPolicy>('/api/v1/sla/policies', { method: 'POST', token, body: payload });
  },
  listTicketConnectors(token: string): Promise<TicketConnector[]> {
    return request<TicketConnector[]>('/api/v1/ticketing/connectors', { token });
  },
  createTicketConnector(
    token: string,
    payload: {
      name: string;
      connector_type: TicketConnectorType;
      base_url: string;
      project_key: string;
      secret: string;
      config: Record<string, unknown>;
    },
  ): Promise<TicketConnector> {
    return request<TicketConnector>('/api/v1/ticketing/connectors', {
      method: 'POST',
      token,
      body: payload,
    });
  },
  updateTicketConnector(
    token: string,
    connectorId: string,
    payload: Partial<Pick<TicketConnector, 'enabled' | 'close_after_verification'>>,
  ): Promise<TicketConnector> {
    return request<TicketConnector>(`/api/v1/ticketing/connectors/${connectorId}`, {
      method: 'PATCH',
      token,
      body: payload,
    });
  },
  testTicketConnector(token: string, connectorId: string): Promise<TicketConnectorTest> {
    return request<TicketConnectorTest>(`/api/v1/ticketing/connectors/${connectorId}/test`, {
      method: 'POST',
      token,
    });
  },
  listTicketSyncs(token: string): Promise<TicketSync[]> {
    return request<TicketSync[]>('/api/v1/ticketing/syncs', { token });
  },
  queueTicketSync(
    token: string,
    findingId: string,
    connectorId: string,
    action: 'upsert' | 'close',
    explicitCloseReason?: string,
  ): Promise<BackgroundTask> {
    return request<BackgroundTask>(`/api/v1/ticketing/findings/${findingId}/sync`, {
      method: 'POST',
      token,
      body: {
        connector_id: connectorId,
        action,
        explicit_close_reason: explicitCloseReason || undefined,
      },
    });
  },
  // --- Controlled pentest ---
  listRoE(token: string): Promise<RulesOfEngagement[]> {
    return request<RulesOfEngagement[]>('/api/v1/pentest/rules-of-engagement', { token });
  },
  createRoE(
    token: string,
    payload: {
      name: string;
      authorization_owner: string;
      authorization_source: string;
      authorization_reference: string;
      authorization_document_sha256: string;
      effective_from: string;
      effective_until: string;
      authorized_cidrs: string[];
      authorized_asset_ids: string[];
      authorized_modules: string[];
      allowed_actions: string[];
      cleanup_required: boolean;
    },
  ): Promise<RulesOfEngagement> {
    return request<RulesOfEngagement>('/api/v1/pentest/rules-of-engagement', {
      method: 'POST',
      token,
      body: payload,
    });
  },
  pentestModules(token: string): Promise<{ modules: string[] }> {
    return request<{ modules: string[] }>('/api/v1/pentest/allowlisted-modules', { token });
  },
  pentestCandidates(token: string): Promise<PentestCandidate[]> {
    return request<PentestCandidate[]>('/api/v1/pentest/candidates', { token });
  },
  createPentestSession(
    token: string,
    payload: { finding_id: string; module: string; rules_of_engagement_id: string },
  ): Promise<PentestSession> {
    return request<PentestSession>('/api/v1/pentest/sessions', {
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
  createJob(
    token: string,
    probeId: string,
    targets: string[],
    networkId?: string,
    presetKey?: string,
  ): Promise<JobSummary> {
    return request<JobSummary>('/api/v1/jobs', {
      method: 'POST',
      token,
      body: {
        ...(networkId ? { network_id: networkId } : {}),
        ...(presetKey ? { preset_key: presetKey } : {}),
        probe_id: probeId,
        targets,
        mode: 'vulnerability_assessment',
      },
    });
  },
  listJobs(token: string, status?: string, limit = 100, offset = 0): Promise<Page<Job>> {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    if (status) params.set('status', status);
    return request<Page<Job>>(`/api/v1/jobs?${params.toString()}`, { token });
  },
  listAllJobs(token: string, status?: string): Promise<Page<Job>> {
    return collectPages((offset) => api.listJobs(token, status, 200, offset));
  },
  cancelJob(token: string, id: string): Promise<Job> {
    return request<Job>(`/api/v1/jobs/${id}/cancel`, { method: 'POST', token });
  },
  jobDiagnostics(token: string, id: string): Promise<JobDiagnostics> {
    return request<JobDiagnostics>(`/api/v1/jobs/${id}/diagnostics`, { token });
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
  updateChannel(
    token: string,
    id: string,
    body: {
      events?: string[];
      policy?: string;
      enabled?: boolean;
      quiet_start_hour?: number | null;
      quiet_end_hour?: number | null;
    },
  ): Promise<NotificationChannel> {
    return request<NotificationChannel>(`/api/v1/notifications/channels/${id}`, {
      method: 'PATCH',
      token,
      body,
    });
  },
  rotateChannelSecret(token: string, id: string, secret: string): Promise<{ rotated: boolean }> {
    return request<{ rotated: boolean }>(`/api/v1/notifications/channels/${id}/rotate-secret`, {
      method: 'POST',
      token,
      body: { secret },
    });
  },
  deleteChannel(token: string, id: string): Promise<{ deleted: boolean }> {
    return request<{ deleted: boolean }>(`/api/v1/notifications/channels/${id}`, {
      method: 'DELETE',
      token,
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

  // --- Durable task operations (post-Phase-39 gate) ---
  listTasks(token: string): Promise<TaskPage> {
    return request<TaskPage>('/api/v1/tasks?limit=100', { token });
  },
  taskHealth(token: string): Promise<TaskHealth> {
    return request<TaskHealth>('/api/v1/tasks/health', { token });
  },
  cancelTask(token: string, id: string): Promise<BackgroundTask> {
    return request<BackgroundTask>(`/api/v1/tasks/${id}/cancel`, { method: 'POST', token });
  },
  retryTask(token: string, id: string): Promise<BackgroundTask> {
    return request<BackgroundTask>(`/api/v1/tasks/${id}/retry`, { method: 'POST', token });
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

  // --- Passive inventory, reconciliation, analytics, and report builder (Phase 44) ---
  inventoryDashboard(token: string): Promise<InventoryDashboard> {
    return request<InventoryDashboard>('/api/v1/analytics/dashboard', {
      token,
      headers: { 'Cache-Control': 'no-cache' },
    });
  },
  listInventoryConnectors(token: string): Promise<InventoryConnector[]> {
    return request<InventoryConnector[]>('/api/v1/inventory/connectors', { token });
  },
  createInventoryConnector(
    token: string,
    body: {
      site_id: string;
      name: string;
      connector_type: PassiveConnectorType;
      base_url?: string;
      secret?: string;
      interval_minutes?: number;
      config?: Record<string, unknown>;
    },
  ): Promise<InventoryConnector> {
    return request<InventoryConnector>('/api/v1/inventory/connectors', {
      method: 'POST',
      token,
      body,
    });
  },
  discoverUnifiSites(token: string, apiKey: string): Promise<UnifiSite[]> {
    return request<UnifiSite[]>('/api/v1/inventory/unifi/sites', {
      method: 'POST',
      token,
      body: { api_key: apiKey },
    });
  },
  uploadInventoryCsv(token: string, connectorId: string, file: File): Promise<InventoryConnector> {
    return request<InventoryConnector>(
      `/api/v1/inventory/connectors/${encodeURIComponent(connectorId)}/csv`,
      {
        method: 'PUT',
        token,
        rawBody: file,
        contentType: 'text/csv',
        headers: { 'X-File-Name': file.name },
      },
    );
  },
  clearInventoryCsv(token: string, connectorId: string): Promise<InventoryConnector> {
    return request<InventoryConnector>(
      `/api/v1/inventory/connectors/${encodeURIComponent(connectorId)}/csv`,
      { method: 'DELETE', token },
    );
  },
  testInventoryConnector(
    token: string,
    connectorId: string,
  ): Promise<{ succeeded: boolean; error: string | null }> {
    return request(`/api/v1/inventory/connectors/${encodeURIComponent(connectorId)}/test`, {
      method: 'POST',
      token,
    });
  },
  updateInventoryConnector(
    token: string,
    connectorId: string,
    body: {
      enabled?: boolean;
      interval_minutes?: number | null;
      secret?: string;
      clear_secret?: boolean;
      config?: Record<string, unknown>;
    },
  ): Promise<InventoryConnector> {
    return request<InventoryConnector>(
      `/api/v1/inventory/connectors/${encodeURIComponent(connectorId)}`,
      { method: 'PATCH', token, body },
    );
  },
  runInventoryConnector(token: string, connectorId: string): Promise<unknown> {
    return request(`/api/v1/inventory/connectors/${encodeURIComponent(connectorId)}/runs`, {
      method: 'POST',
      token,
    });
  },
  listConnectorRuns(token: string): Promise<ConnectorRun[]> {
    return request<ConnectorRun[]>('/api/v1/inventory/runs', { token });
  },
  listReconciliationCandidates(token: string): Promise<ReconciliationCandidate[]> {
    return request<ReconciliationCandidate[]>('/api/v1/inventory/reconciliation', { token });
  },
  decideReconciliation(
    token: string,
    candidateId: string,
    action: 'approve' | 'reject' | 'split',
  ): Promise<ReconciliationCandidate> {
    return request<ReconciliationCandidate>(
      `/api/v1/inventory/reconciliation/${encodeURIComponent(candidateId)}/decision`,
      { method: 'POST', token, body: { action } },
    );
  },
  listReportTemplates(token: string): Promise<ReportTemplate[]> {
    return request<ReportTemplate[]>('/api/v1/report-templates', { token });
  },
  createReportTemplate(
    token: string,
    body: {
      site_id?: string;
      name: string;
      description?: string;
      report_types: string[];
      sections?: string[];
      filters?: Record<string, unknown>;
      redaction?: Record<string, unknown>;
      branding?: Record<string, unknown>;
      export_password?: string;
    },
  ): Promise<ReportTemplate> {
    return request<ReportTemplate>('/api/v1/report-templates', {
      method: 'POST',
      token,
      body,
    });
  },
  runReportTemplate(token: string, templateId: string): Promise<unknown> {
    return request(`/api/v1/report-templates/${encodeURIComponent(templateId)}/runs`, {
      method: 'POST',
      token,
    });
  },
  listReportTemplateRuns(token: string): Promise<ReportTemplateRun[]> {
    return request<ReportTemplateRun[]>('/api/v1/report-templates/runs', { token });
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
  relayEnrollmentCommand(token: string, name: string, siteId: string): Promise<RelayEnrollment> {
    return request<RelayEnrollment>('/api/v1/relays/enrollment-command', {
      method: 'POST',
      token,
      body: { name, site_id: siteId },
    });
  },
  setRelayScope(
    token: string,
    id: string,
    approvedCidrs: string[],
    deniedCidrs: string[] = [],
    allowPublicAddresses = false,
  ): Promise<{ approved_cidrs: string[]; denied_cidrs: string[] }> {
    return request(`/api/v1/relays/${id}/scope`, {
      method: 'POST',
      token,
      body: {
        approved_cidrs: approvedCidrs,
        denied_cidrs: deniedCidrs,
        allow_public_addresses: allowPublicAddresses,
      },
    });
  },
  killRelay(token: string, id: string): Promise<Relay> {
    return request<Relay>(`/api/v1/relays/${id}/kill`, { method: 'POST', token });
  },
  resumeRelay(token: string, id: string): Promise<Relay> {
    return request<Relay>(`/api/v1/relays/${id}/resume`, { method: 'POST', token });
  },
  revokeRelay(token: string, id: string): Promise<{ revoked: boolean }> {
    return request<{ revoked: boolean }>(`/api/v1/relays/${id}/revoke`, {
      method: 'POST',
      token,
    });
  },
  deleteRelay(token: string, id: string): Promise<void> {
    return request<void>(`/api/v1/relays/${id}`, { method: 'DELETE', token });
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
  listFindings(token: string, limit = 50, offset = 0): Promise<FindingPage<Finding>> {
    // The API caps page size at 200; requesting more 422s, which would leave the
    // findings list (and any severity/asset counts derived from it) empty.
    const capped = Math.min(limit, 200);
    return request<FindingPage<Finding>>(`/api/v1/findings?limit=${capped}&offset=${offset}`, {
      token,
    });
  },
  listAllFindings(token: string): Promise<FindingPage<Finding>> {
    return collectPages((offset) => api.listFindings(token, 200, offset));
  },
  async listFindingSnapshot(token: string): Promise<FindingPage<Finding> & { truncated: boolean }> {
    const items: Finding[] = [];
    const pageSize = 200;
    // Tables and summary cards are intentionally bounded. Large installations
    // must not download the entire findings corpus into one browser tab.
    const maxItems = 1000;
    let offset = 0;
    let total = 0;
    do {
      const limit = Math.min(pageSize, maxItems - items.length);
      const page = await request<FindingPage<Finding>>(
        `/api/v1/findings?limit=${limit}&offset=${offset}`,
        { token },
      );
      total = page.total;
      items.push(...page.items);
      if (page.items.length === 0) break;
      offset += page.items.length;
    } while (offset < total && items.length < maxItems);
    return { items, total, limit: maxItems, offset: 0, truncated: items.length < total };
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
  listRiskProfiles(token: string): Promise<RiskProfile[]> {
    return request<RiskProfile[]>('/api/v1/risk-profiles', { token });
  },
  findingScores(token: string, id: string): Promise<FindingScore[]> {
    return request<FindingScore[]>(`/api/v1/finding-scores/${encodeURIComponent(id)}`, { token });
  },
  recalculateFindingScore(token: string, id: string): Promise<FindingScore> {
    return request<FindingScore>(`/api/v1/finding-scores/${encodeURIComponent(id)}/recalculate`, {
      method: 'POST',
      token,
    });
  },
  listRemediationUnits(token: string): Promise<FindingPage<RemediationUnit>> {
    return request<FindingPage<RemediationUnit>>('/api/v1/remediation-units?limit=200', { token });
  },
  autoGroupRemediation(
    token: string,
    findingIds: string[],
  ): Promise<{
    units_created: number;
    memberships_created: number;
  }> {
    return request('/api/v1/remediation-units/auto-group', {
      method: 'POST',
      token,
      body: { finding_ids: findingIds },
    });
  },
  createFindingDecision(
    token: string,
    findingId: string,
    payload: {
      decision_type: 'false_positive' | 'duplicate' | 'suppression';
      reason: string;
      evidence: Array<Record<string, unknown>>;
      expires_at: string;
      duplicate_of_finding_id?: string;
    },
  ): Promise<FindingDecision> {
    return request<FindingDecision>(`/api/v1/findings/${encodeURIComponent(findingId)}/decisions`, {
      method: 'POST',
      token,
      body: payload,
    });
  },
  findingDecisions(token: string, findingId: string): Promise<FindingDecision[]> {
    return request<FindingDecision[]>(
      `/api/v1/findings/${encodeURIComponent(findingId)}/decisions`,
      { token },
    );
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

// --- Unauthenticated liveness endpoint (used by HealthPage) ---

export function fetchHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/health');
}
