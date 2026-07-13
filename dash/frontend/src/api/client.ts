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
  ChangeEvent,
  NetworkScope,
  NewScope,
  NewSite,
  Page,
  Site,
} from '../types/inventory';
import type { Network, NewNetwork } from '../types/network';
import type { PentestCandidate, PentestSession, RulesOfEngagement } from '../types/pentest';
import type { Job, NewSchedule, ScanSchedule } from '../types/schedule';
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
import type { HealthResponse, SystemInfoResponse } from '../types/system';
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
    credentials: 'include',
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
  listSites(token: string): Promise<Page<Site>> {
    return request<Page<Site>>('/api/v1/sites', { token });
  },
  createSite(token: string, payload: NewSite): Promise<Site> {
    return request<Site>('/api/v1/sites', { method: 'POST', token, body: payload });
  },
  updateSite(
    token: string,
    siteId: string,
    patch: { name?: string; code?: string; description?: string | null; address?: string | null },
  ): Promise<Site> {
    return request<Site>(`/api/v1/sites/${siteId}`, { method: 'PATCH', token, body: patch });
  },
  deleteSite(token: string, siteId: string): Promise<void> {
    return request<void>(`/api/v1/sites/${siteId}`, { method: 'DELETE', token });
  },
  listAssets(token: string, limit = 200, siteId?: string): Promise<Page<Asset>> {
    const params = new URLSearchParams({ limit: String(limit) });
    if (siteId) params.set('site_id', siteId);
    return request<Page<Asset>>(`/api/v1/assets?${params.toString()}`, { token });
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
  listReports(token: string, limit = 50): Promise<Page<Report>> {
    return request<Page<Report>>(`/api/v1/reports?limit=${limit}`, { token });
  },
  createReports(token: string, scanJobId: string, reportTypes?: string[]): Promise<Report[]> {
    return request<Report[]>('/api/v1/reports', {
      method: 'POST',
      token,
      body: { scan_job_id: scanJobId, ...(reportTypes ? { report_types: reportTypes } : {}) },
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
  pentestModules(token: string): Promise<{ modules: string[] }> {
    return request<{ modules: string[] }>('/api/v1/pentest/allowlisted-modules', { token });
  },
  pentestCandidates(token: string): Promise<PentestCandidate[]> {
    return request<PentestCandidate[]>('/api/v1/pentest/candidates', { token });
  },
  createPentestSession(
    token: string,
    payload: { finding_id: string; module: string; rules_of_engagement_id?: string },
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
  createJob(token: string, probeId: string, targets: string[]): Promise<JobSummary> {
    return request<JobSummary>('/api/v1/jobs', {
      method: 'POST',
      token,
      body: { probe_id: probeId, targets, mode: 'vulnerability_assessment' },
    });
  },
  listJobs(token: string, status?: string, limit = 100): Promise<Page<Job>> {
    const params = new URLSearchParams({ limit: String(limit) });
    if (status) params.set('status', status);
    return request<Page<Job>>(`/api/v1/jobs?${params.toString()}`, { token });
  },
  cancelJob(token: string, id: string): Promise<Job> {
    return request<Job>(`/api/v1/jobs/${id}/cancel`, { method: 'POST', token });
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
  ): Promise<{ approved_cidrs: string[]; denied_cidrs: string[] }> {
    return request(`/api/v1/relays/${id}/scope`, {
      method: 'POST',
      token,
      body: { approved_cidrs: approvedCidrs, denied_cidrs: deniedCidrs },
    });
  },
  killRelay(token: string, id: string): Promise<Relay> {
    return request<Relay>(`/api/v1/relays/${id}/kill`, { method: 'POST', token });
  },
  resumeRelay(token: string, id: string): Promise<Relay> {
    return request<Relay>(`/api/v1/relays/${id}/resume`, { method: 'POST', token });
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
    // The API caps page size at 200; requesting more 422s, which would leave the
    // findings list (and any severity/asset counts derived from it) empty.
    const capped = Math.min(limit, 200);
    return request<FindingPage<Finding>>(`/api/v1/findings?limit=${capped}`, { token });
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
