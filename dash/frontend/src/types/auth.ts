export type Role =
  | 'administrator'
  | 'security_operator'
  | 'pentest_approver'
  | 'remediation_owner'
  | 'auditor'
  | 'viewer';

export type AccountStatus = 'invited' | 'active' | 'suspended' | 'deactivated' | 'locked';
export type AuthenticationSource = 'local' | 'jit' | 'scim';
export type SiteAccessMode = 'all' | 'assigned';

export interface CurrentUser {
  id: string;
  email: string;
  full_name: string | null;
  role: Role;
  organization_id: string;
  is_active: boolean;
  mfa_status: 'not_enrolled' | 'enrolled' | 'required';
  mfa_grace_expires_at: string | null;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  session_id: string | null;
  mfa_required: boolean;
  mfa_enrollment_required: boolean;
  mfa_methods: string[];
  mfa_grace_expires_at: string | null;
}

export interface MfaVerification {
  access_token: string;
  token_type: string;
  expires_in: number;
  method: string;
  recovery_codes_remaining: number | null;
}

export interface MfaStatus {
  required: boolean;
  enrolled: boolean;
  grace_expires_at: string | null;
  totp: boolean;
  webauthn_credentials: number;
  recovery_codes_remaining: number;
  methods: string[];
}

export interface TotpSetup {
  factor_id: string;
  secret: string;
  provisioning_uri: string;
  expires_in: number;
}

export interface RecoveryCodes {
  codes: string[];
  shown_once: boolean;
}

export interface WebAuthnBegin {
  challenge_id: string;
  public_key: Record<string, unknown>;
}

export interface WebAuthnCredentialSummary {
  id: string;
  label: string;
  device_type: string;
  backed_up: boolean;
  transports: string[];
  created_at: string;
  last_used_at: string | null;
}

export interface MfaPolicy {
  mode: 'optional' | 'required';
  required_roles: Role[];
  grace_period_days: number;
}

export interface UserSession {
  id: string;
  user_id: string;
  created_at: string;
  last_seen_at: string;
  authenticated_at: string;
  idle_expires_at: string;
  absolute_expires_at: string;
  revoked_at: string | null;
  revocation_reason: string | null;
  device_name: string | null;
  source_ip: string | null;
  user_agent: string | null;
  trusted_until: string | null;
  current: boolean;
  active: boolean;
  privileged_until: string;
  mfa_pending: boolean;
  mfa_authenticated_at: string | null;
  authentication_methods: string[];
}

export interface SessionPolicy {
  idle_timeout_hours: number;
  absolute_lifetime_days: number;
  privileged_window_minutes: number;
  max_concurrent_sessions: number;
  trusted_device_days: number;
}

export interface UserSummary extends CurrentUser {
  account_status: AccountStatus;
  authentication_source: AuthenticationSource;
  site_access_mode: SiteAccessMode;
  site_ids: string[];
  mfa_status: 'not_enrolled' | 'enrolled' | 'required';
  mfa_grace_expires_at: string | null;
  last_login_at: string | null;
  invited_at: string | null;
  activated_at: string | null;
  suspended_at: string | null;
  deactivated_at: string | null;
  password_changed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface InviteUserPayload {
  email: string;
  full_name?: string | null;
  role: Role;
  site_access_mode: SiteAccessMode;
  site_ids: string[];
}

export interface InvitedUser extends UserSummary {
  invitation_url: string | null;
  invitation_expires_at: string | null;
}

export interface InvitationIssued {
  user: UserSummary;
  invitation_url: string;
  expires_at: string;
}

export interface PasswordResetIssued {
  user_id: string;
  reset_url: string;
  expires_at: string;
}

export interface LifecycleEvent {
  id: string;
  user_id: string;
  actor_user_id: string | null;
  event_type: string;
  previous_status: string | null;
  new_status: string | null;
  reason: string | null;
  metadata_json: Record<string, unknown>;
  created_at: string;
}

export interface LoginHistoryEvent {
  id: string;
  outcome: 'succeeded' | 'failed' | 'denied';
  source_ip: string | null;
  user_agent: string | null;
  occurred_at: string;
}
