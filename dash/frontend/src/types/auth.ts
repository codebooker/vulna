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
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export interface UserSummary extends CurrentUser {
  account_status: AccountStatus;
  authentication_source: AuthenticationSource;
  site_access_mode: SiteAccessMode;
  site_ids: string[];
  mfa_status: 'not_enrolled' | 'planned';
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
