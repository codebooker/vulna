import type { Role } from './auth';

export type PrincipalType = 'user' | 'service_account';
export type GrantScopeType = 'organization' | 'site';
export type ServiceAccountStatus = 'active' | 'suspended';

export interface PermissionDefinition {
  key: string;
  label: string;
  description: string;
  scopes: GrantScopeType[];
  high_risk: boolean;
}

export interface AuthorizationRole {
  id: string;
  key: string;
  name: string;
  description: string | null;
  is_system: boolean;
  compatibility_role: Role | null;
  permission_keys: string[];
  created_at: string;
  updated_at: string;
}

export interface ScopedGrant {
  id: string;
  organization_id: string;
  principal_type: PrincipalType;
  principal_id: string;
  role_id: string;
  role_key: string;
  role_name: string;
  scope_type: GrantScopeType;
  scope_id: string;
  created_at: string;
}

export interface ServiceAccount {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  status: ServiceAccountStatus;
  primary_role: Role;
  last_used_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ApiTokenSummary {
  id: string;
  principal_type: PrincipalType;
  principal_id: string;
  name: string;
  token_prefix: string;
  has_secret: boolean;
  expires_at: string;
  revoked_at: string | null;
  ip_restrictions: string[];
  last_used_at: string | null;
  last_used_ip: string | null;
  created_at: string;
}

export interface ApiTokenIssued extends ApiTokenSummary {
  token: string;
}

export interface ApiTokenCreate {
  name: string;
  expires_in_days: number;
  ip_restrictions: string[];
}
