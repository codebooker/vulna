import type { Role } from './auth';

export type IdentityProtocol = 'oidc' | 'saml';
export type SsoPolicyMode = 'disabled' | 'optional' | 'enforced';

export interface IdentityProvider {
  id: string;
  organization_id: string;
  name: string;
  slug: string;
  protocol: IdentityProtocol;
  enabled: boolean;
  jit_provisioning: boolean;
  default_role: Role;
  preset: string;
  allow_private_network: boolean;
  issuer: string | null;
  discovery_url: string | null;
  client_id: string | null;
  scopes: string[];
  idp_entity_id: string | null;
  idp_sso_url: string | null;
  idp_slo_url: string | null;
  want_assertions_encrypted: boolean;
  has_client_secret: boolean;
  has_idp_certificate: boolean;
  has_next_idp_certificate: boolean;
  has_sp_certificate: boolean;
  validated_at: string | null;
  last_test_succeeded_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface IdentityProviderCreate {
  name: string;
  slug: string;
  protocol: IdentityProtocol;
  preset?: 'generic' | 'entra' | 'google' | 'okta' | 'keycloak';
  jit_provisioning?: boolean;
  default_role?: Role;
  allow_private_network?: boolean;
  issuer?: string;
  discovery_url?: string;
  client_id?: string;
  client_secret?: string;
  want_assertions_encrypted?: boolean;
}

export interface SsoPolicy {
  mode: SsoPolicyMode;
  identity_provider_id: string | null;
  break_glass_user_ids: string[];
  enforcement_ready: boolean;
  readiness_reasons: string[];
}

export interface GroupMapping {
  id: string;
  external_group: string;
  role: Role | null;
  site_ids: string[];
}

export interface PublicIdentityProvider {
  id: string;
  name: string;
  slug: string;
  protocol: IdentityProtocol;
}

export interface SsoStart {
  authorization_url: string;
  expires_at: string;
}
