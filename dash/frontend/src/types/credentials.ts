import type { Page } from './inventory';

export type CredentialProtocol = 'ssh' | 'winrm';
export type CredentialAuthType = 'password' | 'ssh_private_key';
export type CredentialTargetType = 'asset' | 'group' | 'tag' | 'network' | 'site' | 'preset';

export interface Credential {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  protocol: CredentialProtocol;
  auth_type: CredentialAuthType;
  username: string;
  metadata: Record<string, unknown>;
  is_active: boolean;
  has_secret: boolean;
  current_version: number;
  created_at: string;
  updated_at: string;
}

export interface CredentialCreate {
  name: string;
  description?: string;
  protocol: CredentialProtocol;
  auth_type: CredentialAuthType;
  username: string;
  secret: string;
  metadata: Record<string, unknown>;
}

export interface CredentialAssignment {
  id: string;
  credential_id: string;
  protocol: CredentialProtocol;
  credential_name: string;
  target_type: CredentialTargetType;
  target_id: string;
  site_id: string | null;
  enabled: boolean;
  created_at: string;
}

export interface CredentialResolution {
  protocol: CredentialProtocol;
  credential_id: string | null;
  credential_name: string | null;
  secret_version_id: string | null;
  matched_level: CredentialTargetType | null;
  conflict: boolean;
  candidates: string[];
  message: string;
}

export interface CredentialUsage {
  id: string;
  credential_id: string;
  secret_version_id: string;
  asset_id: string;
  probe_id: string;
  scan_job_id: string;
  protocol: CredentialProtocol;
  status: 'encrypted_for_job' | 'succeeded' | 'failed';
  detail: string | null;
  created_at: string;
}

export interface EolEvaluation {
  status: 'unknown' | 'supported' | 'end_of_life' | 'extended_support';
  eol_date: string | null;
  source: string;
  source_url: string | null;
  overridden: boolean;
}

export interface SoftwareItem {
  id: string;
  organization_id: string;
  site_id: string;
  asset_id: string;
  source: 'ssh' | 'winrm' | 'manual';
  name: string;
  package_key: string;
  version: string;
  architecture: string;
  publisher: string | null;
  product_key: string | null;
  install_date: string | null;
  first_seen_at: string;
  last_seen_at: string;
  removed_at: string | null;
  metadata: Record<string, unknown>;
  eol: EolEvaluation;
}

export type CredentialPage = Page<Credential>;
export type CredentialAssignmentPage = Page<CredentialAssignment>;
export type CredentialUsagePage = Page<CredentialUsage>;
export type SoftwarePage = Page<SoftwareItem>;
