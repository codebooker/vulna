import type { Role } from './auth';

export interface ScimToken {
  id: string;
  name: string;
  token_prefix: string;
  has_secret: boolean;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  last_used_at: string | null;
  last_used_ip: string | null;
}

export interface ScimTokenIssued extends ScimToken {
  token: string;
}

export interface ScimGroupMapping {
  id: string;
  external_id: string | null;
  display_name: string;
  member_count: number;
  role: Role | null;
  grants_all_sites: boolean;
  site_ids: string[];
  created_at: string;
  updated_at: string;
}

export interface ScimMappingPayload {
  role: Role | null;
  grants_all_sites: boolean;
  site_ids: string[];
}

export interface ScimMappingPreview extends ScimMappingPayload {
  group_id: string;
  affected_users: number;
  users: Array<{
    id: string;
    email: string;
    role: Role;
    site_access_mode: 'all' | 'assigned';
  }>;
}

export interface ScimProvisioningLog {
  id: string;
  operation: string;
  resource_type: string | null;
  resource_id: string | null;
  external_id: string | null;
  status_code: number;
  succeeded: boolean;
  detail: string | null;
  request_id: string | null;
  source_ip: string | null;
  changes: Record<string, unknown>;
  created_at: string;
}

export interface ScimLogPage {
  items: ScimProvisioningLog[];
  total: number;
  limit: number;
  offset: number;
}
