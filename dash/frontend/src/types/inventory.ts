export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface Site {
  id: string;
  organization_id: string;
  name: string;
  code: string;
  description: string | null;
  address: string | null;
  timezone: string;
  business_owner: string | null;
  technical_owner: string | null;
  owner_user_id: string | null;
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface NewSite {
  name: string;
  code: string;
  description?: string | null;
}

export interface Asset {
  id: string;
  organization_id: string;
  site_id: string;
  canonical_name: string;
  asset_type: string;
  status: string;
  operating_system: string | null;
  manufacturer: string | null;
  identity_confidence: number;
  department: string | null;
  business_function: string | null;
  environment: 'unknown' | 'production' | 'staging' | 'development' | 'test';
  criticality: 'unknown' | 'low' | 'moderate' | 'high' | 'mission_critical';
  data_classification: 'unknown' | 'public' | 'internal' | 'confidential' | 'restricted';
  internet_exposed: boolean;
  owner_user_id: string | null;
  context_json: Record<string, unknown>;
  ip_addresses: string[];
  mac_addresses: string[];
  hostnames: string[];
  tags: AssetTag[];
  group_ids: string[];
  first_seen_at: string | null;
  last_seen_at: string | null;
  last_assessed_at: string | null;
  created_at: string;
  updated_at: string;
}

export type IdentifierType =
  | 'ip_address'
  | 'mac_address'
  | 'hostname'
  | 'fqdn'
  | 'smb_name'
  | 'ssh_host_key'
  | 'tls_cert_fingerprint'
  | 'snmp_engine_id'
  | 'cloud_instance_id'
  | 'agent_id';

export interface AssetIdentifier {
  identifier_type: IdentifierType;
  identifier_value: string;
}

/** An asset plus its discovered identifiers (hostname, MAC, IPs) and services. */
export interface AssetDetail extends Asset {
  identifiers: AssetIdentifier[];
  services: unknown[];
}

export interface AssetTag {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  color: string | null;
  created_at: string;
  updated_at: string;
}

export interface AssetGroup {
  id: string;
  organization_id: string;
  site_id: string | null;
  name: string;
  description: string | null;
  group_type: 'static' | 'dynamic';
  rule_json: Record<string, unknown> | null;
  priority: number;
  owner_user_id: string | null;
  enabled: boolean;
  last_evaluated_at: string | null;
  member_count: number;
  created_at: string;
  updated_at: string;
}

export interface AssetContextPatch {
  canonical_name?: string;
  asset_type?: string;
  status?: string;
  department?: string | null;
  business_function?: string | null;
  environment?: Asset['environment'];
  criticality?: Asset['criticality'];
  data_classification?: Asset['data_classification'];
  internet_exposed?: boolean;
  owner_user_id?: string | null;
  context_json?: Record<string, unknown>;
}

export interface AssetBulkPayload {
  asset_ids: string[];
  context?: AssetContextPatch;
  add_tag_ids?: string[];
  remove_tag_ids?: string[];
  add_static_group_ids?: string[];
  remove_static_group_ids?: string[];
}

export interface AssetBulkResult {
  updated_assets: number;
  tags_added: number;
  tags_removed: number;
  memberships_added: number;
  memberships_removed: number;
}

export interface AssetFilters {
  q?: string;
  tag_id?: string;
  group_id?: string;
  department?: string;
  environment?: Asset['environment'];
  criticality?: Asset['criticality'];
  data_classification?: Asset['data_classification'];
  owner_user_id?: string;
  internet_exposed?: boolean;
}

export interface OwnershipResolution {
  asset_id: string;
  finding_id: string | null;
  owner_user_id: string | null;
  source: 'explicit_finding' | 'explicit_asset' | 'group' | 'site' | 'department' | 'unassigned';
  source_id: string | null;
  explanation: Record<string, unknown>;
}

export interface OwnershipHistory {
  id: string;
  asset_id: string;
  finding_id: string | null;
  owner_user_id: string | null;
  source: OwnershipResolution['source'];
  source_id: string | null;
  explanation_json: Record<string, unknown>;
  created_at: string;
}

export interface DepartmentOwner {
  id: string;
  department: string;
  owner_user_id: string;
  created_at: string;
  updated_at: string;
}

export interface GroupPreview {
  matches: Array<{
    asset_id: string;
    canonical_name: string;
    explanation: Record<string, unknown>;
  }>;
  total: number;
  truncated: boolean;
}

export interface NetworkScope {
  id: string;
  organization_id: string;
  site_id: string;
  network_id: string;
  probe_id: string | null;
  name: string;
  cidr: string;
  enabled: boolean;
  allow_public_addresses: boolean;
  approved_by: string | null;
  approved_at: string | null;
  policy_version: number;
  created_at: string;
  updated_at: string;
}

export interface NewScope {
  site_id: string;
  name: string;
  cidr: string;
  allow_public_addresses?: boolean;
}

export interface ChangeEvent {
  id: string;
  site_id: string;
  asset_id: string | null;
  event_type: string;
  severity: string;
  summary: string;
  created_at: string;
}
