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
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface NewSite {
  name: string;
  code: string;
  description?: string | null;
}

export interface NetworkScope {
  id: string;
  organization_id: string;
  site_id: string;
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
