export interface NetworkRange {
  id: string;
  cidr: string;
  enabled: boolean;
  allow_public_addresses: boolean;
  maximum_hosts: number | null;
  maximum_packets_per_second: number | null;
  maximum_concurrency: number | null;
}

export interface NetworkScoutBinding {
  probe_id: string;
  probe_name: string;
  is_primary: boolean;
}

export interface Network {
  id: string;
  organization_id: string;
  site_id: string;
  name: string;
  description: string | null;
  enabled: boolean;
  policy_version: number;
  ranges: NetworkRange[];
  scouts: NetworkScoutBinding[];
  created_at: string;
  updated_at: string;
}

export interface NewNetwork {
  site_id: string;
  name: string;
  description?: string | null;
  ranges?: { cidr: string; allow_public_addresses?: boolean }[];
  scouts?: { probe_id: string; is_primary: boolean }[];
}
