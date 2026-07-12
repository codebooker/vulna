export interface Relay {
  id: string;
  name: string;
  site_id: string | null;
  status: string;
  tunnel_up: boolean;
  tunnel_address: string | null;
  approved_cidrs: string[];
  denied_cidrs: string[];
  certificate_fingerprint: string | null;
  last_seen_at: string | null;
  enrolled_at: string | null;
}

export interface RelayEnrollment {
  relay_id: string;
  token: string;
  short_code: string;
  install: { name: string; command: string; note: string };
}
