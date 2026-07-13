export interface Finding {
  id: string;
  site_id: string;
  asset_id: string | null;
  service_id: string | null;
  scanner_name: string;
  title: string;
  description: string | null;
  severity: string;
  cvss_score: number | null;
  cvss_vector: string | null;
  cve_ids_json: string[];
  confidence: number;
  confidence_label: string;
  priority: string;
  priority_rationale: string;
  current_score_snapshot_id: string | null;
  risk_score: number | null;
  risk_profile_version: number | null;
  risk_scored_at: string | null;
  known_exploited: boolean;
  epss_score: number | null;
  validation_status: string;
  evidence_json: Record<string, unknown>;
  remediation: string | null;
  references_json: string[];
  status: string;
  owner_user_id: string | null;
  last_verified_at: string | null;
  resolved_at: string | null;
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}
