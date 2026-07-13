export interface RiskProfile {
  id: string;
  name: string;
  version: number;
  description: string | null;
  weights_json: Record<string, number>;
  is_default: boolean;
  created_at: string;
}

export interface RiskFactor {
  factor: string;
  source_value: unknown;
  normalized_value: number;
  weight: number;
  contribution: number;
}

export interface FindingScore {
  id: string;
  finding_id: string;
  risk_profile_id: string;
  profile_version: number;
  score: number;
  priority: string;
  weighted_sum: number;
  positive_maximum: number;
  source_values_json: Record<string, unknown>;
  factors_json: RiskFactor[];
  input_hash: string;
  created_at: string;
}

export interface RemediationUnit {
  id: string;
  site_id: string;
  key_type: 'cve' | 'package' | 'product' | 'remediation' | 'manual';
  exact_key: string;
  title: string;
  description: string | null;
  status: 'open' | 'in_progress' | 'ready_for_verification' | 'resolved';
  owner_user_id: string | null;
  automatically_created: boolean;
  finding_count: number;
  projected_risk_reduction: number;
  created_at: string;
  updated_at: string;
}

export interface FindingDecision {
  id: string;
  finding_id: string;
  decision_type: 'false_positive' | 'duplicate' | 'suppression';
  status: 'active' | 'expired' | 'revoked';
  reason: string;
  evidence_json: Array<Record<string, unknown>>;
  expires_at: string;
  duplicate_of_finding_id: string | null;
  created_at: string;
}
