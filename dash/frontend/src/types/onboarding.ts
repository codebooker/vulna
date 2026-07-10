export interface OnboardingState {
  current_step: string;
  completed_steps: string[];
  site_id: string | null;
  scope_id: string | null;
  first_job_id: string | null;
  demo_used: boolean;
  dismissed: boolean;
  completed_at: string | null;
}

export interface CompleteStepPayload {
  step: string;
  site_id?: string;
  scope_id?: string;
  first_job_id?: string;
  demo_used?: boolean;
}

export interface RecoveryCodes {
  codes: string[];
  generated_at: string;
}

export interface NetworkCandidates {
  candidates: string[];
  source: string;
  note: string;
}

export interface ScopePreview {
  cidr: string;
  host_estimate: number;
  is_private: boolean;
  warnings: string[];
  requires_confirmation: boolean;
}

export interface ScanPreset {
  key: string;
  name: string;
  mode: string;
  description: string;
  checks: string[];
  intrusive: boolean;
  active_web: boolean;
  uses_credentials: boolean;
  resource_class: string;
  duration_class: string;
}

export interface ScanSummary {
  preset: string;
  preset_name: string;
  targets: string[];
  host_estimate: number;
  checks: string[];
  intrusive: boolean;
  active_web: boolean;
  uses_credentials: boolean;
  resource_class: string;
  duration_class: string;
  demo: boolean;
  data_retention: string;
}

export interface DemoTarget {
  cidr: string;
  note: string;
}

export interface ComponentHealth {
  application: string;
  database: string;
  local_scout: string;
  scanner_capabilities: string;
  feeds: string;
}

export interface ProbeSummary {
  id: string;
  name: string;
  status: string;
  site_id: string;
}

export interface JobSummary {
  id: string;
  status: string;
  mode: string;
}
