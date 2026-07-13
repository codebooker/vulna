export type PassiveConnectorType =
  | 'dhcp'
  | 'dns'
  | 'active_directory'
  | 'entra'
  | 'unifi'
  | 'vcenter'
  | 'proxmox'
  | 'xcp_ng'
  | 'aws'
  | 'azure'
  | 'google_cloud'
  | 'csv'
  | 'generic_api';

export interface InventoryConnector {
  id: string;
  organization_id: string;
  site_id: string;
  name: string;
  connector_type: PassiveConnectorType;
  base_url: string | null;
  config_json: Record<string, unknown>;
  has_secret: boolean;
  enabled: boolean;
  interval_minutes: number | null;
  next_run_at: string | null;
  successful_test_at: string | null;
  last_test_error: string | null;
  last_run_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ConnectorRun {
  id: string;
  connector_id: string;
  site_id: string;
  status: 'queued' | 'running' | 'succeeded' | 'partial' | 'failed' | 'cancelled';
  records_read: number;
  observations_created: number;
  error: string | null;
  created_at: string;
}

export interface ReconciliationCandidate {
  id: string;
  observation_id: string;
  candidate_asset_id: string;
  site_id: string;
  score: number;
  reasons_json: Array<Record<string, unknown>>;
  conflicts_json: Array<Record<string, unknown>>;
  status: 'pending' | 'auto_merged' | 'approved' | 'rejected' | 'split';
  decided_at: string | null;
}

export interface InventoryDashboard {
  generated_at: string;
  findings: {
    total: number;
    open: number;
    closed: number;
    breached: number;
    by_status: Record<string, number>;
    by_severity: Record<string, number>;
  };
  inventory: {
    total: number;
    by_state: Record<string, number>;
    pending_reconciliation: number;
  };
  connector_runs: Record<string, number>;
  cache: 'hit' | 'miss';
}

export interface ReportTemplate {
  id: string;
  organization_id: string;
  site_id: string | null;
  name: string;
  description: string | null;
  version: number;
  report_types_json: string[];
  sections_json: string[];
  filters_json: Record<string, unknown>;
  redaction_json: Record<string, unknown>;
  branding_json: Record<string, unknown>;
  has_export_password: boolean;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface ReportTemplateRun {
  id: string;
  template_id: string;
  status: 'queued' | 'running' | 'succeeded' | 'failed';
  template_version: number;
  report_ids_json: string[];
  comparison_json: Record<string, unknown>;
  error: string | null;
  created_at: string;
}
