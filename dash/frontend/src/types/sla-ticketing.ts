export interface SlaPolicy {
  id: string;
  name: string;
  description: string | null;
  priority: number;
  enabled: boolean;
  match_json: Record<string, unknown>;
  due_days_json: Record<string, number>;
  pause_on_risk_acceptance: boolean;
  created_at: string;
  updated_at: string;
}

export interface SlaMetrics {
  total_with_sla: number;
  open: number;
  overdue: number;
  due_within_7_days: number;
  completed: number;
  completed_on_time: number;
  on_time_percentage: number | null;
  by_severity: Record<string, number>;
  generated_at: string;
}

export type TicketConnectorType = 'github' | 'gitlab' | 'glpi' | 'jira' | 'generic';

export interface TicketConnector {
  id: string;
  name: string;
  connector_type: TicketConnectorType;
  base_url: string;
  project_key: string;
  config_json: Record<string, unknown>;
  has_secret: boolean;
  enabled: boolean;
  close_after_verification: boolean;
  timeout_seconds: number;
  successful_test_at: string | null;
  last_test_error: string | null;
  created_at: string;
  updated_at: string;
}

export interface TicketConnectorTest {
  succeeded: boolean;
  tested_at: string;
  metadata: Record<string, unknown>;
  error: string | null;
}

export interface TicketSync {
  id: string;
  site_id: string;
  connector_id: string;
  finding_id: string;
  status: 'pending' | 'succeeded' | 'failed' | 'skipped';
  last_action: 'upsert' | 'close';
  external_ticket_id: string | null;
  external_ticket_url: string | null;
  last_payload_hash: string | null;
  last_error: string | null;
  last_synced_at: string | null;
  created_at: string;
  updated_at: string;
}
