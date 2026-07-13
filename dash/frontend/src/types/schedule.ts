export interface ScanSchedule {
  id: string;
  organization_id: string;
  network_id: string;
  name: string;
  mode: string;
  interval_minutes: number;
  enabled: boolean;
  next_run_at: string;
  last_run_at: string | null;
  last_job_id: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

export interface NewSchedule {
  network_id: string;
  name: string;
  interval_minutes: number;
}

/** A one-off (or schedule-spawned) scan job. */
export interface Job {
  id: string;
  site_id: string;
  probe_id: string;
  network_id: string | null;
  mode: string;
  status: string;
  requested_targets_json: string[];
  not_before: string;
  expires_at: string;
  created_by: string | null;
  started_at: string | null;
  finished_at: string | null;
  error_code: string | null;
  error_message: string | null;
  summary_json: Record<string, unknown>;
  created_at: string;
}
