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
