export type BackgroundTaskStatus =
  'queued' | 'running' | 'retry' | 'completed' | 'cancelled' | 'dead_letter';

export interface BackgroundTask {
  id: string;
  organization_id: string | null;
  task_type: string;
  payload_json: Record<string, unknown>;
  idempotency_key: string;
  status: BackgroundTaskStatus;
  priority: number;
  scheduled_at: string;
  attempts: number;
  max_attempts: number;
  lease_owner: string | null;
  lease_expires_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  cancel_requested_at: string | null;
  cancelled_at: string | null;
  dead_lettered_at: string | null;
  last_error: string | null;
  result_json: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface WorkerHeartbeat {
  id: string;
  worker_id: string;
  kind: string;
  hostname: string;
  process_id: number;
  status: string;
  current_task_id: string | null;
  started_at: string;
  last_seen_at: string;
  metadata_json: Record<string, unknown>;
}

export interface TaskHealth {
  counts: Record<string, number>;
  workers: WorkerHeartbeat[];
  stale_after_seconds: number;
}

export interface TaskPage {
  items: BackgroundTask[];
  total: number;
  limit: number;
  offset: number;
}
