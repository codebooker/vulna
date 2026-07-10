export type FeedStatus = 'ok' | 'degraded' | 'failed' | 'stale' | 'never_synced';

export interface FeedHealth {
  source: string;
  status: FeedStatus;
  last_success_at: string | null;
  last_attempt_at: string | null;
  records_processed: number;
  records_changed: number;
  attempts: number;
  error: string | null;
  last_source_timestamp: string | null;
  updated_at: string;
}

export interface SyncResult {
  source: string;
  status: FeedStatus;
  attempts: number;
  records_processed: number;
  records_changed: number;
  change_events: number;
  error: string | null;
}
