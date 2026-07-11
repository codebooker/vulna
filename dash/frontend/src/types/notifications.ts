export interface NotificationEventDef {
  type: string;
  label: string;
}

export interface NotificationChannel {
  id: string;
  name: string;
  channel_type: string;
  config: Record<string, unknown>;
  has_secret: boolean;
  events: string[];
  policy: string;
  quiet_start_hour: number | null;
  quiet_end_hour: number | null;
  enabled: boolean;
  last_digest_at: string | null;
}

export interface NotificationDelivery {
  id: string;
  channel_id: string;
  event_type: string;
  status: string;
  attempts: number;
  last_error: string | null;
  title: string;
  created_at: string;
  sent_at: string | null;
}

export interface NewChannel {
  name: string;
  channel_type: string;
  config: Record<string, unknown>;
  secret?: string;
  events: string[];
  policy: string;
}
