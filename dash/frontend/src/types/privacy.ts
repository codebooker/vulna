export interface OutboundConnection {
  name: string;
  category: string;
  destination: string | null;
  enabled: boolean;
  purpose: string;
}

export interface SecretItem {
  name: string;
  present: boolean;
  category: string;
  rotatable: boolean;
  count?: number;
}

export interface PrivacySettings {
  telemetry_enabled: boolean;
  update_check_enabled: boolean;
  intelligence_feeds_enabled: boolean;
  local_analytics_enabled: boolean;
}

export interface TelemetryPreview {
  schema_version: string;
  vulna_version: string;
  counts: Record<string, number>;
  excluded: string[];
}
