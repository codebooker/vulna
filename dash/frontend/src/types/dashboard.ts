export interface TopFinding {
  id: string;
  title: string;
  priority: string;
  rationale: string;
  severity: string;
  confidence_label: string;
  asset_id: string | null;
}

export interface DashboardSummary {
  health: Record<string, string>;
  needs_attention: {
    fix_now: number;
    plan: number;
    watch: number;
    informational: number;
    top: TopFinding[];
  };
  changed_recently: {
    window_days: number;
    total: number;
    by_type: Record<string, number>;
    recent: { event_type: string; summary: string; severity: string; created_at: string }[];
  };
  unassessed: {
    stale_assets: number;
    approved_scopes: number;
    completed_scans: number;
  };
  next_action: { kind: string; priority: string; message: string };
}

export interface SearchResults {
  assets: SearchHit[];
  findings: SearchHit[];
  sites: SearchHit[];
  scans: SearchHit[];
  reports: SearchHit[];
}

export interface SearchHit {
  id: string;
  label: string;
  kind: string;
}
