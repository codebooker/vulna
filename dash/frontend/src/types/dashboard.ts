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
  finding_metrics: {
    active_total: number;
    by_severity: Record<
      'critical' | 'high' | 'medium' | 'low' | 'info',
      { total: number; fresh: number; resolved: number }
    >;
    attention_assets: number;
    risky_assets: {
      asset_id: string;
      name: string;
      critical: number;
      high: number;
      total: number;
    }[];
    risk_by_site: {
      site_id: string;
      critical: number;
      high: number;
      total: number;
    }[];
  };
  operational_metrics: {
    asset_total: number;
    failed_scans: number;
    recent_jobs: {
      id: string;
      mode: string;
      status: string;
      targets: string[];
      created_at: string;
      finished_at: string | null;
      error_message: string | null;
    }[];
    recent_failed_jobs: DashboardSummary['operational_metrics']['recent_jobs'];
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
