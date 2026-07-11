export interface DiagnosticCheck {
  component: string;
  status: string; // ok | warn | fail
  summary: string;
  impact: string;
  data_safety: string;
  next_step: string;
  doc: string;
}

export interface DiagnosticsResult {
  summary: { ok: number; warn: number; fail: number };
  checks: DiagnosticCheck[];
}

export interface TimelineEvent {
  when: string;
  kind: string;
  summary: string;
}

export interface SupportBundle {
  manifest: { section: string; fields: string[] }[];
  bundle: Record<string, unknown>;
  secret_scan: { clean: boolean; findings: string[] };
}
