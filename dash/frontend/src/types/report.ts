export interface Report {
  id: string;
  organization_id: string;
  site_id: string | null;
  scan_job_id: string | null;
  report_type: string;
  format: string;
  status: string;
  sha256: string | null;
  size_bytes: number;
  generated_at: string | null;
  expires_at: string | null;
  error: string | null;
  created_at: string;
}
