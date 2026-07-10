export interface EnrollmentCommand {
  site_id: string;
  probe_name: string;
  token: string;
  short_code: string;
  expires_at: string;
  server_url: string;
  commands: Record<string, string>;
  verification: string;
}
