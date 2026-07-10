export interface NetworkIssue {
  code: string;
  problem: string;
  action: string;
}

export interface CertificateInfo {
  common_name: string | null;
  dns_names: string[];
  not_after: string;
  expired: boolean;
  days_left: number;
}

export interface ValidateResult {
  valid: boolean;
  issues: NetworkIssue[];
  certificate: CertificateInfo | null;
  settings: { mode: string; vulna_domain: string; caddy_tls: string; warnings: string[] };
  proxy_snippet: string;
}

export interface BrowserTest {
  reachable: boolean;
  peer: string | null;
  peer_is_trusted_proxy: boolean;
  host_header: string | null;
  forwarded_proto: string | null;
  fingerprint_header_would_be_trusted: boolean;
  note: string;
}

export interface NetworkStatus {
  public_base_url: string | null;
  cors_origins: string[];
  trusted_proxies: string;
  access_modes: string[];
  note: string;
}
