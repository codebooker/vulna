export interface HealthResponse {
  status: string;
  service: string;
  version: string;
}

export interface SystemInfoResponse {
  service: string;
  version: string;
  environment: string;
  api_version: string;
}
