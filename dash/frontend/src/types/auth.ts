export type Role =
  | 'administrator'
  | 'security_operator'
  | 'pentest_approver'
  | 'remediation_owner'
  | 'auditor'
  | 'viewer';

export interface CurrentUser {
  id: string;
  email: string;
  full_name: string | null;
  role: Role;
  organization_id: string;
  is_active: boolean;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}
