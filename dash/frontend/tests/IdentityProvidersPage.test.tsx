import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AuthProvider } from '../src/auth/AuthProvider';
import { IdentityProvidersPage } from '../src/pages/IdentityProvidersPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const admin = {
  id: 'user-1',
  email: 'admin@example.com',
  full_name: 'Admin',
  role: 'administrator',
  organization_id: 'org-1',
  is_active: true,
  account_status: 'active',
  authentication_source: 'local',
  site_access_mode: 'all',
  site_ids: [],
  mfa_status: 'enrolled',
  mfa_grace_expires_at: null,
  is_break_glass: false,
  last_login_at: null,
  invited_at: null,
  activated_at: '2026-07-13T00:00:00Z',
  suspended_at: null,
  deactivated_at: null,
  password_changed_at: '2026-07-13T00:00:00Z',
  created_at: '2026-07-13T00:00:00Z',
  updated_at: '2026-07-13T00:00:00Z',
};

const provider = {
  id: 'provider-1',
  organization_id: 'org-1',
  name: 'Company OIDC',
  slug: 'company-oidc',
  protocol: 'oidc',
  enabled: false,
  jit_provisioning: true,
  default_role: 'viewer',
  preset: 'generic',
  allow_private_network: false,
  issuer: 'https://issuer.example/',
  discovery_url: null,
  client_id: 'vulna',
  scopes: ['openid', 'email'],
  idp_entity_id: null,
  idp_sso_url: null,
  idp_slo_url: null,
  want_assertions_encrypted: false,
  has_client_secret: true,
  has_idp_certificate: false,
  has_next_idp_certificate: false,
  has_sp_certificate: false,
  validated_at: null,
  last_test_succeeded_at: null,
  created_at: '2026-07-13T00:00:00Z',
  updated_at: '2026-07-13T00:00:00Z',
};

beforeEach(() => {
  localStorage.setItem('vulna.token', 'token');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/api/v1/auth/me')) return jsonResponse(admin);
      if (url.endsWith('/api/v1/identity/providers') && (init?.method ?? 'GET') === 'GET') {
        return jsonResponse([provider]);
      }
      if (url.endsWith('/api/v1/identity/policy') && (init?.method ?? 'GET') === 'GET') {
        return jsonResponse({
          mode: 'disabled',
          identity_provider_id: null,
          break_glass_user_ids: [],
          enforcement_ready: false,
          readiness_reasons: [
            'Select an identity provider',
            'Configure an active local administrator with strong MFA as break-glass',
          ],
        });
      }
      if (url.endsWith('/api/v1/users')) {
        return jsonResponse({ items: [admin], total: 1, limit: 50, offset: 0 });
      }
      if (url.endsWith('/validate') && init?.method === 'POST') {
        return jsonResponse({ ...provider, validated_at: '2026-07-13T01:00:00Z' });
      }
      if (url.includes('/api/v1/identity/break-glass/') && init?.method === 'PUT') {
        return jsonResponse({
          mode: 'disabled',
          identity_provider_id: null,
          break_glass_user_ids: ['user-1'],
          enforcement_ready: false,
          readiness_reasons: ['Select an identity provider'],
        });
      }
      return jsonResponse({ detail: 'not found' }, 404);
    }),
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

it('shows test-before-enable readiness and protects a strong-MFA administrator', async () => {
  render(
    <AuthProvider>
      <IdentityProvidersPage />
    </AuthProvider>,
  );

  expect(await screen.findByRole('heading', { name: 'Company OIDC' })).toBeInTheDocument();
  expect(screen.getByText('Client secret stored')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Enable' })).toBeDisabled();
  expect(screen.getByText('Enforcement blocked')).toBeInTheDocument();

  fireEvent.click(screen.getByRole('button', { name: 'Validate discovery' }));
  await waitFor(() =>
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/identity/providers/provider-1/validate'),
      expect.objectContaining({ method: 'POST' }),
    ),
  );

  fireEvent.click(screen.getByRole('button', { name: 'Protect' }));
  await waitFor(() =>
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/identity/break-glass/user-1'),
      expect.objectContaining({
        method: 'PUT',
        body: JSON.stringify({ enabled: true }),
      }),
    ),
  );
  expect(await screen.findByText('Protected')).toBeInTheDocument();
});
