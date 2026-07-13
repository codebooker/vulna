import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AuthProvider } from '../src/auth/AuthProvider';
import { AuthorizationPage } from '../src/pages/AuthorizationPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
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
  permissions: [
    'roles.manage',
    'users.read',
    'sites.read',
    'tokens.self',
    'service_accounts.manage',
  ],
};

const role = {
  id: 'role-1',
  key: 'administrator',
  name: 'Administrator',
  description: 'Built-in compatibility role',
  is_system: true,
  compatibility_role: 'administrator',
  permission_keys: ['roles.manage', 'sites.read'],
  created_at: '2026-07-13T00:00:00Z',
  updated_at: '2026-07-13T00:00:00Z',
};

const service = {
  id: 'service-1',
  organization_id: 'org-1',
  name: 'Inventory robot',
  description: 'Read-only inventory',
  status: 'active',
  primary_role: 'viewer',
  last_used_at: null,
  created_at: '2026-07-13T00:00:00Z',
  updated_at: '2026-07-13T00:00:00Z',
};

beforeEach(() => {
  localStorage.setItem('vulna.token', 'access-token');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? 'GET';
      if (url.endsWith('/api/v1/auth/me')) return jsonResponse(admin);
      if (url.endsWith('/api/v1/permissions')) {
        return jsonResponse([
          {
            key: 'sites.read',
            label: 'View sites',
            description: 'View assigned sites.',
            scopes: ['organization', 'site'],
            high_risk: false,
          },
        ]);
      }
      if (url.endsWith('/api/v1/roles') && method === 'GET') return jsonResponse([role]);
      if (url.endsWith('/api/v1/roles') && method === 'POST') {
        return jsonResponse({ ...role, id: 'role-2', is_system: false, name: 'Site Reader' }, 201);
      }
      if (url.endsWith('/api/v1/grants')) return jsonResponse([]);
      if (url.endsWith('/api/v1/service-accounts') && method === 'GET') {
        return jsonResponse([service]);
      }
      if (url.endsWith('/api/v1/tokens') && method === 'GET') return jsonResponse([]);
      if (url.endsWith('/api/v1/tokens') && method === 'POST') {
        return jsonResponse(
          {
            id: 'token-1',
            principal_type: 'user',
            principal_id: 'user-1',
            name: 'Automation token',
            token_prefix: 'vapi_visible',
            has_secret: true,
            token: 'vapi_one_time_secret',
            expires_at: '2026-10-13T00:00:00Z',
            revoked_at: null,
            ip_restrictions: [],
            last_used_at: null,
            last_used_ip: null,
            created_at: '2026-07-13T00:00:00Z',
          },
          201,
        );
      }
      if (url.endsWith('/api/v1/service-accounts/service-1/tokens')) return jsonResponse([]);
      if (url.endsWith('/api/v1/users')) {
        return jsonResponse({ items: [admin], total: 1, limit: 50, offset: 0 });
      }
      if (url.endsWith('/api/v1/sites')) {
        return jsonResponse({ items: [], total: 0, limit: 50, offset: 0 });
      }
      return jsonResponse({ detail: 'not found' }, 404);
    }),
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

it('renders code-defined roles and displays API token values only at creation', async () => {
  render(
    <AuthProvider>
      <AuthorizationPage />
    </AuthProvider>,
  );

  expect((await screen.findAllByText('Administrator')).length).toBeGreaterThan(0);
  expect(screen.getAllByText('Inventory robot').length).toBeGreaterThan(0);
  expect(screen.getByRole('option', { name: /View sites/ })).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText('Role name'), { target: { value: 'Site Reader' } });
  const permissionList = screen.getByRole('listbox') as HTMLSelectElement;
  permissionList.options[0].selected = true;
  fireEvent.change(permissionList);
  fireEvent.click(screen.getByRole('button', { name: 'Create role' }));
  await waitFor(() =>
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/roles'),
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          key: 'site_reader',
          name: 'Site Reader',
          description: '',
          permission_keys: ['sites.read'],
        }),
      }),
    ),
  );

  fireEvent.click(screen.getByRole('button', { name: 'Issue token' }));
  expect(await screen.findByDisplayValue('vapi_one_time_secret')).toBeInTheDocument();
  expect(screen.getByText(/Only its SHA-256 hash is stored/)).toBeInTheDocument();
});
