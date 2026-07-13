import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AuthProvider } from '../src/auth/AuthProvider';
import { ScimProvisioningPage } from '../src/pages/ScimProvisioningPage';

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
};

const tokenRow = {
  id: 'token-1',
  name: 'Primary directory',
  token_prefix: 'vscim_visible',
  has_secret: true,
  created_at: '2026-07-13T00:00:00Z',
  expires_at: '2027-07-13T00:00:00Z',
  revoked_at: null,
  last_used_at: null,
  last_used_ip: null,
};

const group = {
  id: 'group-1',
  external_id: 'directory-group-1',
  display_name: 'Security Operators',
  member_count: 2,
  role: null,
  grants_all_sites: false,
  site_ids: [],
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
      if (url.endsWith('/api/v1/scim/tokens') && method === 'GET') {
        return jsonResponse([tokenRow]);
      }
      if (url.endsWith('/api/v1/scim/tokens') && method === 'POST') {
        return jsonResponse({ ...tokenRow, id: 'token-2', token: 'vscim_one_time_secret' }, 201);
      }
      if (url.endsWith('/api/v1/scim/groups') && method === 'GET') {
        return jsonResponse([group]);
      }
      if (url.endsWith('/api/v1/scim/logs?limit=50')) {
        return jsonResponse({ items: [], total: 0, limit: 50, offset: 0 });
      }
      if (url.endsWith('/api/v1/sites')) {
        return jsonResponse({
          items: [
            {
              id: 'site-1',
              organization_id: 'org-1',
              name: 'HQ',
              code: 'hq',
              description: null,
              address: null,
              timezone: 'UTC',
              business_owner: null,
              technical_owner: null,
              tags: [],
              created_at: '2026-07-13T00:00:00Z',
              updated_at: '2026-07-13T00:00:00Z',
            },
          ],
          total: 1,
          limit: 50,
          offset: 0,
        });
      }
      if (url.endsWith('/api/v1/scim/groups/group-1/mapping/preview')) {
        return jsonResponse({
          group_id: 'group-1',
          affected_users: 2,
          role: 'security_operator',
          grants_all_sites: false,
          site_ids: ['site-1'],
          users: [],
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

it('shows one-time tokens and requires a mapping preview before apply', async () => {
  render(
    <AuthProvider>
      <ScimProvisioningPage />
    </AuthProvider>,
  );

  expect(await screen.findByText('Primary directory')).toBeInTheDocument();
  expect(screen.getByDisplayValue(/\/scim\/v2$/)).toBeInTheDocument();

  fireEvent.click(screen.getByRole('button', { name: 'Create token' }));
  expect(await screen.findByDisplayValue('vscim_one_time_secret')).toBeInTheDocument();

  fireEvent.click(screen.getByRole('button', { name: 'Configure' }));
  const apply = screen.getByRole('button', { name: 'Apply mapping' });
  expect(apply).toBeDisabled();
  fireEvent.change(screen.getByRole('combobox'), {
    target: { value: 'security_operator' },
  });
  fireEvent.click(screen.getByLabelText('HQ'));
  fireEvent.click(screen.getByRole('button', { name: 'Preview impact' }));
  expect(await screen.findByText(/Preview: 2 users/)).toBeInTheDocument();
  expect(apply).toBeEnabled();
  await waitFor(() =>
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/scim/groups/group-1/mapping/preview'),
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          role: 'security_operator',
          grants_all_sites: false,
          site_ids: ['site-1'],
        }),
      }),
    ),
  );
});
