import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AuthProvider } from '../src/auth/AuthProvider';
import { AssetsPage } from '../src/pages/AssetsPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const tag = {
  id: 'tag-1',
  organization_id: 'org-1',
  name: 'Payment Tier',
  description: null,
  color: '#3366ff',
  created_at: '2026-07-13T00:00:00Z',
  updated_at: '2026-07-13T00:00:00Z',
};

const group = {
  id: 'group-1',
  organization_id: 'org-1',
  site_id: 'site-1',
  name: 'Production payments',
  description: null,
  group_type: 'dynamic',
  rule_json: { field: 'environment', operator: 'eq', value: 'production' },
  priority: 100,
  owner_user_id: 'admin-1',
  enabled: true,
  last_evaluated_at: '2026-07-13T00:00:00Z',
  member_count: 1,
  created_at: '2026-07-13T00:00:00Z',
  updated_at: '2026-07-13T00:00:00Z',
};

const asset = {
  id: 'asset-1',
  organization_id: 'org-1',
  site_id: 'site-1',
  canonical_name: 'payments-api',
  asset_type: 'server',
  status: 'active',
  operating_system: 'Linux',
  manufacturer: 'Example',
  identity_confidence: 90,
  department: 'Finance',
  business_function: 'Payments',
  environment: 'production',
  criticality: 'mission_critical',
  data_classification: 'restricted',
  internet_exposed: true,
  owner_user_id: null,
  context_json: { cost_center: 'FIN-42' },
  tags: [tag],
  group_ids: ['group-1'],
  first_seen_at: '2026-07-01T00:00:00Z',
  last_seen_at: '2026-07-13T00:00:00Z',
  last_assessed_at: '2026-07-13T00:00:00Z',
  created_at: '2026-07-01T00:00:00Z',
  updated_at: '2026-07-13T00:00:00Z',
};

beforeEach(() => {
  localStorage.setItem('vulna.token', 'access-token');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/api/v1/auth/me')) {
        return jsonResponse({
          id: 'admin-1',
          email: 'admin@example.com',
          full_name: 'Administrator',
          role: 'administrator',
          organization_id: 'org-1',
          is_active: true,
          permissions: ['assets.read', 'assets.manage', 'users.read'],
        });
      }
      if (url.includes('/api/v1/assets?')) {
        return jsonResponse({ items: [asset], total: 1, limit: 200, offset: 0 });
      }
      if (url.endsWith('/api/v1/sites')) {
        return jsonResponse({
          items: [
            {
              id: 'site-1',
              organization_id: 'org-1',
              name: 'Main',
              code: 'MAIN',
              description: null,
              address: null,
              timezone: 'UTC',
              business_owner: null,
              technical_owner: null,
              owner_user_id: null,
              tags: [],
              created_at: '2026-07-01T00:00:00Z',
              updated_at: '2026-07-01T00:00:00Z',
            },
          ],
          total: 1,
          limit: 50,
          offset: 0,
        });
      }
      if (url.includes('/api/v1/findings')) {
        return jsonResponse({ items: [], total: 0, limit: 500, offset: 0 });
      }
      if (url.includes('/api/v1/asset-tags')) {
        return jsonResponse({ items: [tag], total: 1, limit: 500, offset: 0 });
      }
      if (url.includes('/api/v1/asset-groups')) {
        return jsonResponse({ items: [group], total: 1, limit: 500, offset: 0 });
      }
      if (url.endsWith('/api/v1/department-owners')) {
        return jsonResponse([]);
      }
      if (url.endsWith('/api/v1/users')) {
        return jsonResponse({
          items: [
            {
              id: 'admin-1',
              email: 'admin@example.com',
              full_name: 'Administrator',
              role: 'administrator',
              organization_id: 'org-1',
              is_active: true,
            },
          ],
          total: 1,
          limit: 50,
          offset: 0,
        });
      }
      if (url.endsWith('/api/v1/assets/asset-1/ownership')) {
        return jsonResponse({
          asset_id: 'asset-1',
          finding_id: null,
          owner_user_id: 'admin-1',
          source: 'group',
          source_id: 'group-1',
          explanation: { reason: 'Highest-priority matching asset group' },
        });
      }
      if (url.includes('/api/v1/assets/asset-1/ownership-history')) {
        return jsonResponse({
          items: [
            {
              id: 'history-1',
              asset_id: 'asset-1',
              finding_id: null,
              owner_user_id: 'admin-1',
              source: 'group',
              source_id: 'group-1',
              explanation_json: { reason: 'Highest-priority matching asset group' },
              created_at: '2026-07-13T00:00:00Z',
            },
          ],
          total: 1,
          limit: 20,
          offset: 0,
        });
      }
      if (url.endsWith('/api/v1/assets/bulk') && init?.method === 'POST') {
        return jsonResponse({
          updated_assets: 1,
          tags_added: 0,
          tags_removed: 0,
          memberships_added: 0,
          memberships_removed: 0,
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

it('shows structured context and saves an audited bulk-compatible context edit', async () => {
  render(
    <AuthProvider>
      <AssetsPage />
    </AuthProvider>,
  );

  await screen.findByRole('button', { name: 'New tag' });
  expect(await screen.findByText('payments-api')).toBeInTheDocument();
  expect(screen.getAllByText('Mission critical').length).toBeGreaterThan(0);
  expect(screen.getAllByText('Payment Tier').length).toBeGreaterThan(0);

  fireEvent.click(screen.getByRole('button', { name: 'Ownership rules' }));
  expect(screen.getByText('No department fallback owners.')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Close' }));

  fireEvent.click(screen.getByText('payments-api'));
  expect((await screen.findAllByText('Production payments')).length).toBeGreaterThan(0);
  expect(screen.getByText('(Group)')).toBeInTheDocument();
  expect(await screen.findByText('Administrator · Group')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Edit context' }));
  const department = screen.getByDisplayValue('Finance');
  fireEvent.change(department, { target: { value: 'Risk' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save context' }));

  await waitFor(() =>
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/assets/bulk'),
      expect.objectContaining({
        method: 'POST',
        body: expect.stringContaining('"department":"Risk"'),
      }),
    ),
  );
});
