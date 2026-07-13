import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AuthProvider } from '../src/auth/AuthProvider';
import { PassiveInventoryPage } from '../src/pages/PassiveInventoryPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const connector = {
  id: 'connector-1',
  organization_id: 'org-1',
  site_id: 'site-1',
  name: 'Cloud inventory',
  connector_type: 'aws',
  base_url: 'https://inventory.example.test',
  config_json: { region: 'us-east-1' },
  has_secret: true,
  enabled: false,
  interval_minutes: 60,
  next_run_at: null,
  successful_test_at: null,
  last_test_error: null,
  last_run_at: null,
  created_at: '2026-07-13T00:00:00Z',
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
          full_name: 'Admin',
          role: 'administrator',
          organization_id: 'org-1',
          is_active: true,
          permissions: [
            'analytics.read',
            'connectors.read',
            'connectors.manage',
            'reconciliation.read',
            'reconciliation.manage',
            'report_templates.read',
            'report_templates.manage',
          ],
        });
      }
      if (url.endsWith('/api/v1/analytics/dashboard')) {
        return jsonResponse({
          generated_at: '2026-07-13T00:00:00Z',
          findings: { total: 12, open: 8, closed: 4, breached: 1, by_status: {}, by_severity: {} },
          inventory: { total: 42, by_state: { assessed: 40, stale: 2 }, pending_reconciliation: 1 },
          connector_runs: {},
          cache: 'miss',
        });
      }
      if (url.endsWith('/api/v1/inventory/connectors') && init?.method === 'POST') {
        return jsonResponse({ ...connector, id: 'connector-2', name: 'New source' }, 201);
      }
      if (url.endsWith('/api/v1/inventory/connectors')) return jsonResponse([connector]);
      if (url.endsWith('/api/v1/inventory/reconciliation')) {
        return jsonResponse([
          {
            id: 'candidate-1',
            observation_id: 'observation-1',
            candidate_asset_id: 'asset-1',
            site_id: 'site-1',
            score: 75,
            reasons_json: [{ identifier_type: 'hostname' }],
            conflicts_json: [],
            status: 'pending',
            decided_at: null,
          },
        ]);
      }
      if (url.endsWith('/api/v1/report-templates')) return jsonResponse([]);
      if (url.endsWith('/api/v1/sites')) {
        return jsonResponse({
          items: [{ id: 'site-1', name: 'Main', code: 'MAIN' }],
          total: 1,
          limit: 100,
          offset: 0,
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

it('shows scoped analytics and keeps connector secrets one-way', async () => {
  render(
    <AuthProvider>
      <PassiveInventoryPage />
    </AuthProvider>,
  );

  expect(await screen.findByText('42')).toBeInTheDocument();
  expect(screen.getByText('Needs reconciliation')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('tab', { name: /Sources/ }));
  expect(await screen.findByText('Cloud inventory')).toBeInTheDocument();
  expect(screen.getByText('Test required')).toBeInTheDocument();
  expect(screen.queryByText('inventory-secret')).not.toBeInTheDocument();

  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'New source' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save source' }));
  await waitFor(() =>
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/inventory/connectors'),
      expect.objectContaining({
        method: 'POST',
        body: expect.stringContaining('New source'),
      }),
    ),
  );

  fireEvent.click(screen.getByRole('tab', { name: /Reconciliation/ }));
  expect(await screen.findByText('75')).toBeInTheDocument();
  expect(screen.getByText('1 exact identifier match(es)')).toBeInTheDocument();
});
