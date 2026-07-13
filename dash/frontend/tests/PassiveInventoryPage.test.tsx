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
  has_source_data: false,
  source_filename: null,
  source_sha256: null,
  source_size_bytes: null,
  source_uploaded_at: null,
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
            'connectors.run',
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
        return jsonResponse(
          {
            ...connector,
            id: 'connector-2',
            name: 'New source',
            connector_type: 'csv',
            base_url: null,
            has_secret: false,
          },
          201,
        );
      }
      if (url.endsWith('/api/v1/inventory/connectors/connector-2/csv') && init?.method === 'PUT') {
        return jsonResponse({
          ...connector,
          id: 'connector-2',
          name: 'New source',
          connector_type: 'csv',
          base_url: null,
          has_secret: false,
          has_source_data: true,
          source_filename: 'inventory.csv',
          source_sha256: 'csv-sha256',
          source_size_bytes: 32,
          source_uploaded_at: '2026-07-13T00:01:00Z',
        });
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
  const csv = new File(['hostname,ip\nserver-1,192.0.2.10\n'], 'inventory.csv', {
    type: 'text/csv',
  });
  fireEvent.change(screen.getByLabelText('CSV file (5 MiB maximum)'), {
    target: { files: [csv] },
  });
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
  await waitFor(() =>
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/inventory/connectors/connector-2/csv'),
      expect.objectContaining({
        method: 'PUT',
        body: csv,
        headers: expect.objectContaining({
          'Content-Type': 'text/csv',
          'X-File-Name': 'inventory.csv',
        }),
      }),
    ),
  );

  fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'dhcp' } });
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Kea leases' } });
  fireEvent.change(screen.getByLabelText('HTTPS URL (when required)'), {
    target: { value: 'https://kea.internal.test:8000/' },
  });
  fireEvent.change(screen.getByLabelText('Kea username'), {
    target: { value: 'vulna-reader' },
  });
  fireEvent.change(screen.getByLabelText('Kea password'), {
    target: { value: 'kea-password' },
  });
  fireEvent.change(screen.getByLabelText('Private network URL'), {
    target: { value: 'yes' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Save source' }));
  await waitFor(() => {
    const dhcpCall = vi.mocked(fetch).mock.calls.find(([, init]) => {
      if (init?.method !== 'POST' || typeof init.body !== 'string') return false;
      return (JSON.parse(init.body) as { connector_type?: string }).connector_type === 'dhcp';
    });
    expect(dhcpCall).toBeDefined();
    const payload = JSON.parse(String(dhcpCall?.[1]?.body)) as Record<string, unknown>;
    expect(payload).toMatchObject({
      connector_type: 'dhcp',
      base_url: 'https://kea.internal.test:8000/',
      secret: 'kea-password',
      config: {
        username: 'vulna-reader',
        allow_private: true,
        legacy_control_agent: false,
      },
    });
  });

  fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'dns' } });
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'DNS inventory' } });
  fireEvent.change(screen.getByLabelText('Authoritative DNS server'), {
    target: { value: 'dns.internal.test' },
  });
  fireEvent.change(screen.getByLabelText('Authoritative zones'), {
    target: { value: 'example.test, 2.0.192.in-addr.arpa' },
  });
  fireEvent.change(screen.getByLabelText('TSIG key name'), {
    target: { value: 'vulna-transfer.example.test.' },
  });
  fireEvent.change(screen.getByLabelText('TSIG secret (base64)'), {
    target: { value: 'c3VwZXItc2VjcmV0' },
  });
  fireEvent.change(screen.getByLabelText('Private network server'), {
    target: { value: 'yes' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Save source' }));
  await waitFor(() => {
    const dnsCall = vi.mocked(fetch).mock.calls.find(([, init]) => {
      if (init?.method !== 'POST' || typeof init.body !== 'string') return false;
      return (JSON.parse(init.body) as { connector_type?: string }).connector_type === 'dns';
    });
    expect(dnsCall).toBeDefined();
    const payload = JSON.parse(String(dnsCall?.[1]?.body)) as Record<string, unknown>;
    expect(payload).toMatchObject({
      connector_type: 'dns',
      secret: 'c3VwZXItc2VjcmV0',
      config: {
        server: 'dns.internal.test',
        zones: ['example.test', '2.0.192.in-addr.arpa'],
        allow_private: true,
        allow_unsigned: false,
        tsig_name: 'vulna-transfer.example.test.',
        tsig_algorithm: 'hmac-sha256',
      },
    });
    expect(payload).not.toHaveProperty('base_url');
  });

  fireEvent.click(screen.getByRole('tab', { name: /Reconciliation/ }));
  expect(await screen.findByText('75')).toBeInTheDocument();
  expect(screen.getByText('1 exact identifier match(es)')).toBeInTheDocument();
});
