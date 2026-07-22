import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AuthProvider } from '../src/auth/AuthProvider';
import { PassiveInventoryPage } from '../src/pages/PassiveInventoryPage';
import type { ConnectorRun, InventoryConnector } from '../src/types/passive-inventory';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const connector: InventoryConnector = {
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

let inventoryConnectors: InventoryConnector[] = [connector];
let inventoryRuns: ConnectorRun[] = [];

beforeEach(() => {
  inventoryConnectors = [connector];
  inventoryRuns = [];
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
      if (url.endsWith('/api/v1/inventory/connectors')) return jsonResponse(inventoryConnectors);
      if (url.endsWith('/api/v1/inventory/runs')) return jsonResponse(inventoryRuns);
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

  fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'active_directory' } });
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Domain computers' } });
  fireEvent.change(screen.getByLabelText('Directory server'), {
    target: { value: 'dc01.example.test' },
  });
  fireEvent.change(screen.getByLabelText('Bind user'), {
    target: { value: 'vulna-reader@example.test' },
  });
  fireEvent.change(screen.getByLabelText('Base DN'), {
    target: { value: 'DC=example,DC=test' },
  });
  fireEvent.change(screen.getByLabelText('Bind password'), {
    target: { value: 'directory-password' },
  });
  fireEvent.change(screen.getByLabelText('Private directory server'), {
    target: { value: 'yes' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Save source' }));
  await waitFor(() => {
    const directoryCall = vi.mocked(fetch).mock.calls.find(([, init]) => {
      if (init?.method !== 'POST' || typeof init.body !== 'string') return false;
      return (
        (JSON.parse(init.body) as { connector_type?: string }).connector_type === 'active_directory'
      );
    });
    expect(directoryCall).toBeDefined();
    const payload = JSON.parse(String(directoryCall?.[1]?.body)) as Record<string, unknown>;
    expect(payload).toMatchObject({
      connector_type: 'active_directory',
      secret: 'directory-password',
      config: {
        server: 'dc01.example.test',
        bind_user: 'vulna-reader@example.test',
        base_dn: 'DC=example,DC=test',
        allow_private: true,
      },
    });
    expect(payload).not.toHaveProperty('base_url');
  });

  fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'entra' } });
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Entra devices' } });
  fireEvent.change(screen.getByLabelText('Microsoft Entra tenant ID'), {
    target: { value: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' },
  });
  fireEvent.change(screen.getByLabelText('Application client ID'), {
    target: { value: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' },
  });
  fireEvent.change(screen.getByLabelText('Microsoft cloud'), {
    target: { value: 'us_government' },
  });
  fireEvent.change(screen.getByLabelText('Application client secret'), {
    target: { value: 'entra-client-secret' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Save source' }));
  await waitFor(() => {
    const entraCall = vi.mocked(fetch).mock.calls.find(([, init]) => {
      if (init?.method !== 'POST' || typeof init.body !== 'string') return false;
      return (JSON.parse(init.body) as { connector_type?: string }).connector_type === 'entra';
    });
    expect(entraCall).toBeDefined();
    const payload = JSON.parse(String(entraCall?.[1]?.body)) as Record<string, unknown>;
    expect(payload).toMatchObject({
      connector_type: 'entra',
      secret: 'entra-client-secret',
      config: {
        tenant_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        client_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        cloud: 'us_government',
      },
    });
    expect(payload).not.toHaveProperty('base_url');
  });

  fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'unifi' } });
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'UniFi inventory' } });
  expect(screen.getByLabelText('Site Manager API endpoint')).toHaveValue(
    'https://api.ui.com/v1/devices',
  );
  fireEvent.change(screen.getByLabelText('UniFi host IDs (optional)'), {
    target: { value: 'host-01:region\nhost-02:region' },
  });
  fireEvent.change(screen.getByLabelText('UniFi Site Manager API key'), {
    target: { value: 'unifi-api-key' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Save source' }));
  await waitFor(() => {
    const unifiCall = vi.mocked(fetch).mock.calls.find(([, init]) => {
      if (init?.method !== 'POST' || typeof init.body !== 'string') return false;
      return (JSON.parse(init.body) as { connector_type?: string }).connector_type === 'unifi';
    });
    expect(unifiCall).toBeDefined();
    const payload = JSON.parse(String(unifiCall?.[1]?.body)) as Record<string, unknown>;
    expect(payload).toMatchObject({
      connector_type: 'unifi',
      secret: 'unifi-api-key',
      config: {
        host_ids: ['host-01:region', 'host-02:region'],
      },
    });
    expect(payload).not.toHaveProperty('base_url');
  });

  fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'vcenter' } });
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'vCenter inventory' } });
  fireEvent.change(screen.getByLabelText('vCenter server URL'), {
    target: { value: 'https://vcenter.internal.test' },
  });
  fireEvent.change(screen.getByLabelText('vCenter read-only username'), {
    target: { value: 'vulna-reader@vsphere.local' },
  });
  fireEvent.change(screen.getByLabelText('vCenter password'), {
    target: { value: 'vcenter-password' },
  });
  fireEvent.change(screen.getByLabelText('Private vCenter server'), {
    target: { value: 'yes' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Save source' }));
  await waitFor(() => {
    const vcenterCall = vi.mocked(fetch).mock.calls.find(([, init]) => {
      if (init?.method !== 'POST' || typeof init.body !== 'string') return false;
      return (JSON.parse(init.body) as { connector_type?: string }).connector_type === 'vcenter';
    });
    expect(vcenterCall).toBeDefined();
    const payload = JSON.parse(String(vcenterCall?.[1]?.body)) as Record<string, unknown>;
    expect(payload).toMatchObject({
      connector_type: 'vcenter',
      base_url: 'https://vcenter.internal.test',
      secret: 'vcenter-password',
      config: {
        username: 'vulna-reader@vsphere.local',
        allow_private: true,
        include_hosts: true,
        include_vms: true,
      },
    });
  });

  fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'proxmox' } });
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Proxmox inventory' } });
  fireEvent.change(screen.getByLabelText('Proxmox API origin'), {
    target: { value: 'https://proxmox.internal.test:8006' },
  });
  fireEvent.change(screen.getByLabelText('Proxmox API token ID'), {
    target: { value: 'vulna@pve!inventory' },
  });
  fireEvent.change(screen.getByLabelText('Proxmox token secret'), {
    target: { value: 'proxmox-token-secret' },
  });
  fireEvent.change(screen.getByLabelText('Private Proxmox server'), {
    target: { value: 'yes' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Save source' }));
  await waitFor(() => {
    const call = vi.mocked(fetch).mock.calls.find(([, init]) => {
      if (init?.method !== 'POST' || typeof init.body !== 'string') return false;
      return (JSON.parse(init.body) as { connector_type?: string }).connector_type === 'proxmox';
    });
    expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({
      connector_type: 'proxmox',
      base_url: 'https://proxmox.internal.test:8006',
      secret: 'proxmox-token-secret',
      config: {
        api_identity: 'vulna@pve!inventory',
        allow_private: true,
        include_nodes: true,
        include_guests: true,
        include_templates: false,
      },
    });
  });

  fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'xcp_ng' } });
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'XCP-ng inventory' } });
  fireEvent.change(screen.getByLabelText('Xen Orchestra origin'), {
    target: { value: 'https://xo.internal.test' },
  });
  fireEvent.change(screen.getByLabelText('Xen Orchestra authentication token'), {
    target: { value: 'xoa-authentication-token' },
  });
  fireEvent.change(screen.getByLabelText('Private Xen Orchestra server'), {
    target: { value: 'yes' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Save source' }));
  await waitFor(() => {
    const call = vi.mocked(fetch).mock.calls.find(([, init]) => {
      if (init?.method !== 'POST' || typeof init.body !== 'string') return false;
      return (JSON.parse(init.body) as { connector_type?: string }).connector_type === 'xcp_ng';
    });
    expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({
      connector_type: 'xcp_ng',
      base_url: 'https://xo.internal.test',
      secret: 'xoa-authentication-token',
      config: {
        allow_private: true,
        include_hosts: true,
        include_vms: true,
      },
    });
  });

  fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'aws' } });
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'AWS inventory' } });
  fireEvent.change(screen.getByLabelText('AWS regions'), {
    target: { value: 'us-east-1, us-west-2' },
  });
  fireEvent.change(screen.getByLabelText('Expected AWS account ID (optional)'), {
    target: { value: '123456789012' },
  });
  fireEvent.change(screen.getByLabelText('AWS access key ID'), {
    target: { value: 'EXAMPLEACCESSKEY01' },
  });
  fireEvent.change(screen.getByLabelText('AWS secret access key'), {
    target: { value: 'aws-secret-access-key' },
  });
  fireEvent.change(screen.getByLabelText('AWS session token (optional)'), {
    target: { value: 'aws-session-token' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Save source' }));
  await waitFor(() => {
    const call = vi.mocked(fetch).mock.calls.find(([, init]) => {
      if (init?.method !== 'POST' || typeof init.body !== 'string') return false;
      return (JSON.parse(init.body) as { connector_type?: string }).connector_type === 'aws';
    });
    const payload = JSON.parse(String(call?.[1]?.body)) as {
      secret: string;
      base_url?: string;
      config: Record<string, unknown>;
    };
    expect(payload).not.toHaveProperty('base_url');
    expect(payload.config).toEqual({
      partition: 'aws',
      regions: ['us-east-1', 'us-west-2'],
      expected_account_id: '123456789012',
      include_terminated: false,
    });
    expect(JSON.parse(payload.secret)).toEqual({
      access_key_id: 'EXAMPLEACCESSKEY01',
      secret_access_key: 'aws-secret-access-key',
      session_token: 'aws-session-token',
    });
  });

  fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'azure' } });
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Azure inventory' } });
  fireEvent.change(screen.getByLabelText('Azure tenant ID'), {
    target: { value: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' },
  });
  fireEvent.change(screen.getByLabelText('Azure application client ID'), {
    target: { value: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' },
  });
  fireEvent.change(screen.getByLabelText('Azure subscription IDs'), {
    target: { value: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' },
  });
  fireEvent.change(screen.getByLabelText('Azure cloud'), {
    target: { value: 'us_government' },
  });
  fireEvent.change(screen.getByLabelText('Azure client secret'), {
    target: { value: 'azure-client-secret' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Save source' }));
  await waitFor(() => {
    const call = vi.mocked(fetch).mock.calls.find(([, init]) => {
      if (init?.method !== 'POST' || typeof init.body !== 'string') return false;
      return (JSON.parse(init.body) as { connector_type?: string }).connector_type === 'azure';
    });
    expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({
      connector_type: 'azure',
      secret: 'azure-client-secret',
      config: {
        tenant_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        client_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        subscription_ids: ['cccccccc-cccc-4ccc-8ccc-cccccccccccc'],
        cloud: 'us_government',
        include_scale_set_instances: true,
      },
    });
  });

  fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'google_cloud' } });
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Google inventory' } });
  fireEvent.change(screen.getByLabelText('Google Cloud project IDs (optional)'), {
    target: { value: 'security-project-1, workload-project-2' },
  });
  const serviceAccount = JSON.stringify({
    type: 'service_account',
    project_id: 'security-project-1',
    private_key: 'one-way-private-key',
  });
  fireEvent.change(screen.getByLabelText('Google service-account JSON'), {
    target: {
      files: [
        {
          name: 'service-account.json',
          size: serviceAccount.length,
          text: async () => serviceAccount,
        },
      ],
    },
  });
  expect(await screen.findByText('Loaded service-account.json')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Save source' }));
  await waitFor(() => {
    const call = vi.mocked(fetch).mock.calls.find(([, init]) => {
      if (init?.method !== 'POST' || typeof init.body !== 'string') return false;
      return (
        (JSON.parse(init.body) as { connector_type?: string }).connector_type === 'google_cloud'
      );
    });
    const payload = JSON.parse(String(call?.[1]?.body)) as Record<string, unknown>;
    expect(payload).toMatchObject({
      connector_type: 'google_cloud',
      secret: serviceAccount,
      config: { project_ids: ['security-project-1', 'workload-project-2'] },
    });
    expect(payload).not.toHaveProperty('base_url');
  });

  fireEvent.click(screen.getByRole('tab', { name: /Reconciliation/ }));
  expect(await screen.findByText('75')).toBeInTheDocument();
  expect(screen.getByText('1 exact identifier match(es)')).toBeInTheDocument();
});

it('clears one-way credentials when the provider type changes', async () => {
  render(
    <AuthProvider>
      <PassiveInventoryPage />
    </AuthProvider>,
  );

  expect(await screen.findByText('42')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('tab', { name: /Sources/ }));
  fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'vcenter' } });
  fireEvent.change(screen.getByLabelText('vCenter password'), {
    target: { value: 'must-not-cross-provider-boundary' },
  });
  fireEvent.change(screen.getByLabelText('vCenter server URL'), {
    target: { value: 'https://vcenter.internal.test' },
  });

  fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'proxmox' } });
  expect(screen.getByLabelText('Proxmox token secret')).toHaveValue('');
  expect(screen.getByLabelText('Proxmox API origin')).toHaveValue('');
});

it('shows the connector site name and a visible failed run', async () => {
  inventoryConnectors = [
    {
      ...connector,
      enabled: true,
      successful_test_at: '2026-07-13T00:01:00Z',
    },
  ];
  inventoryRuns = [
    {
      id: 'run-1',
      organization_id: 'org-1',
      site_id: 'site-1',
      connector_id: 'connector-1',
      background_task_id: 'task-1',
      status: 'failed',
      started_at: '2026-07-13T00:02:00Z',
      finished_at: '2026-07-13T00:02:05Z',
      records_read: 0,
      observations_created: 0,
      error: 'PostgreSQL reconciliation failed safely.',
      has_cursor: false,
      created_at: '2026-07-13T00:02:00Z',
    },
  ];

  render(
    <AuthProvider>
      <PassiveInventoryPage />
    </AuthProvider>,
  );

  expect(await screen.findByText('42')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('tab', { name: /Sources/ }));
  expect((await screen.findAllByText('Main')).length).toBeGreaterThanOrEqual(2);
  expect(screen.getByText('Failed')).toBeInTheDocument();
  expect(screen.getByText('PostgreSQL reconciliation failed safely.')).toBeInTheDocument();
});
