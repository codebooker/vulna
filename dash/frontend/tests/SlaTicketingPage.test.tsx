import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AuthProvider } from '../src/auth/AuthProvider';
import { SlaTicketingPage } from '../src/pages/SlaTicketingPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const policy = {
  id: 'policy-1',
  organization_id: 'org-1',
  name: 'Known exploited first',
  description: null,
  priority: 10,
  enabled: true,
  match_json: { known_exploited: true },
  due_days_json: { critical: 2, high: 14, medium: 30, low: 90, info: 180 },
  pause_on_risk_acceptance: false,
  created_by_user_id: 'admin-1',
  created_at: '2026-07-13T00:00:00Z',
  updated_at: '2026-07-13T00:00:00Z',
};

const connector = {
  id: 'connector-1',
  organization_id: 'org-1',
  name: 'Engineering',
  connector_type: 'github',
  base_url: 'https://github.example.test/api/v3',
  project_key: 'security/issues',
  config_json: {},
  has_secret: true,
  enabled: false,
  close_after_verification: true,
  timeout_seconds: 15,
  successful_test_at: null,
  last_test_error: null,
  created_by_user_id: 'admin-1',
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
          role: 'administrator',
          organization_id: 'org-1',
          is_active: true,
          permissions: [
            'sla.read',
            'sla.manage',
            'ticketing.read',
            'ticketing.manage',
            'ticketing.sync',
          ],
        });
      }
      if (url.endsWith('/api/v1/sla/policies')) return jsonResponse([policy]);
      if (url.endsWith('/api/v1/sla/metrics')) {
        return jsonResponse({
          total_with_sla: 12,
          open: 8,
          overdue: 2,
          due_within_7_days: 3,
          completed: 4,
          completed_on_time: 3,
          on_time_percentage: 75,
          by_severity: { critical: 1 },
          generated_at: '2026-07-13T00:00:00Z',
        });
      }
      if (url.endsWith('/api/v1/ticketing/connectors') && init?.method === 'POST') {
        return jsonResponse({ ...connector, id: 'connector-2', name: 'New connector' }, 201);
      }
      if (url.endsWith('/api/v1/ticketing/connectors')) return jsonResponse([connector]);
      if (url.endsWith('/api/v1/ticketing/syncs')) return jsonResponse([]);
      return jsonResponse({ detail: 'not found' }, 404);
    }),
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

it('shows SLA metrics and never retains a submitted connector secret', async () => {
  render(
    <AuthProvider>
      <SlaTicketingPage />
    </AuthProvider>,
  );

  expect(await screen.findByText('Known exploited first')).toBeInTheDocument();
  expect(screen.getByText('75%')).toBeInTheDocument();
  expect(screen.getByText('2 days')).toBeInTheDocument();

  fireEvent.click(screen.getByRole('tab', { name: /Connectors/ }));
  expect(await screen.findByText('Engineering')).toBeInTheDocument();
  expect(screen.getByText('Required')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Enable' })).toBeDisabled();

  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'New connector' } });
  fireEvent.change(screen.getByLabelText('HTTPS API URL'), {
    target: { value: 'https://tickets.example.test/api' },
  });
  fireEvent.change(screen.getByLabelText('Project / queue'), {
    target: { value: 'security/project' },
  });
  fireEvent.change(screen.getByLabelText('Token / secret'), {
    target: { value: 'one-way-ticket-secret' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Add' }));

  await waitFor(() =>
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/ticketing/connectors'),
      expect.objectContaining({
        method: 'POST',
        body: expect.stringContaining('one-way-ticket-secret'),
      }),
    ),
  );
  await waitFor(() => expect(screen.getByLabelText('Token / secret')).toHaveValue(''));
  expect(screen.queryByText('one-way-ticket-secret')).not.toBeInTheDocument();
});
