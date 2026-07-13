import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AuthProvider } from '../src/auth/AuthProvider';
import { SessionManagementPage } from '../src/pages/SessionManagementPage';

const admin = {
  id: 'user-1',
  email: 'admin@example.com',
  full_name: 'Admin',
  role: 'administrator',
  organization_id: 'org-1',
  is_active: true,
};

const session = {
  id: 'session-2',
  user_id: 'user-1',
  created_at: '2026-07-13T00:00:00Z',
  last_seen_at: '2026-07-13T01:00:00Z',
  authenticated_at: '2026-07-13T00:00:00Z',
  idle_expires_at: '2026-07-13T13:00:00Z',
  absolute_expires_at: '2026-08-12T00:00:00Z',
  revoked_at: null,
  revocation_reason: null,
  device_name: 'Firefox on workstation',
  source_ip: '192.0.2.10',
  user_agent: 'Firefox Test',
  trusted_until: '2026-08-12T00:00:00Z',
  current: false,
  active: true,
  privileged_until: '2026-07-13T00:15:00Z',
  mfa_pending: false,
  mfa_authenticated_at: '2026-07-13T00:00:00Z',
  authentication_methods: ['password', 'totp'],
};

const policy = {
  idle_timeout_hours: 12,
  absolute_lifetime_days: 30,
  privileged_window_minutes: 15,
  max_concurrent_sessions: 10,
  trusted_device_days: 30,
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

beforeEach(() => {
  localStorage.setItem('vulna.token', 'token');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/api/v1/auth/me')) return jsonResponse(admin);
      if (url.endsWith('/api/v1/auth/sessions/session-2') && init?.method === 'DELETE') {
        return jsonResponse(null, 204);
      }
      if (url.endsWith('/api/v1/auth/sessions')) return jsonResponse([session]);
      if (url.endsWith('/session-policy') && init?.method === 'PATCH') {
        return jsonResponse({ ...policy, idle_timeout_hours: 8 });
      }
      if (url.endsWith('/session-policy')) return jsonResponse(policy);
      return jsonResponse({ detail: 'not found' }, 404);
    }),
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

it('lists and revokes sessions and lets administrators edit the organization policy', async () => {
  render(
    <AuthProvider>
      <SessionManagementPage />
    </AuthProvider>,
  );

  await screen.findByLabelText('Idle timeout (hours)');
  expect(screen.getByText('Firefox on workstation')).toBeInTheDocument();
  expect(screen.getByText('192.0.2.10', { exact: false })).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));
  await waitFor(() =>
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/auth/sessions/session-2'),
      expect.objectContaining({ method: 'DELETE', credentials: 'include' }),
    ),
  );

  fireEvent.change(screen.getByLabelText('Idle timeout (hours)'), { target: { value: '8' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save session policy' }));
  await waitFor(() =>
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/session-policy'),
      expect.objectContaining({
        method: 'PATCH',
        body: expect.stringContaining('"idle_timeout_hours":8'),
      }),
    ),
  );
});
