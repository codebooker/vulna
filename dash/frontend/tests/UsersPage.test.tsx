import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AuthProvider } from '../src/auth/AuthProvider';
import { UsersPage } from '../src/pages/UsersPage';

const admin = {
  id: 'u1',
  email: 'admin@example.com',
  full_name: 'Admin',
  role: 'administrator',
  organization_id: 'o1',
  is_active: true,
  account_status: 'active',
  authentication_source: 'local',
  site_access_mode: 'all',
  site_ids: [],
  mfa_status: 'not_enrolled',
  mfa_grace_expires_at: null,
  last_login_at: null,
  invited_at: null,
  activated_at: '2026-07-12T00:00:00Z',
  suspended_at: null,
  deactivated_at: null,
  password_changed_at: '2026-07-12T00:00:00Z',
  created_at: '2026-07-12T00:00:00Z',
  updated_at: '2026-07-12T00:00:00Z',
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

beforeEach(() => {
  localStorage.setItem('vulna.token', 'tok123');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/api/v1/auth/me')) return jsonResponse(admin);
      if (url.endsWith('/api/v1/sites')) {
        return jsonResponse({
          items: [
            {
              id: 'site-1',
              organization_id: 'o1',
              name: 'Head Office',
              code: 'HQ',
              description: null,
              address: null,
              timezone: 'UTC',
              business_owner: null,
              technical_owner: null,
              tags: [],
              created_at: '2026-07-12T00:00:00Z',
              updated_at: '2026-07-12T00:00:00Z',
            },
          ],
          total: 1,
          limit: 50,
          offset: 0,
        });
      }
      if (url.endsWith('/api/v1/users') && init?.method === 'POST') {
        return jsonResponse(
          {
            ...admin,
            id: 'u2',
            email: 'analyst@example.com',
            full_name: 'Analyst',
            role: 'viewer',
            is_active: false,
            account_status: 'invited',
            site_access_mode: 'assigned',
            site_ids: ['site-1'],
            invited_at: '2026-07-13T00:00:00Z',
            activated_at: null,
            password_changed_at: null,
            invitation_url: 'https://vulna.test/#accept-invitation?token=shown-once',
            invitation_expires_at: '2026-07-16T00:00:00Z',
          },
          201,
        );
      }
      if (url.endsWith('/lifecycle') || url.endsWith('/login-history')) {
        return jsonResponse({ items: [], total: 0, limit: 50, offset: 0 });
      }
      if (url.endsWith('/sessions')) return jsonResponse([]);
      return jsonResponse({ items: [admin], total: 1, limit: 50, offset: 0 });
    }),
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

it('supports invitation creation and shows the one-time copyable link', async () => {
  render(
    <AuthProvider>
      <UsersPage />
    </AuthProvider>,
  );

  expect(await screen.findByText('admin@example.com')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Invite user' }));
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'analyst@example.com' } });
  fireEvent.change(screen.getByLabelText('Full name'), { target: { value: 'Analyst' } });
  fireEvent.click(screen.getByLabelText('Head Office'));
  fireEvent.click(screen.getByRole('button', { name: 'Create invitation' }));

  expect(await screen.findByDisplayValue(/shown-once/)).toBeInTheDocument();
  expect(screen.getByText(/stored only as a purpose-bound hash/i)).toBeInTheDocument();
  const fetchMock = vi.mocked(fetch);
  await waitFor(() =>
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/users'),
      expect.objectContaining({ method: 'POST' }),
    ),
  );
});

it('opens a user detail with lifecycle, login, access, and MFA information', async () => {
  render(
    <AuthProvider>
      <UsersPage />
    </AuthProvider>,
  );
  fireEvent.click(await screen.findByText('admin@example.com'));
  expect(await screen.findByText('Lifecycle actions')).toBeInTheDocument();
  expect(screen.getByText('Login history')).toBeInTheDocument();
  expect(screen.getByText('Sessions')).toBeInTheDocument();
  expect(screen.getByText('Lifecycle history')).toBeInTheDocument();
  expect(screen.getAllByText(/MFA Not Enrolled/).length).toBeGreaterThan(0);
  expect(screen.getByLabelText('Role')).toBeDisabled();
});
