import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AuthProvider } from '../src/auth/AuthProvider';
import { AuthenticatedInventoryPage } from '../src/pages/AuthenticatedInventoryPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const credential = {
  id: 'credential-1',
  organization_id: 'org-1',
  name: 'Linux inventory',
  description: null,
  protocol: 'ssh',
  auth_type: 'password',
  username: 'inventory',
  metadata: { host_key_fingerprint: 'SHA256:test', port: 22 },
  is_active: true,
  has_secret: true,
  current_version: 1,
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
            'credentials.read',
            'credentials.manage',
            'software.read',
            'software.manage',
            'scouts.manage',
          ],
        });
      }
      if (url.includes('/api/v1/credentials?') && init?.method !== 'POST') {
        return jsonResponse({ items: [credential], total: 1, limit: 200, offset: 0 });
      }
      if (url.endsWith('/api/v1/credentials') && init?.method === 'POST') {
        return jsonResponse(
          { ...credential, id: 'credential-2', name: 'New credential', current_version: 1 },
          201,
        );
      }
      if (url.includes('/api/v1/credentials/assignments')) {
        return jsonResponse({ items: [], total: 0, limit: 500, offset: 0 });
      }
      if (url.includes('/api/v1/credentials/usage')) {
        return jsonResponse({ items: [], total: 0, limit: 100, offset: 0 });
      }
      if (url.includes('/api/v1/software?')) {
        return jsonResponse({ items: [], total: 0, limit: 500, offset: 0 });
      }
      if (url.includes('/api/v1/assets?')) {
        return jsonResponse({ items: [], total: 0, limit: 500, offset: 0 });
      }
      if (url.endsWith('/api/v1/probes')) {
        return jsonResponse({
          items: [
            {
              id: 'probe-1',
              name: 'Scout one',
              status: 'enrolled',
              site_id: 'site-1',
              credentialed_scans_enabled: false,
              has_encryption_key: true,
            },
          ],
          total: 1,
          limit: 50,
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

it('shows only secret metadata and clears the one-way secret after creation', async () => {
  render(
    <AuthProvider>
      <AuthenticatedInventoryPage />
    </AuthProvider>,
  );

  expect(await screen.findByText('Linux inventory')).toBeInTheDocument();
  expect(screen.getByText('Stored · version 1')).toBeInTheDocument();
  expect(screen.queryByText('existing-secret')).not.toBeInTheDocument();

  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'New credential' } });
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'scanner' } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'one-way-secret' } });
  fireEvent.change(screen.getByLabelText('Host-key fingerprint'), {
    target: { value: 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Encrypt credential' }));

  await waitFor(() =>
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/credentials'),
      expect.objectContaining({
        method: 'POST',
        body: expect.stringContaining('one-way-secret'),
      }),
    ),
  );
  await waitFor(() => expect(screen.getByLabelText('Password')).toHaveValue(''));

  fireEvent.click(screen.getByRole('tab', { name: /Scout opt-in/ }));
  expect(await screen.findByText('Scout encryption key enrolled')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Enable' })).toBeEnabled();
});
