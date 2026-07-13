import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AuthProvider } from '../src/auth/AuthProvider';
import { AppliancesPage } from '../src/pages/AppliancesPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('AppliancesPage', () => {
  beforeEach(() => {
    localStorage.setItem('vulna.token', 'token');
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? 'GET';
        if (url.endsWith('/api/v1/auth/me')) {
          return jsonResponse({
            id: 'u1',
            email: 'admin@example.com',
            full_name: 'Admin',
            role: 'administrator',
            organization_id: 'o1',
            is_active: true,
          });
        }
        if (url.endsWith('/api/v1/sites')) {
          return jsonResponse({
            items: [
              {
                id: 's1',
                organization_id: 'o1',
                name: 'HQ',
                code: 'HQ',
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
        if (url.endsWith('/api/v1/probes')) {
          return jsonResponse({
            items: [{ id: 'p1', name: 'Scout One', status: 'enrolled', site_id: 's1' }],
            total: 1,
            limit: 50,
            offset: 0,
          });
        }
        if (url.endsWith('/api/v1/probes/p1') && method === 'GET') {
          return jsonResponse({
            id: 'p1',
            site_id: 's1',
            name: 'Scout One',
            description: null,
            status: 'enrolled',
            online: true,
            certificate_fingerprint: '1234567890abcdef1234567890abcdef',
            agent_version: '1.0.0',
            operating_system: 'Linux',
            architecture: 'amd64',
            hostname: 'scout-one',
            primary_ip: '10.0.0.2',
            pentest_enabled: false,
            last_seen_at: '2026-07-12T00:00:00Z',
            enrolled_at: '2026-07-12T00:00:00Z',
            approved_at: '2026-07-12T00:00:00Z',
            created_at: '2026-07-12T00:00:00Z',
          });
        }
        if (url.endsWith('/api/v1/probes/p1/revoke') && method === 'POST') {
          return jsonResponse({ detail: 'Certificate revocation failed' }, 500);
        }
        return jsonResponse({ detail: 'not found' }, 404);
      }),
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('keeps the appliance drawer open and exposes a failed revocation', async () => {
    render(
      <AuthProvider>
        <AppliancesPage />
      </AuthProvider>,
    );

    fireEvent.click(await screen.findByText('Scout One'));
    fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Revoke appliance' }));

    expect(await screen.findByText('Certificate revocation failed')).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.queryByRole('button', { name: 'Revoke appliance' })).not.toBeInTheDocument(),
    );
    expect(screen.getByRole('button', { name: 'Revoke' })).toBeInTheDocument();
  });
});
