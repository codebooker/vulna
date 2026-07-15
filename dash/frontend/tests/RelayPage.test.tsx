import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AuthProvider } from '../src/auth/AuthProvider';
import { RelayPage } from '../src/pages/RelayPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('RelayPage', () => {
  beforeEach(() => {
    localStorage.setItem('vulna.token', 'tok123');
    let enabled = false;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith('/api/v1/auth/me')) {
          return jsonResponse({
            id: 'u1',
            email: 'a@example.com',
            full_name: null,
            role: 'administrator',
            organization_id: 'o1',
            is_active: true,
          });
        }
        if (url.endsWith('/api/v1/relays/settings')) {
          if (init?.method === 'POST') enabled = true;
          return jsonResponse({ enabled });
        }
        if (url.includes('/api/v1/sites')) {
          return jsonResponse({
            items: [{ id: 's1', organization_id: 'o1', name: 'HQ', code: 'HQ' }],
            total: 1,
            limit: 50,
            offset: 0,
          });
        }
        if (url.endsWith('/api/v1/relays')) {
          return jsonResponse({ relays: [] });
        }
        return jsonResponse({ detail: 'not found' }, 404);
      }),
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('shows the relay list and organization kill switch immediately', async () => {
    render(
      <AuthProvider>
        <RelayPage />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText(/No relays enrolled yet/)).toBeInTheDocument());
    expect(screen.getByRole('switch', { name: 'Organization relay mode' })).toBeInTheDocument();
  });

  it('round-trips approved, denied, and public-address scope settings', async () => {
    let scopeBody: Record<string, unknown> | null = null;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith('/api/v1/auth/me')) {
          return jsonResponse({
            id: 'u1',
            email: 'a@example.com',
            full_name: null,
            role: 'administrator',
            organization_id: 'o1',
            is_active: true,
          });
        }
        if (url.endsWith('/api/v1/relays/settings')) return jsonResponse({ enabled: true });
        if (url.includes('/api/v1/sites')) {
          return jsonResponse({
            items: [{ id: 's1', organization_id: 'o1', name: 'HQ', code: 'HQ' }],
            total: 1,
            limit: 50,
            offset: 0,
          });
        }
        if (url.endsWith('/api/v1/relays')) {
          return jsonResponse({
            relays: [
              {
                id: 'r1',
                name: 'Branch relay',
                site_id: 's1',
                status: 'enrolled',
                tunnel_up: true,
                tunnel_address: '10.254.0.2',
                approved_cidrs: ['10.0.0.0/8'],
                denied_cidrs: ['10.9.0.0/16'],
                allow_public_addresses: false,
                certificate_fingerprint: 'fp',
                last_seen_at: null,
                enrolled_at: null,
              },
            ],
          });
        }
        if (url.endsWith('/api/v1/relays/r1/scope')) {
          scopeBody = JSON.parse(String(init?.body));
          return jsonResponse({ approved_cidrs: [], denied_cidrs: [] });
        }
        return jsonResponse({ detail: 'not found' }, 404);
      }),
    );

    render(
      <AuthProvider>
        <RelayPage />
      </AuthProvider>,
    );
    const denied = await screen.findByLabelText('Denied CIDRs for Branch relay');
    fireEvent.change(denied, { target: { value: '10.10.0.0/16' } });
    fireEvent.click(screen.getByLabelText('Allow public addresses'));
    fireEvent.click(screen.getByRole('button', { name: 'Save scope' }));

    await waitFor(() =>
      expect(scopeBody).toMatchObject({
        approved_cidrs: ['10.0.0.0/8'],
        denied_cidrs: ['10.10.0.0/16'],
        allow_public_addresses: true,
      }),
    );
  });
});
