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

  it('is off by default and can be enabled', async () => {
    render(
      <AuthProvider>
        <RelayPage />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText(/Relay mode is/)).toBeInTheDocument());
    // Off by default.
    expect(screen.getByRole('button', { name: /Enable relay mode/ })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Enable relay mode/ }));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /Disable relay mode/ })).toBeInTheDocument(),
    );
    // Relay management appears once enabled.
    expect(screen.getByText(/No relays enrolled yet/)).toBeInTheDocument();
  });
});
