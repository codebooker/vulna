import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AuthProvider } from '../src/auth/AuthProvider';
import { AddScoutPage } from '../src/pages/AddScoutPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('AddScoutPage', () => {
  beforeEach(() => {
    localStorage.setItem('vulna.token', 'tok123');
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
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
        if (url.endsWith('/api/v1/sites')) {
          return jsonResponse({
            items: [{ id: 's1', name: 'HQ', code: 'HQ', timezone: 'UTC' }],
            total: 1,
            limit: 50,
            offset: 0,
          });
        }
        if (url.endsWith('/api/v1/probes/enrollment-command')) {
          return jsonResponse(
            {
              site_id: 's1',
              probe_name: 'remote-scout',
              token: 'vscout_secrettoken',
              short_code: 'ABCD1234',
              expires_at: '2026-07-10T01:00:00Z',
              server_url: 'https://vulna.example.com',
              commands: {
                universal:
                  'curl -fsSLO https://vulna.example.com/install-scout.sh && ' +
                  'VULNA_SERVER=https://vulna.example.com VULNA_ENROLL_TOKEN=vscout_secrettoken sh install-scout.sh',
              },
              verification: 'Confirm the short code ABCD1234',
            },
            201,
          );
        }
        return jsonResponse({ detail: 'not found' }, 404);
      }),
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('generates a single-use install command with a verify code', async () => {
    render(
      <AuthProvider>
        <AddScoutPage />
      </AuthProvider>,
    );
    const button = await screen.findByRole('button', { name: /generate install command/i });
    await waitFor(() => expect(button).toBeEnabled()); // wait for sites to load
    fireEvent.click(button);
    await waitFor(() => expect(screen.getByText(/install-scout.sh/)).toBeInTheDocument());
    expect(screen.getByText(/ABCD1234/)).toBeInTheDocument();
    // The command uses the verifying bootstrap and env-passed token.
    expect(screen.getByText(/VULNA_ENROLL_TOKEN=vscout_secrettoken/)).toBeInTheDocument();
  });
});
