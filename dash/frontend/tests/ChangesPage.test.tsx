import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { ChangesPage } from '../src/pages/ChangesPage';
import { AuthProvider } from '../src/auth/AuthProvider';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('ChangesPage', () => {
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
        if (url.includes('/api/v1/changes')) {
          return jsonResponse({
            items: [
              {
                id: 'c1',
                site_id: 's1',
                asset_id: 'a1',
                event_type: 'new_port_opened',
                severity: 'info',
                summary: 'Port 80/tcp opened on 10.20.0.5',
                created_at: '2026-07-10T00:00:00Z',
              },
            ],
            total: 1,
            limit: 20,
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

  it('renders recent change events', async () => {
    render(
      <AuthProvider>
        <ChangesPage />
      </AuthProvider>,
    );
    // "Port opened" appears both as a table cell and as a filter option in the
    // redesigned activity table, so assert on at least one occurrence.
    await waitFor(() => expect(screen.getAllByText('Port opened').length).toBeGreaterThan(0));
    expect(screen.getByText(/Port 80\/tcp opened on 10\.20\.0\.5/)).toBeInTheDocument();
  });
});
