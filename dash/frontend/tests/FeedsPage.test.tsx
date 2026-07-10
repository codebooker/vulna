import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { FeedsPage } from '../src/pages/FeedsPage';
import { AuthProvider } from '../src/auth/AuthProvider';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const feeds = [
  {
    source: 'nvd',
    status: 'ok',
    last_success_at: '2026-07-10T00:00:00Z',
    last_attempt_at: '2026-07-10T00:00:00Z',
    records_processed: 1200,
    records_changed: 3,
    attempts: 1,
    error: null,
    last_source_timestamp: null,
    updated_at: '2026-07-10T00:00:00Z',
  },
  {
    source: 'kev',
    status: 'failed',
    last_success_at: null,
    last_attempt_at: '2026-07-10T00:00:00Z',
    records_processed: 0,
    records_changed: 0,
    attempts: 3,
    error: 'GET kev failed: 503',
    last_source_timestamp: null,
    updated_at: '2026-07-10T00:00:00Z',
  },
];

describe('FeedsPage', () => {
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
        if (url.endsWith('/api/v1/feeds/health')) {
          return jsonResponse(feeds);
        }
        return jsonResponse({ detail: 'not found' }, 404);
      }),
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('shows feed status and surfaces a failing feed', async () => {
    render(
      <AuthProvider>
        <FeedsPage />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText('NVD (CVE)')).toBeInTheDocument());
    expect(screen.getByText('Failed')).toBeInTheDocument();
    // The error from the failing feed is visible to the operator.
    expect(screen.getByText('GET kev failed: 503')).toBeInTheDocument();
    // Admins get a per-feed sync control.
    expect(screen.getAllByRole('button', { name: 'Sync now' })).toHaveLength(2);
  });
});
