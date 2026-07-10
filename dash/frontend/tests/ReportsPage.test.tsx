import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { ReportsPage } from '../src/pages/ReportsPage';
import { AuthProvider } from '../src/auth/AuthProvider';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const report = {
  id: 'r1',
  organization_id: 'o1',
  site_id: 's1',
  scan_job_id: 'j1',
  report_type: 'executive_pdf',
  format: 'pdf',
  status: 'completed',
  sha256: 'abc',
  size_bytes: 2048,
  generated_at: '2026-07-10T00:00:00Z',
  expires_at: null,
  error: null,
  created_at: '2026-07-10T00:00:00Z',
};

describe('ReportsPage', () => {
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
        if (url.includes('/api/v1/reports')) {
          return jsonResponse({ items: [report], total: 1, limit: 50, offset: 0 });
        }
        return jsonResponse({ detail: 'not found' }, 404);
      }),
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('lists reports with a download control', async () => {
    render(
      <AuthProvider>
        <ReportsPage />
      </AuthProvider>,
    );
    await waitFor(() =>
      expect(screen.getByText('Executive summary (PDF)')).toBeInTheDocument(),
    );
    expect(screen.getByText('2.0 KB')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Download' })).toBeEnabled();
  });
});
