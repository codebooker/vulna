import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { AuthProvider } from '../src/auth/AuthProvider';
import { MaintenancePage } from '../src/pages/MaintenancePage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('MaintenancePage', () => {
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
        if (url.endsWith('/api/v1/maintenance')) {
          return jsonResponse({
            overall_state: 'warn',
            summary: { ok: 4, warn: 1, action: 0 },
            items: [
              { domain: 'backups', state: 'warn', summary: 'verify a recent backup', detail: '', action: 'run vulna backup', doc: '' },
              { domain: 'storage', state: 'ok', summary: '60% disk free', detail: '', action: '', doc: '' },
            ],
          });
        }
        if (url.endsWith('/api/v1/maintenance/storage')) {
          return jsonResponse({
            categories: [{ category: 'raw_output', bytes: 5242880, location: 'database' }],
            disk: { free_pct: 60, total_bytes: 100 },
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

  it('shows maintenance items with a linked action', async () => {
    render(
      <AuthProvider>
        <MaintenancePage />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText(/verify a recent backup/)).toBeInTheDocument());
    expect(screen.getByText(/run vulna backup/)).toBeInTheDocument();
    expect(screen.getByText(/raw output/)).toBeInTheDocument();
  });
});
