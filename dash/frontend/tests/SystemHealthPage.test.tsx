import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { AuthProvider } from '../src/auth/AuthProvider';
import { SystemHealthPage } from '../src/pages/SystemHealthPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('SystemHealthPage', () => {
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
        if (url.endsWith('/api/v1/diagnostics')) {
          return jsonResponse({
            summary: { ok: 3, warn: 1, fail: 1 },
            checks: [
              { component: 'database', status: 'ok', summary: 'reachable', impact: '', data_safety: 'safe', next_step: '', doc: '' },
              {
                component: 'certificate_scouts',
                status: 'fail',
                summary: '1 Scout certificate expired',
                impact: 'those Scouts can no longer authenticate',
                data_safety: 'safe',
                next_step: 're-enroll the affected Scouts',
                doc: 'docs/deployment.md',
              },
            ],
          });
        }
        if (url.endsWith('/api/v1/diagnostics/timeline')) {
          return jsonResponse({ events: [{ when: 't', kind: 'site.created', summary: 'user · site.created' }] });
        }
        return jsonResponse({ detail: 'not found' }, 404);
      }),
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('shows failing component with impact and next step', async () => {
    render(
      <AuthProvider>
        <SystemHealthPage />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText(/1 Scout certificate expired/)).toBeInTheDocument());
    expect(screen.getByText(/can no longer authenticate/)).toBeInTheDocument();
    expect(screen.getByText(/re-enroll the affected Scouts/)).toBeInTheDocument();
  });
});
