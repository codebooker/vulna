import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { AuthProvider } from '../src/auth/AuthProvider';
import { HomeDashboard } from '../src/pages/HomeDashboard';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('HomeDashboard', () => {
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
        if (url.endsWith('/api/v1/dashboard/summary')) {
          return jsonResponse({
            health: { application: 'ok', database: 'ok', local_scout: 'connected' },
            needs_attention: {
              fix_now: 2,
              plan: 1,
              watch: 0,
              informational: 0,
              top: [
                {
                  id: 'f1',
                  title: 'Critical RCE',
                  priority: 'fix_now',
                  rationale: 'Known exploited in the wild (CISA KEV).',
                  severity: 'critical',
                  confidence_label: 'high',
                  asset_id: 'a1',
                },
              ],
            },
            changed_recently: { window_days: 7, total: 3, by_type: {}, recent: [] },
            unassessed: { stale_assets: 0, approved_scopes: 1, completed_scans: 2 },
            next_action: {
              kind: 'review_fix_now',
              priority: 'fix_now',
              message: '2 issues need fixing now — review the top of the list.',
            },
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

  it('surfaces the next action and highest-priority issue', async () => {
    render(
      <AuthProvider>
        <HomeDashboard />
      </AuthProvider>,
    );
    await waitFor(() =>
      expect(screen.getByText(/need fixing now — review the top/)).toBeInTheDocument(),
    );
    expect(screen.getByText(/Critical RCE/)).toBeInTheDocument();
    expect(screen.getByText(/Known exploited in the wild/)).toBeInTheDocument();
  });
});
