import { render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AuthProvider } from '../src/auth/AuthProvider';
import { FindingsPage } from '../src/pages/FindingsPage';

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

beforeEach(() => {
  localStorage.setItem('vulna.token', 'access-token');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/api/v1/auth/me')) {
        return jsonResponse({
          id: 'admin-1',
          email: 'admin@example.com',
          full_name: 'Administrator',
          role: 'administrator',
          organization_id: 'org-1',
          is_active: true,
          permissions: ['assets.read', 'findings.read'],
        });
      }
      if (url.includes('/api/v1/findings?')) {
        return jsonResponse({
          items: [
            {
              id: 'finding-1',
              site_id: 'site-1',
              asset_id: 'asset-1',
              service_id: 'service-1',
              scanner_name: 'testssl',
              title: 'Certificate chain not trusted',
              description: null,
              severity: 'critical',
              cvss_score: null,
              cvss_vector: null,
              cve_ids_json: [],
              confidence: 50,
              confidence_label: 'Medium',
              priority: 'plan',
              priority_rationale: 'Explainable risk score is between 50 and 74.',
              current_score_snapshot_id: 'score-1',
              risk_score: 50,
              risk_profile_version: 1,
              risk_scored_at: '2026-07-20T00:00:00Z',
              known_exploited: false,
              epss_score: null,
              validation_status: 'unvalidated',
              evidence_json: {},
              remediation: 'Install the complete certificate chain.',
              references_json: [],
              status: 'new',
              owner_user_id: null,
              last_verified_at: null,
              resolved_at: null,
            },
          ],
          total: 1,
          limit: 200,
          offset: 0,
        });
      }
      if (url.includes('/api/v1/assets?')) {
        return jsonResponse({
          items: [
            {
              id: 'asset-1',
              canonical_name: 'gateway.example.test',
            },
          ],
          total: 1,
          limit: 200,
          offset: 0,
        });
      }
      return new Response(JSON.stringify({ detail: 'not found' }), { status: 404 });
    }),
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

it('shows the real risk score and a human-readable affected asset', async () => {
  render(
    <AuthProvider>
      <FindingsPage />
    </AuthProvider>,
  );

  expect(await screen.findByText('gateway.example.test')).toBeInTheDocument();
  expect(screen.getByText('50.0')).toBeInTheDocument();
  expect(screen.getAllByText('Plan a fix')).toHaveLength(2);
});
