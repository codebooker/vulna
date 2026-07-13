import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AuthProvider } from '../src/auth/AuthProvider';
import { RemediationPage } from '../src/pages/RemediationPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const finding = {
  id: 'finding-1',
  site_id: 'site-1',
  asset_id: 'asset-1',
  service_id: null,
  scanner_name: 'nuclei',
  title: 'OpenSSL vulnerability',
  description: 'Affected package',
  severity: 'critical',
  cvss_score: 9.8,
  cvss_vector: null,
  cve_ids_json: ['CVE-2026-4242'],
  confidence: 95,
  confidence_label: 'high',
  priority: 'fix_now',
  priority_rationale: 'Explainable risk score is 75 or higher.',
  current_score_snapshot_id: 'score-1',
  risk_score: 88.5,
  risk_profile_version: 1,
  risk_scored_at: '2026-07-13T00:00:00Z',
  known_exploited: true,
  epss_score: 0.9,
  validation_status: 'likely',
  evidence_json: {},
  remediation: 'Upgrade OpenSSL',
  references_json: [],
  status: 'new',
  owner_user_id: null,
  last_verified_at: null,
  resolved_at: null,
};

const unit = {
  id: 'unit-1',
  organization_id: 'org-1',
  site_id: 'site-1',
  key_type: 'cve',
  exact_key: 'CVE-2026-4242',
  title: 'Remediate CVE-2026-4242',
  description: null,
  status: 'open',
  owner_user_id: null,
  automatically_created: true,
  finding_count: 1,
  projected_risk_reduction: 88.5,
  created_at: '2026-07-13T00:00:00Z',
  updated_at: '2026-07-13T00:00:00Z',
};

beforeEach(() => {
  localStorage.setItem('vulna.token', 'access-token');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/api/v1/auth/me')) {
        return jsonResponse({
          id: 'admin-1',
          email: 'admin@example.com',
          full_name: 'Administrator',
          role: 'administrator',
          organization_id: 'org-1',
          is_active: true,
          permissions: ['findings.read', 'remediation.read', 'remediation.manage'],
        });
      }
      if (url.includes('/api/v1/findings?')) {
        return jsonResponse({ items: [finding], total: 1, limit: 200, offset: 0 });
      }
      if (url.includes('/api/v1/remediation-units?')) {
        return jsonResponse({ items: [unit], total: 1, limit: 200, offset: 0 });
      }
      if (url.endsWith('/api/v1/risk-profiles')) {
        return jsonResponse([
          {
            id: 'profile-1',
            name: 'Vulna default',
            version: 1,
            description: 'Balanced',
            weights_json: {},
            is_default: true,
            created_at: '2026-07-13T00:00:00Z',
          },
        ]);
      }
      if (url.endsWith('/api/v1/remediation-units/auto-group') && init?.method === 'POST') {
        return jsonResponse({ units_created: 0, memberships_created: 1 });
      }
      return jsonResponse({ detail: 'not found' }, 404);
    }),
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

it('shows explainable remediation units and applies only explicit exact grouping', async () => {
  render(
    <AuthProvider>
      <RemediationPage />
    </AuthProvider>,
  );

  expect(await screen.findByText('OpenSSL vulnerability')).toBeInTheDocument();
  fireEvent.click(screen.getByTitle('Remediation units'));
  expect(await screen.findByText('Remediate CVE-2026-4242')).toBeInTheDocument();
  expect(
    screen.getByText(/exact keys group automatically; fuzzy matches require review/i),
  ).toBeInTheDocument();
  expect(screen.getByText('−89')).toBeInTheDocument();

  fireEvent.click(screen.getByRole('button', { name: 'Group exact matches' }));
  await waitFor(() =>
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/remediation-units/auto-group'),
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ finding_ids: ['finding-1'] }),
      }),
    ),
  );
});
