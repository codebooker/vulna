import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { AuthProvider } from '../src/auth/AuthProvider';
import { PrivacyPage } from '../src/pages/PrivacyPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('PrivacyPage', () => {
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
        if (url.endsWith('/api/v1/privacy/outbound')) {
          return jsonResponse({
            connections: [
              {
                name: 'Update checks',
                category: 'updates',
                destination: null,
                enabled: false,
                purpose: 'The application never contacts a release server.',
              },
            ],
          });
        }
        if (url.endsWith('/api/v1/privacy/settings')) {
          return jsonResponse({
            settings: {
              telemetry_enabled: false,
              update_check_enabled: true,
              intelligence_feeds_enabled: true,
              local_analytics_enabled: true,
            },
          });
        }
        if (url.endsWith('/api/v1/privacy/telemetry/preview')) {
          return jsonResponse({
            schema_version: '1',
            vulna_version: '0.1.0',
            counts: { sites: 1, assets: 2, scans: 0, findings: 0, critical_findings: 0 },
            excluded: ['ip_addresses', 'hostnames'],
          });
        }
        if (url.endsWith('/api/v1/privacy/secrets')) {
          return jsonResponse({
            secrets: [
              { name: 'Application secret key', present: true, category: 'core', rotatable: true },
            ],
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

  it('shows outbound connections and that telemetry is off', async () => {
    render(
      <AuthProvider>
        <PrivacyPage />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText('Update checks')).toBeInTheDocument());
    expect(screen.getByText(/never contacts a release server/)).toBeInTheDocument();
    // Telemetry off note appears.
    expect(screen.getByText(/Telemetry is off/)).toBeInTheDocument();
    // Secret inventory shows status, not values (loads once admin role resolves).
    await waitFor(() =>
      expect(screen.getByText('Application secret key')).toBeInTheDocument(),
    );
  });
});
