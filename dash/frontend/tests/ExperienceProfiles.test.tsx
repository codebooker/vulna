import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { App } from '../src/App';
import { AuthProvider } from '../src/auth/AuthProvider';
import type { ExperienceProfile } from '../src/types/experience';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function experience(profile: ExperienceProfile, pentest: boolean) {
  return {
    experience_profile: profile,
    feature_overrides: profile === 'custom' ? { pentest } : {},
    route_visibility: {
      overview: true,
      assets: true,
      findings: true,
      scans: true,
      sites: true,
      reports: true,
      appliances: true,
      notifications: true,
      users: true,
      settings: true,
      changes: profile !== 'small_business',
      remediation: profile !== 'small_business',
      networks: profile !== 'small_business',
      presets: profile !== 'small_business',
      pentest,
      feeds: profile !== 'small_business',
      system_health: profile !== 'small_business',
      relay: profile !== 'small_business',
      audit: profile !== 'small_business',
    },
    core_routes: [],
    advanced_routes: [],
    capabilities: [],
    note: 'Presentation only.',
  };
}

function installFetchMock(profile: ExperienceProfile) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/api/v1/auth/me')) {
        return jsonResponse({
          id: 'u1',
          email: 'admin@example.com',
          full_name: 'Admin',
          role: 'administrator',
          organization_id: 'o1',
          is_active: true,
        });
      }
      if (url.endsWith('/api/v1/onboarding/state')) {
        return jsonResponse({
          current_step: 'results',
          completed_steps: [],
          site_id: null,
          scope_id: null,
          first_job_id: null,
          demo_used: false,
          dismissed: false,
          completed_at: '2026-07-12T00:00:00Z',
        });
      }
      if (url.endsWith('/api/v1/organizations/current/experience')) {
        return jsonResponse(experience(profile, profile === 'enterprise'));
      }
      if (url.endsWith('/api/v1/dashboard/summary')) {
        return jsonResponse({
          health: {},
          needs_attention: { fix_now: 0, plan: 0, watch: 0, informational: 0, top: [] },
          changed_recently: { window_days: 7, total: 0, by_type: {}, recent: [] },
          unassessed: { stale_assets: 0, approved_scopes: 0, completed_scans: 0 },
          next_action: { kind: 'none', priority: 'low', message: 'Ready' },
        });
      }
      return jsonResponse({ detail: 'not found' }, 404);
    }),
  );
}

describe('experience-aware route catalogue', () => {
  beforeEach(() => {
    localStorage.setItem('vulna.token', 'tok123');
    window.location.hash = '';
  });

  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
    window.location.hash = '';
  });

  it('puts non-core Small Business routes under collapsed Advanced navigation', async () => {
    installFetchMock('small_business');
    render(
      <AuthProvider>
        <App />
      </AuthProvider>,
    );

    const advanced = await screen.findByRole('button', { name: 'Advanced' });
    expect(advanced).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByRole('button', { name: 'Pentest' })).not.toBeInTheDocument();
    fireEvent.click(advanced);
    expect(screen.getByRole('button', { name: 'Pentest' })).toBeInTheDocument();
  });

  it('shows all implemented routes for Enterprise', async () => {
    installFetchMock('enterprise');
    render(
      <AuthProvider>
        <App />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByRole('button', { name: 'Pentest' })).toBeVisible());
    expect(screen.queryByRole('button', { name: 'Advanced' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Users' })).toBeVisible();
  });

  it('keeps a Custom-hidden route directly addressable', async () => {
    installFetchMock('custom');
    window.location.hash = '#pentest';
    render(
      <AuthProvider>
        <App />
      </AuthProvider>,
    );
    await screen.findByRole('heading', { name: 'Controlled pentest' });
    await waitFor(() =>
      expect(screen.queryByRole('button', { name: 'Pentest' })).not.toBeInTheDocument(),
    );
  });
});
