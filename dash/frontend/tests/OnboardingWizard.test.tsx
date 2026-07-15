import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AuthProvider } from '../src/auth/AuthProvider';
import { OnboardingWizard } from '../src/pages/OnboardingWizard';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const scopeState = {
  current_step: 'scope',
  completed_steps: ['admin', 'recovery_codes', 'health', 'site', 'scout', 'network'],
  site_id: 's1',
  scope_id: null,
  first_job_id: null,
  demo_used: false,
  dismissed: false,
  completed_at: null,
};

describe('OnboardingWizard scope step', () => {
  beforeEach(() => {
    localStorage.setItem('vulna.token', 'tok123');
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
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
        if (url.endsWith('/api/v1/onboarding/state')) {
          return jsonResponse(scopeState);
        }
        if (url.endsWith('/api/v1/onboarding/scope-preview')) {
          const body = JSON.parse(String(init?.body ?? '{}')) as { cidr: string };
          if (body.cidr === '0.0.0.0/0') {
            return jsonResponse({ detail: 'Refusing to approve a default route' }, 422);
          }
          return jsonResponse({
            cidr: body.cidr,
            host_estimate: 254,
            is_private: true,
            warnings: [],
            requires_confirmation: false,
          });
        }
        return jsonResponse({ detail: 'not found' }, 404);
      }),
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
    sessionStorage.clear();
  });

  it('previews a private range with a host estimate', async () => {
    render(
      <AuthProvider>
        <OnboardingWizard onFinished={() => {}} />
      </AuthProvider>,
    );
    const input = await screen.findByPlaceholderText(/192.168.1.0\/24/);
    fireEvent.change(input, { target: { value: '10.0.0.0/24' } });
    fireEvent.click(screen.getByRole('button', { name: /preview/i }));
    await waitFor(() => expect(screen.getByText(/254/)).toBeInTheDocument());
    expect(screen.getByRole('button', { name: /approve scope/i })).toBeEnabled();
  });

  it('rejects a default route with a clear error', async () => {
    render(
      <AuthProvider>
        <OnboardingWizard onFinished={() => {}} />
      </AuthProvider>,
    );
    const input = await screen.findByPlaceholderText(/192.168.1.0\/24/);
    fireEvent.change(input, { target: { value: '0.0.0.0/0' } });
    fireEvent.click(screen.getByRole('button', { name: /preview/i }));
    await waitFor(() => expect(screen.getByText(/default route/i)).toBeInTheDocument());
  });

  it('launches the chosen preset through the approved scope network primary Scout', async () => {
    sessionStorage.setItem('vulna.onboarding.preset', 'safe');
    let jobBody: Record<string, unknown> | null = null;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith('/api/v1/auth/me')) {
          return jsonResponse({
            id: 'u1',
            email: 'a@example.com',
            role: 'administrator',
            organization_id: 'o1',
            is_active: true,
          });
        }
        if (url.endsWith('/api/v1/onboarding/state')) {
          return jsonResponse({ ...scopeState, current_step: 'launch', scope_id: 'scope-1' });
        }
        if (url.endsWith('/api/v1/scopes')) {
          return jsonResponse({
            items: [{ id: 'scope-1', network_id: 'network-1', cidr: '10.20.0.0/24' }],
            total: 1,
            limit: 50,
            offset: 0,
          });
        }
        if (url.endsWith('/api/v1/networks')) {
          return jsonResponse([
            {
              id: 'network-1',
              scouts: [{ probe_id: 'probe-primary', probe_name: 'HQ Scout', is_primary: true }],
              ranges: [{ cidr: '10.20.0.0/24' }],
            },
          ]);
        }
        if (url.endsWith('/api/v1/probes')) {
          return jsonResponse({
            items: [
              { id: 'probe-other', status: 'enrolled', site_id: 's2', name: 'Wrong Scout' },
              { id: 'probe-primary', status: 'enrolled', site_id: 's1', name: 'HQ Scout' },
            ],
            total: 2,
            limit: 50,
            offset: 0,
          });
        }
        if (url.endsWith('/api/v1/onboarding/scan-summary')) {
          const body = JSON.parse(String(init?.body));
          return jsonResponse({
            preset: body.preset,
            preset_name: 'Safe check',
            targets: body.targets,
            host_estimate: 254,
            checks: ['discovery'],
            intrusive: false,
            active_web: false,
            uses_credentials: false,
            resource_class: 'low',
            duration_class: 'short',
            demo: false,
            data_retention: 'Standard retention.',
          });
        }
        if (url.endsWith('/api/v1/jobs')) {
          jobBody = JSON.parse(String(init?.body));
          return jsonResponse({ id: 'job-1', status: 'queued', mode: 'vulnerability_assessment' });
        }
        if (url.endsWith('/api/v1/onboarding/complete-step')) {
          return jsonResponse({ ...scopeState, current_step: 'results', first_job_id: 'job-1' });
        }
        return jsonResponse({ detail: 'not found' }, 404);
      }),
    );

    render(
      <AuthProvider>
        <OnboardingWizard onFinished={() => {}} />
      </AuthProvider>,
    );
    fireEvent.click(await screen.findByRole('button', { name: 'Launch assessment' }));

    await waitFor(() =>
      expect(jobBody).toMatchObject({
        probe_id: 'probe-primary',
        network_id: 'network-1',
        preset_key: 'safe',
        targets: ['10.20.0.0/24'],
      }),
    );
  });
});
