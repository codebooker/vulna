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
});
