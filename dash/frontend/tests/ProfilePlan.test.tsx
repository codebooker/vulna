import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AuthProvider } from '../src/auth/AuthProvider';
import { OnboardingWizard } from '../src/pages/OnboardingWizard';

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

const state = {
  current_step: 'profile_plan',
  completed_steps: ['admin'],
  site_id: null,
  scope_id: null,
  first_job_id: null,
  demo_used: false,
  dismissed: false,
  completed_at: null,
};

beforeEach(() => {
  localStorage.setItem('vulna.token', 'tok123');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
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
      if (url.endsWith('/api/v1/onboarding/state')) return jsonResponse(state);
      if (url.endsWith('/api/v1/onboarding/profile-plan') && init?.method === 'PUT') {
        return jsonResponse({
          experience_profile: 'small_business',
          questions: [],
          answers: JSON.parse(String(init.body)).answers,
          recommendations: [
            {
              capability: 'Synchronize remediation tickets',
              status: 'planned',
              reason: 'Ticket connectors arrive in Phase 43.',
              route: null,
            },
          ],
          updated_at: '2026-07-12T00:00:00Z',
        });
      }
      if (url.endsWith('/api/v1/onboarding/profile-plan')) {
        return jsonResponse({
          experience_profile: 'small_business',
          questions: [
            {
              key: 'asset_count',
              label: 'About how many assets do you manage?',
              kind: 'number',
              options: [],
              required: true,
            },
            {
              key: 'ticketing',
              label: 'Do you want findings synchronized to a ticket system?',
              kind: 'boolean',
              options: [],
              required: false,
            },
          ],
          answers: {},
          recommendations: [],
          updated_at: null,
        });
      }
      if (url.endsWith('/api/v1/onboarding/state/complete-step')) {
        return jsonResponse({
          ...state,
          current_step: 'recovery_codes',
          completed_steps: ['admin', 'profile_plan'],
        });
      }
      return jsonResponse({ detail: 'not found' });
    }),
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

it('stores planning answers and labels unavailable recommendations as planned', async () => {
  render(
    <AuthProvider>
      <OnboardingWizard onFinished={() => {}} />
    </AuthProvider>,
  );
  fireEvent.change(await screen.findByLabelText('About how many assets do you manage?'), {
    target: { value: '650' },
  });
  fireEvent.change(screen.getByLabelText('Do you want findings synchronized to a ticket system?'), {
    target: { value: 'true' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Show recommendations' }));
  await waitFor(() => expect(screen.getByText('planned')).toBeInTheDocument());
  expect(screen.getByText(/Phase 43/)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Continue' })).toBeEnabled();
});
