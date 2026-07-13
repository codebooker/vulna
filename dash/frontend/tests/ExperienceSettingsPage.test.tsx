import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AuthProvider } from '../src/auth/AuthProvider';
import { ExperienceSettingsPage } from '../src/pages/ExperienceSettingsPage';

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

const base = {
  experience_profile: 'small_business',
  feature_overrides: {},
  route_visibility: { assets: true, pentest: false },
  core_routes: ['assets'],
  advanced_routes: ['pentest'],
  capabilities: [],
  note: 'Profiles change presentation only.',
};

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  localStorage.setItem('vulna.token', 'tok123');
  fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith('/api/v1/auth/me')) {
      return jsonResponse({
        id: 'u1', email: 'admin@example.com', full_name: 'Admin', role: 'administrator',
        organization_id: 'o1', is_active: true,
      });
    }
    if (url.endsWith('/experience/preview')) {
      return jsonResponse({
        ...base,
        experience_profile: 'enterprise',
        route_visibility: { assets: true, pentest: true },
        changed_routes: ['pentest'],
      });
    }
    if (url.endsWith('/api/v1/organizations/current/experience') && init?.method === 'PATCH') {
      return jsonResponse({ ...base, experience_profile: 'enterprise' });
    }
    return jsonResponse(base);
  });
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

it('previews preserved controls before applying an audited profile change', async () => {
  render(
    <AuthProvider>
      <ExperienceSettingsPage />
    </AuthProvider>,
  );
  const select = await screen.findByLabelText('Experience profile');
  fireEvent.change(select, { target: { value: 'enterprise' } });
  fireEvent.click(screen.getByRole('button', { name: 'Preview change' }));

  expect(await screen.findByText('Confirm presentation change')).toBeInTheDocument();
  expect(screen.getByText(/security controls/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Confirm profile' }));
  await waitFor(() =>
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/organizations/current/experience'),
      expect.objectContaining({ method: 'PATCH' }),
    ),
  );
});
