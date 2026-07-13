import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { App } from '../src/App';
import { AuthProvider } from '../src/auth/AuthProvider';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const adminUser = {
  id: 'u1',
  email: 'admin@example.com',
  full_name: 'Admin',
  role: 'administrator',
  organization_id: 'o1',
  is_active: true,
};

function installFetchMock({
  refreshSession = false,
  mfaSession = false,
  ssoProviders = false,
}: { refreshSession?: boolean; mfaSession?: boolean; ssoProviders?: boolean } = {}) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? 'GET';
    const headers = (init?.headers ?? {}) as Record<string, string>;

    if (url.endsWith('/api/v1/feeds/health')) {
      return jsonResponse([]);
    }
    if (url.includes('/api/v1/reports')) {
      return jsonResponse({ items: [], total: 0, limit: 50, offset: 0 });
    }
    if (url.endsWith('/health')) {
      return jsonResponse({ status: 'ok', service: 'VulnaDash', version: '0.1.0' });
    }
    if (url.endsWith('/api/v1/system/info')) {
      return jsonResponse({
        service: 'VulnaDash',
        version: '0.1.0',
        environment: 'test',
        api_version: 'v1',
      });
    }
    if (url.endsWith('/api/v1/sso/providers')) {
      return jsonResponse(
        ssoProviders
          ? [{ id: 'idp-1', name: 'Company SSO', slug: 'company', protocol: 'oidc' }]
          : [],
      );
    }
    if (url.endsWith('/api/v1/auth/login') && method === 'POST') {
      const creds = JSON.parse(String(init?.body)) as { password: string };
      if (creds.password === 'right-password') {
        return jsonResponse({
          access_token: 'tok123',
          token_type: 'bearer',
          expires_in: 900,
          session_id: 'session-1',
          mfa_required: mfaSession,
          mfa_enrollment_required: false,
          mfa_methods: mfaSession ? ['totp', 'recovery_code'] : [],
          mfa_grace_expires_at: null,
        });
      }
      return jsonResponse({ detail: 'Invalid email or password' }, 401);
    }
    if (url.endsWith('/api/v1/auth/refresh')) {
      if (refreshSession) {
        return jsonResponse({
          access_token: 'tok123',
          token_type: 'bearer',
          expires_in: 900,
          session_id: 'session-1',
        });
      }
      return jsonResponse({ detail: 'No refresh session' }, 401);
    }
    if (url.endsWith('/api/v1/auth/me')) {
      if (headers.Authorization === 'Bearer tok123' || headers.Authorization === 'Bearer tok456') {
        return jsonResponse(adminUser);
      }
      return jsonResponse({ detail: 'Could not validate credentials' }, 401);
    }
    if (url.endsWith('/api/v1/mfa/totp/verify') && method === 'POST') {
      return jsonResponse({
        access_token: 'tok456',
        token_type: 'bearer',
        expires_in: 900,
        method: 'totp',
        recovery_codes_remaining: 10,
      });
    }
    if (url.endsWith('/api/v1/sites')) {
      return jsonResponse({
        items: [
          {
            id: 's1',
            organization_id: 'o1',
            name: 'Head Office',
            code: 'HQ',
            description: null,
            address: null,
            timezone: 'UTC',
            business_owner: null,
            technical_owner: null,
            tags: [],
            created_at: '2026-07-10T00:00:00Z',
            updated_at: '2026-07-10T00:00:00Z',
          },
        ],
        total: 1,
        limit: 50,
        offset: 0,
      });
    }
    return jsonResponse({ detail: 'not found' }, 404);
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

function renderApp() {
  return render(
    <AuthProvider>
      <App />
    </AuthProvider>,
  );
}

describe('Authentication flow', () => {
  beforeEach(() => {
    localStorage.clear();
    installFetchMock();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('shows the login form when unauthenticated', async () => {
    renderApp();
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: 'Sign in' })).toBeInTheDocument(),
    );
  });

  it('offers enabled organization SSO without hiding local break-glass sign-in', async () => {
    vi.restoreAllMocks();
    installFetchMock({ ssoProviders: true });
    renderApp();
    expect(await screen.findByRole('button', { name: 'Sign in with Company SSO' })).toBeVisible();
    expect(screen.getByLabelText('Password')).toBeVisible();
  });

  it('restores a session from the HttpOnly refresh cookie without browser storage', async () => {
    vi.restoreAllMocks();
    installFetchMock({ refreshSession: true });
    renderApp();
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Sign out' })).toBeInTheDocument(),
    );
    expect(localStorage.getItem('vulna.token')).toBeNull();
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/auth/refresh'),
      expect.objectContaining({ method: 'POST', credentials: 'include' }),
    );
  });

  it('logs in and shows the sites list with an admin create form', async () => {
    renderApp();
    await screen.findByRole('heading', { name: 'Sign in' });

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'admin@example.com' },
    });
    fireEvent.change(screen.getByLabelText('Password'), {
      target: { value: 'right-password' },
    });
    fireEvent.click(screen.getByLabelText(/Trust this device/));
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));

    // Authenticated shell appears with the sidebar nav and a sign-out control.
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Sign out' })).toBeInTheDocument(),
    );
    // Navigate to the Sites section via the sidebar.
    fireEvent.click(screen.getByRole('button', { name: 'Sites' }));
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Sites' })).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText('Head Office')).toBeInTheDocument());
    // Admins get the create action; the form now opens in a modal.
    fireEvent.click(screen.getByRole('button', { name: /Add site/ }));
    expect(screen.getByRole('heading', { name: 'Add a site' })).toBeInTheDocument();
    // Access tokens stay in memory; only the HttpOnly refresh cookie restores a session.
    expect(localStorage.getItem('vulna.token')).toBeNull();
    const loginCall = vi
      .mocked(fetch)
      .mock.calls.find(([input]) => String(input).endsWith('/api/v1/auth/login'));
    expect(loginCall?.[1]).toEqual(
      expect.objectContaining({
        credentials: 'include',
        body: JSON.stringify({
          email: 'admin@example.com',
          password: 'right-password',
          trust_device: true,
        }),
      }),
    );
  });

  it('shows an error on invalid credentials', async () => {
    renderApp();
    await screen.findByRole('heading', { name: 'Sign in' });

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'admin@example.com' },
    });
    fireEvent.change(screen.getByLabelText('Password'), {
      target: { value: 'wrong' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));

    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent('Invalid email or password.'),
    );
    expect(localStorage.getItem('vulna.token')).toBeNull();
  });

  it('keeps an MFA-pending session and completes the second factor before loading the app', async () => {
    vi.restoreAllMocks();
    installFetchMock({ mfaSession: true });
    renderApp();
    await screen.findByRole('heading', { name: 'Sign in' });
    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'admin@example.com' },
    });
    fireEvent.change(screen.getByLabelText('Password'), {
      target: { value: 'right-password' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));

    await screen.findByRole('heading', { name: 'Verify your identity' });
    expect(
      vi
        .mocked(fetch)
        .mock.calls.filter(([input]) => String(input).endsWith('/api/v1/auth/logout')),
    ).toHaveLength(0);
    fireEvent.change(screen.getByLabelText('Authenticator code'), {
      target: { value: '123456' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Sign out' })).toBeInTheDocument(),
    );
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/mfa/totp/verify'),
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ code: '123456' }),
      }),
    );
  });
});
