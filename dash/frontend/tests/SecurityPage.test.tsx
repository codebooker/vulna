import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AuthProvider } from '../src/auth/AuthProvider';
import { SecurityPage } from '../src/pages/SecurityPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

beforeEach(() => {
  localStorage.setItem('vulna.token', 'token');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/api/v1/auth/me')) {
        return jsonResponse({
          id: 'user-1',
          email: 'admin@example.com',
          full_name: 'Admin',
          role: 'administrator',
          organization_id: 'org-1',
          is_active: true,
          mfa_status: 'not_enrolled',
          mfa_grace_expires_at: null,
        });
      }
      if (url.endsWith('/api/v1/mfa/status')) {
        return jsonResponse({
          required: false,
          enrolled: false,
          grace_expires_at: null,
          totp: false,
          webauthn_credentials: 0,
          recovery_codes_remaining: 0,
          methods: [],
        });
      }
      if (url.endsWith('/api/v1/mfa/webauthn/credentials')) return jsonResponse([]);
      if (url.endsWith('/api/v1/mfa/policy')) {
        return jsonResponse({ mode: 'optional', required_roles: [], grace_period_days: 7 });
      }
      if (url.endsWith('/api/v1/mfa/totp/setup')) {
        return jsonResponse({
          factor_id: 'factor-1',
          secret: 'JBSWY3DPEHPK3PXP',
          provisioning_uri: 'otpauth://totp/Vulna:admin',
          expires_in: 600,
        });
      }
      if (url.endsWith('/api/v1/mfa/totp/confirm')) {
        return jsonResponse({
          verification: {
            access_token: 'verified-token',
            token_type: 'bearer',
            expires_in: 900,
            method: 'totp',
            recovery_codes_remaining: 10,
          },
          recovery_codes: {
            codes: Array.from({ length: 10 }, (_, index) => `safe-${index}-code`),
            shown_once: true,
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

it('enrolls TOTP and pauses for one-time recovery-code acknowledgement', async () => {
  render(
    <AuthProvider>
      <SecurityPage />
    </AuthProvider>,
  );

  await screen.findByRole('heading', { name: 'Organization MFA policy' });
  expect(screen.getByText('No MFA method is enrolled.')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Add method' }));
  fireEvent.click(screen.getByRole('button', { name: 'Authenticator app' }));
  expect(await screen.findByText('JBSWY3DPEHPK3PXP')).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Six-digit code'), { target: { value: '123456' } });
  fireEvent.click(screen.getByRole('button', { name: 'Verify and enable' }));

  expect(await screen.findByRole('heading', { name: 'Save your recovery codes' })).toBeVisible();
  expect(screen.getByText('safe-0-code')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'I saved these codes' }));
  await waitFor(() =>
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/auth/me'),
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: 'Bearer verified-token' }),
      }),
    ),
  );
});
