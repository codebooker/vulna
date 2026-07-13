import { expect, test } from '@playwright/test';

const base64url = (length: number) => Buffer.alloc(length, 7).toString('base64url');

test('enrolls a passkey with a virtual authenticator after password verification', async ({
  page,
}) => {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'usb',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  let registrationPayload: Record<string, unknown> | null = null;
  await page.route('**/health', async (route) => {
    await route.fulfill({ json: { status: 'ok', service: 'VulnaDash', version: 'test' } });
  });
  await page.route(/\/api\/v1\//, async (route) => {
    const url = route.request().url();
    if (url.endsWith('/api/v1/auth/refresh')) {
      await route.fulfill({ status: 401, json: { detail: 'No refresh session' } });
      return;
    }
    if (url.endsWith('/api/v1/auth/login')) {
      await route.fulfill({
        json: {
          access_token: 'pending-token',
          token_type: 'bearer',
          expires_in: 900,
          session_id: 'session-1',
          mfa_required: true,
          mfa_enrollment_required: true,
          mfa_methods: [],
          mfa_grace_expires_at: '2026-07-20T00:00:00Z',
        },
      });
      return;
    }
    if (url.endsWith('/api/v1/mfa/webauthn/register/options')) {
      await route.fulfill({
        json: {
          challenge_id: '11111111-1111-4111-8111-111111111111',
          public_key: {
            rp: { id: 'localhost', name: 'Vulna' },
            user: {
              id: base64url(16),
              name: 'admin@example.com',
              displayName: 'Admin',
            },
            challenge: base64url(32),
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            timeout: 300000,
            excludeCredentials: [],
            authenticatorSelection: {
              residentKey: 'preferred',
              userVerification: 'required',
            },
            attestation: 'none',
          },
        },
      });
      return;
    }
    if (url.endsWith('/api/v1/mfa/webauthn/register/verify')) {
      registrationPayload = route.request().postDataJSON() as Record<string, unknown>;
      await route.fulfill({
        json: {
          credential: {
            id: '22222222-2222-4222-8222-222222222222',
            label: 'Security key',
            device_type: 'single_device',
            backed_up: false,
            transports: ['usb'],
            created_at: '2026-07-13T00:00:00Z',
            last_used_at: null,
          },
          verification: {
            access_token: 'verified-token',
            token_type: 'bearer',
            expires_in: 900,
            method: 'webauthn',
            recovery_codes_remaining: 10,
          },
          recovery_codes: {
            codes: Array.from({ length: 10 }, (_, index) => `code-${index}-safe`),
            shown_once: true,
          },
        },
      });
      return;
    }
    if (url.endsWith('/api/v1/auth/me')) {
      await route.fulfill({
        json: {
          id: 'user-1',
          email: 'admin@example.com',
          full_name: 'Admin',
          role: 'administrator',
          organization_id: 'org-1',
          is_active: true,
          mfa_status: 'enrolled',
          mfa_grace_expires_at: null,
        },
      });
      return;
    }
    await route.fulfill({ status: 404, json: { detail: 'not mocked' } });
  });

  await page.goto('/');
  await page.getByLabel('Email').fill('admin@example.com');
  await page.getByLabel('Password').fill('right-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(
    page.getByRole('heading', { name: 'Set up multi-factor authentication' }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Passkey or security key' }).click();

  await expect(page.getByRole('heading', { name: 'Save your recovery codes' })).toBeVisible();
  expect(registrationPayload).not.toBeNull();
  const credential = registrationPayload?.credential as Record<string, unknown>;
  const response = credential.response as Record<string, unknown>;
  expect(credential.id).toBeTruthy();
  expect(response.clientDataJSON).toBeTruthy();
  expect(response.attestationObject).toBeTruthy();

  await page.getByRole('button', { name: 'I saved these codes' }).click();
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
});
