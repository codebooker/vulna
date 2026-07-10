import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AuthProvider } from '../src/auth/AuthProvider';
import { NetworkingPage } from '../src/pages/NetworkingPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('NetworkingPage', () => {
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
        if (url.endsWith('/api/v1/networking/status')) {
          return jsonResponse({
            public_base_url: null,
            cors_origins: [],
            trusted_proxies: '127.0.0.1/32',
            access_modes: ['localhost', 'lan', 'public_dns', 'existing_proxy', 'manual_cert'],
            note: 'separate TLS',
          });
        }
        if (url.endsWith('/api/v1/networking/validate')) {
          return jsonResponse({
            valid: false,
            issues: [
              {
                code: 'mixed_or_insecure',
                problem: 'Reached over HTTP while TLS expected.',
                action: 'Use HTTPS.',
              },
            ],
            certificate: null,
            settings: { mode: 'public_dns', vulna_domain: 'x', caddy_tls: 'internal', warnings: [] },
            proxy_snippet: '# nginx',
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

  it('validates an access config and shows the issue + remediation', async () => {
    render(
      <AuthProvider>
        <NetworkingPage />
      </AuthProvider>,
    );
    const btn = await screen.findByRole('button', { name: /^Validate$/ });
    fireEvent.click(btn);
    await waitFor(() => expect(screen.getByText(/Reached over HTTP/)).toBeInTheDocument());
    expect(screen.getByText(/Use HTTPS/)).toBeInTheDocument();
  });
});
