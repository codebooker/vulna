import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AuthProvider } from '../src/auth/AuthProvider';
import { AddRelayPage } from '../src/pages/AddRelayPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('AddRelayPage', () => {
  const writeText = vi.fn<(value: string) => Promise<void>>();

  beforeEach(() => {
    localStorage.setItem('vulna.token', 'tok123');
    writeText.mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
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
        if (url.endsWith('/api/v1/sites')) {
          return jsonResponse({
            items: [{ id: 's1', name: 'HQ', code: 'HQ', timezone: 'UTC' }],
            total: 1,
            limit: 50,
            offset: 0,
          });
        }
        if (url.endsWith('/api/v1/relays/enrollment-command')) {
          return jsonResponse({
            relay_id: 'r1',
            token: 'vscout_secret',
            short_code: 'ABCD1234',
            install: {
              name: 'Branch relay',
              command:
                'curl -fsSLo /tmp/install-relay.sh https://github.com/codebooker/vulna/releases/latest/download/install-relay.sh && VULNA_VERSION=latest sh /tmp/install-relay.sh',
              note: 'Run as root.',
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

  it('generates and copies the entire relay install command', async () => {
    render(
      <AuthProvider>
        <AddRelayPage />
      </AuthProvider>,
    );

    const name = await screen.findByLabelText('Relay name');
    fireEvent.change(name, { target: { value: 'Branch relay' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add relay' }));
    const copy = await screen.findByRole('button', { name: 'Copy command' });
    fireEvent.click(copy);

    await waitFor(() => expect(writeText).toHaveBeenCalledOnce());
    expect(writeText.mock.calls[0]?.[0]).toContain('/releases/latest/download/install-relay.sh');
    expect(writeText.mock.calls[0]?.[0]).not.toContain('vlatest');
  });
});
