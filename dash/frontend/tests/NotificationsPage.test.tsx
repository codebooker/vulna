import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AuthProvider } from '../src/auth/AuthProvider';
import { NotificationsPage } from '../src/pages/NotificationsPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('NotificationsPage', () => {
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
        if (url.endsWith('/api/v1/notifications/events')) {
          return jsonResponse({
            events: [{ type: 'scan_failed', label: 'A scan failed' }],
            policies: ['immediate'],
          });
        }
        if (url.endsWith('/api/v1/notifications/channels') && (!init || init.method !== 'POST')) {
          return jsonResponse({
            channels: [
              {
                id: 'c1',
                name: 'ops',
                channel_type: 'webhook',
                config: {},
                has_secret: true,
                events: ['scan_failed'],
                policy: 'immediate',
                quiet_start_hour: null,
                quiet_end_hour: null,
                enabled: true,
                last_digest_at: null,
              },
            ],
          });
        }
        if (url.endsWith('/api/v1/notifications/deliveries')) {
          return jsonResponse({
            deliveries: [
              {
                id: 'd1',
                channel_id: 'c1',
                event_type: 'scan_failed',
                status: 'sent',
                attempts: 1,
                last_error: null,
                title: 'Scan failed',
                created_at: 't',
                sent_at: 't',
              },
            ],
          });
        }
        if (url.endsWith('/api/v1/notifications/channels/c1/test')) {
          return jsonResponse({ ok: true });
        }
        return jsonResponse({ detail: 'not found' }, 404);
      }),
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('lists channels and delivery history and can send a test', async () => {
    render(
      <AuthProvider>
        <NotificationsPage />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText('ops')).toBeInTheDocument());
    // Credentials are never shown; only the has_secret indicator drives the UI.
    expect(screen.queryByText(/signing-key/)).not.toBeInTheDocument();
    // Delivery history shows the sent delivery.
    expect(screen.getByText(/Scan failed/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Send test/ }));
    await waitFor(() => expect(screen.getByText(/Test notification sent/)).toBeInTheDocument());
  });
});
