import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AuthProvider } from '../src/auth/AuthProvider';
import { HelpPage } from '../src/pages/HelpPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('HelpPage', () => {
  beforeEach(() => {
    localStorage.setItem('vulna.token', 'tok123');
    let demoOn = false;
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
        if (url.endsWith('/api/v1/help/topics')) {
          return jsonResponse({
            topics: [
              { key: 'getting-started', title: 'Quick start', summary: 'First scan.', doc: 'docs/quickstart.md' },
            ],
          });
        }
        if (url.endsWith('/api/v1/help/exposure-checklist')) {
          return jsonResponse({ checklist: ['Terminate TLS at a reverse proxy.'] });
        }
        if (url.endsWith('/api/v1/demo/status')) {
          return jsonResponse({ demo_mode: demoOn, seeded: demoOn });
        }
        if (url.endsWith('/api/v1/demo/enable')) {
          demoOn = true;
          return jsonResponse({ demo_mode: true, seeded: true });
        }
        return jsonResponse({ detail: 'not found' }, 404);
      }),
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('shows guides and can enable demo mode', async () => {
    render(
      <AuthProvider>
        <HelpPage />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText('Quick start')).toBeInTheDocument());
    expect(screen.getByText(/Terminate TLS/)).toBeInTheDocument();
    expect(screen.getByText(/Demo mode is/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Enable demo mode/ }));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /Disable demo mode/ })).toBeInTheDocument(),
    );
  });
});
