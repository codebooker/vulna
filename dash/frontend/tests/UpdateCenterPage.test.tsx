import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { AuthProvider } from '../src/auth/AuthProvider';
import { UpdateCenterPage } from '../src/pages/UpdateCenterPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('UpdateCenterPage', () => {
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
        if (url.endsWith('/api/v1/system/update')) {
          return jsonResponse({
            current_version: '0.1.0',
            channel: 'stable',
            channels: ['stable', 'candidate', 'development'],
            update_types: ['Vulna application', 'VulnaScout', 'intelligence feeds'],
            how_to_check: 'vulna update check --channel stable',
            how_to_apply: 'vulna update',
            note: 'Automatic installation is opt-in; there is no forced remote update path.',
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

  it('shows current version, channel, and the CLI update commands', async () => {
    render(
      <AuthProvider>
        <UpdateCenterPage />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText('0.1.0')).toBeInTheDocument());
    expect(screen.getByText(/vulna update check --channel stable/)).toBeInTheDocument();
    expect(screen.getByText(/no forced remote update path/)).toBeInTheDocument();
  });
});
