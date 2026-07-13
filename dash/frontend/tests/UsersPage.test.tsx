import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { AuthProvider } from '../src/auth/AuthProvider';
import { UsersPage } from '../src/pages/UsersPage';

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

beforeEach(() => {
  localStorage.setItem('vulna.token', 'tok123');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
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
      return jsonResponse({
        items: [
          {
            id: 'u1',
            email: 'admin@example.com',
            full_name: 'Admin',
            role: 'administrator',
            organization_id: 'o1',
            is_active: true,
            last_login_at: null,
            created_at: '2026-07-12T00:00:00Z',
            updated_at: '2026-07-12T00:00:00Z',
          },
        ],
        total: 1,
        limit: 50,
        offset: 0,
      });
    }),
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

it('renders the Phase 33 administrator account inventory as read-only', async () => {
  render(
    <AuthProvider>
      <UsersPage />
    </AuthProvider>,
  );
  expect(await screen.findByText('admin@example.com')).toBeInTheDocument();
  expect(screen.getByText('Available in Phase 36')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /add user/i })).not.toBeInTheDocument();
});
