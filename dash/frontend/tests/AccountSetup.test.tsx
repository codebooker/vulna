import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { App } from '../src/App';
import { AuthProvider } from '../src/auth/AuthProvider';

beforeEach(() => {
  window.location.hash = '#accept-invitation?token=one-time-secret';
  vi.stubGlobal(
    'fetch',
    vi.fn(
      async (input: RequestInfo | URL) =>
        new Response(
          JSON.stringify(
            String(input).endsWith('/api/v1/auth/refresh')
              ? { detail: 'No refresh session' }
              : { status: 'accepted' },
          ),
          {
            status: String(input).endsWith('/api/v1/auth/refresh') ? 401 : 200,
            headers: { 'Content-Type': 'application/json' },
          },
        ),
    ),
  );
});

afterEach(() => {
  window.location.hash = '';
  vi.restoreAllMocks();
  localStorage.clear();
});

it('lets an invited user choose their own password without an authenticated session', async () => {
  render(
    <AuthProvider>
      <App />
    </AuthProvider>,
  );
  expect(screen.getByText('Accept your invitation')).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('New password'), {
    target: { value: 'a-secure-passphrase' },
  });
  fireEvent.change(screen.getByLabelText('Confirm password'), {
    target: { value: 'a-secure-passphrase' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Activate account' }));
  expect(await screen.findByText('Password saved')).toBeInTheDocument();
  expect(vi.mocked(fetch)).toHaveBeenCalledWith(
    expect.stringContaining('/api/v1/auth/invitations/accept'),
    expect.objectContaining({ method: 'POST' }),
  );
});
