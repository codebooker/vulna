import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { AuthProvider } from '../src/auth/AuthProvider';
import { BackupCenterPage } from '../src/pages/BackupCenterPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('BackupCenterPage', () => {
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
        if (url.endsWith('/api/v1/system/backups')) {
          return jsonResponse({
            default_destination: 'local filesystem',
            destinations: ['local', 's3-compatible'],
            retention_days: 30,
            contents: ['database', 'ca', 'evidence'],
            encryption: 'AES-256-GCM with a recovery passphrase',
            how_to_create: 'vulna backup create --archive <tar.gz> --encrypt',
            how_to_verify: 'vulna backup verify <bundle>',
            how_to_restore: 'vulna backup restore <bundle>',
            warning: 'Keep a recent, VERIFIED, encrypted backup off-host. Data cannot be recovered.',
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

  it('warns about backups and shows the CLI commands', async () => {
    render(
      <AuthProvider>
        <BackupCenterPage />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText(/Keep a recent, VERIFIED/)).toBeInTheDocument());
    expect(screen.getByText(/vulna backup verify/)).toBeInTheDocument();
    expect(screen.getByText(/s3-compatible/)).toBeInTheDocument();
  });
});
