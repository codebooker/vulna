import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AuthProvider } from '../src/auth/AuthProvider';
import { ScansPage } from '../src/pages/SchedulesPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const baseJob = {
  site_id: 'site-1',
  probe_id: 'probe-1',
  mode: 'vulnerability_assessment',
  requested_targets_json: ['192.0.2.0/24'],
  max_duration_seconds: 8 * 60 * 60,
  not_before: '2026-07-13T00:00:00Z',
  expires_at: '2026-07-13T03:00:00Z',
  created_by: 'admin-1',
  started_at: '2026-07-13T00:00:00Z',
  finished_at: null,
  error_code: null,
  error_message: null,
  summary_json: {},
  last_progress_at: '2026-07-13T00:01:00Z',
  created_at: '2026-07-13T00:00:00Z',
};

beforeEach(() => {
  localStorage.setItem('vulna.token', 'access-token');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/api/v1/auth/me')) {
        return jsonResponse({
          id: 'admin-1',
          email: 'admin@example.com',
          full_name: 'Admin',
          role: 'administrator',
          organization_id: 'org-1',
          is_active: true,
          permissions: ['jobs.read', 'jobs.manage', 'jobs.create'],
        });
      }
      if (url.endsWith('/api/v1/schedules')) return jsonResponse([]);
      if (url.endsWith('/api/v1/networks')) return jsonResponse([]);
      if (url.includes('/api/v1/probes?')) {
        return jsonResponse({
          items: [{ id: 'probe-1', name: 'Scout One' }],
          total: 1,
          limit: 100,
          offset: 0,
        });
      }
      if (url.includes('/api/v1/jobs?')) {
        return jsonResponse({
          items: [
            {
              ...baseJob,
              id: 'job-running',
              status: 'running',
              progress_percent: 33,
              progress_json: {
                percent: 33,
                current_stage: 'vulnerability',
                current_plugin: 'nuclei',
                stages_total: 3,
                stages_completed: 1,
                stages_run: 1,
                stages_failed: 0,
                stages_skipped: 0,
                target_groups: 1,
                target_addresses: 256,
                elapsed_seconds: 60,
              },
              estimated_completion_at: new Date(Date.now() + 5 * 60_000).toISOString(),
            },
            {
              ...baseJob,
              id: 'job-failed',
              status: 'failed',
              progress_percent: 66,
              progress_json: {
                stages_total: 3,
                stages_completed: 2,
                current_stage: 'tls',
              },
              estimated_completion_at: null,
              error_code: 'scanner_error',
              error_message: 'TLS scanner failed',
              finished_at: '2026-07-13T00:02:00Z',
            },
          ],
          total: 2,
          limit: 200,
          offset: 0,
        });
      }
      if (url.endsWith('/api/v1/jobs/job-failed/diagnostics')) {
        return jsonResponse({
          job_id: 'job-failed',
          status: 'failed',
          error_code: 'scanner_error',
          error_message: 'TLS scanner failed',
          failures: [
            {
              code: 'scanner_error',
              stage: 'tls',
              plugin: 'testssl',
              message: 'testssl exited with status 2',
              received_at: '2026-07-13T00:02:00Z',
            },
          ],
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

it('shows live percent, stage statistics, ETA, and operator failure diagnostics', async () => {
  render(
    <AuthProvider>
      <ScansPage />
    </AuthProvider>,
  );

  expect(await screen.findByText('33%')).toBeInTheDocument();
  expect(screen.getByText('1 of 3 stages')).toBeInTheDocument();
  expect(screen.getByText(/256 addresses · .* elapsed/)).toBeInTheDocument();
  expect(screen.getByText('about 5 min remaining')).toBeInTheDocument();
  expect(screen.getByText(/Signed limit 8h · deadline/)).toBeInTheDocument();
  expect(screen.getByRole('progressbar', { name: 'Scan progress: 33%' })).toHaveAttribute(
    'aria-valuenow',
    '33',
  );

  fireEvent.click(screen.getByRole('tab', { name: /Failed/ }));
  fireEvent.click(await screen.findByRole('button', { name: 'Diagnostics' }));
  expect(await screen.findByText('testssl exited with status 2')).toBeInTheDocument();
  expect(screen.getByText('Stage: tls')).toBeInTheDocument();
  expect(screen.getByText('Scanner: testssl')).toBeInTheDocument();
  await waitFor(() =>
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/jobs/job-failed/diagnostics'),
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: 'Bearer access-token' }),
      }),
    ),
  );
});
