import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AuthProvider } from '../src/auth/AuthProvider';
import { TaskOperationsPage } from '../src/pages/TaskOperationsPage';

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

const task = (id: string, status: string, type: string) => ({
  id,
  organization_id: 'org-1',
  task_type: type,
  payload_json: {},
  idempotency_key: `key-${id}`,
  status,
  priority: 100,
  scheduled_at: '2026-07-13T00:00:00Z',
  attempts: status === 'dead_letter' ? 5 : 1,
  max_attempts: 5,
  lease_owner: null,
  lease_expires_at: null,
  started_at: null,
  completed_at: null,
  cancel_requested_at: null,
  cancelled_at: null,
  dead_lettered_at: status === 'dead_letter' ? '2026-07-13T00:01:00Z' : null,
  last_error: status === 'dead_letter' ? 'RuntimeError: unavailable' : null,
  result_json: {},
  created_at: '2026-07-13T00:00:00Z',
  updated_at: '2026-07-13T00:00:00Z',
});

beforeEach(() => {
  localStorage.setItem('vulna.token', 'access-token');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/api/v1/auth/me')) {
        return jsonResponse({
          id: 'admin-1',
          email: 'admin@example.com',
          full_name: 'Admin',
          role: 'administrator',
          organization_id: 'org-1',
          is_active: true,
          permissions: ['tasks.read', 'tasks.manage'],
        });
      }
      if (url.includes('/api/v1/tasks?')) {
        return jsonResponse({
          items: [
            task('task-1', 'dead_letter', 'feeds.sync'),
            task('task-2', 'running', 'system.sweep'),
          ],
          total: 2,
          limit: 100,
          offset: 0,
        });
      }
      if (url.endsWith('/api/v1/tasks/health')) {
        return jsonResponse({
          counts: { running: 1, dead_letter: 1 },
          stale_after_seconds: 300,
          workers: [
            {
              id: 'heartbeat-1',
              worker_id: 'worker:host:1',
              kind: 'worker',
              hostname: 'host',
              process_id: 1,
              status: 'idle',
              current_task_id: null,
              started_at: '2026-07-13T00:00:00Z',
              last_seen_at: '2026-07-13T00:02:00Z',
              metadata_json: {},
            },
          ],
        });
      }
      if (url.endsWith('/retry') && init?.method === 'POST') {
        return jsonResponse(task('task-1', 'queued', 'feeds.sync'));
      }
      if (url.endsWith('/cancel') && init?.method === 'POST') {
        return jsonResponse(task('task-2', 'running', 'system.sweep'));
      }
      return jsonResponse({ detail: 'not found' });
    }),
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

it('shows worker health and exposes dead-letter retry and running cancellation', async () => {
  render(
    <AuthProvider>
      <TaskOperationsPage />
    </AuthProvider>,
  );

  expect(await screen.findByText('worker:host:1')).toBeInTheDocument();
  expect(screen.getByText('feeds.sync')).toBeInTheDocument();
  expect(screen.getByText('RuntimeError: unavailable')).toBeInTheDocument();

  fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
  await waitFor(() =>
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/tasks/task-1/retry'),
      expect.objectContaining({ method: 'POST' }),
    ),
  );
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  await waitFor(() =>
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/tasks/task-2/cancel'),
      expect.objectContaining({ method: 'POST' }),
    ),
  );
});
