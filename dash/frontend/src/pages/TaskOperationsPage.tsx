import { useCallback, useEffect, useState } from 'react';
import { RefreshCw, RotateCcw, XCircle } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { PageHeader, SectionHeader } from '../components/app/page-header';
import { InlineError } from '../components/ui/states';
import type { BackgroundTask, TaskHealth } from '../types/task';

const terminal = new Set(['completed', 'cancelled', 'dead_letter']);

function tone(status: string): 'neutral' | 'ok' | 'warn' | 'bad' {
  if (status === 'completed' || status === 'leader' || status === 'idle') return 'ok';
  if (status === 'retry' || status === 'queued' || status === 'backpressure') return 'warn';
  if (status === 'dead_letter' || status === 'lease_lost') return 'bad';
  return 'neutral';
}

export function TaskOperationsPage() {
  const { token, user } = useAuth();
  const [tasks, setTasks] = useState<BackgroundTask[]>([]);
  const [health, setHealth] = useState<TaskHealth | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const canManage = user?.permissions
    ? user.permissions.includes('tasks.manage')
    : user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    setError(null);
    try {
      const [page, status] = await Promise.all([api.listTasks(token), api.taskHealth(token)]);
      setTasks(page.items);
      setHealth(status);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load task operations.');
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const act = async (task: BackgroundTask, action: 'retry' | 'cancel') => {
    if (!token) return;
    setBusy(task.id);
    setError(null);
    try {
      if (action === 'retry') await api.retryTask(token, task.id);
      else await api.cancelTask(token, task.id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to ${action} task.`);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div aria-label="Task operations">
      <PageHeader
        crumbs={[{ label: 'Administration' }, { label: 'Task operations' }]}
        title="Task operations"
        description="Durable scheduler and worker health, retries, leases, and dead letters."
        actions={
          <Button variant="outline" onClick={() => void load()}>
            <RefreshCw size={14} aria-hidden /> Refresh
          </Button>
        }
      />
      {error && <InlineError className="mb-3" message={error} />}

      <SectionHeader title="Services" />
      <Card className="mb-4 divide-y divide-border">
        {!health || health.workers.length === 0 ? (
          <p className="px-4 py-4 text-xs text-muted">No worker heartbeat has been recorded.</p>
        ) : (
          health.workers.map((worker) => (
            <div key={worker.id} className="flex items-center gap-3 px-4 py-3 text-xs">
              <Badge tone={tone(worker.status)}>{worker.status}</Badge>
              <span className="font-medium text-text">{worker.kind}</span>
              <span className="text-muted">{worker.worker_id}</span>
              <span className="ml-auto text-muted">
                {new Date(worker.last_seen_at).toLocaleString()}
              </span>
            </div>
          ))
        )}
      </Card>

      <SectionHeader title={`History (${tasks.length})`} />
      <Card className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-border text-muted">
            <tr>
              <th className="px-4 py-2 font-medium">Task</th>
              <th className="px-3 py-2 font-medium">Status</th>
              <th className="px-3 py-2 font-medium">Attempts</th>
              <th className="px-3 py-2 font-medium">Scheduled</th>
              <th className="px-4 py-2 text-right font-medium">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {tasks.map((task) => (
              <tr key={task.id}>
                <td className="px-4 py-2.5">
                  <p className="font-medium text-text">{task.task_type}</p>
                  {task.last_error && (
                    <p className="max-w-xl truncate text-danger">{task.last_error}</p>
                  )}
                </td>
                <td className="px-3 py-2.5">
                  <Badge tone={tone(task.status)}>{task.status}</Badge>
                </td>
                <td className="px-3 py-2.5 text-muted">
                  {task.attempts}/{task.max_attempts}
                </td>
                <td className="px-3 py-2.5 text-muted">
                  {new Date(task.scheduled_at).toLocaleString()}
                </td>
                <td className="px-4 py-2.5">
                  <div className="flex justify-end gap-1.5">
                    {canManage &&
                      (task.status === 'dead_letter' || task.status === 'cancelled') && (
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={busy === task.id}
                          onClick={() => void act(task, 'retry')}
                        >
                          <RotateCcw size={12} aria-hidden /> Retry
                        </Button>
                      )}
                    {canManage && !terminal.has(task.status) && (
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={busy === task.id}
                        onClick={() => void act(task, 'cancel')}
                      >
                        <XCircle size={12} aria-hidden /> Cancel
                      </Button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
            {tasks.length === 0 && (
              <tr>
                <td className="px-4 py-5 text-center text-muted" colSpan={5}>
                  No tasks have been queued.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
