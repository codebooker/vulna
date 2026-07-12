import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { CalendarClock, Play, Plus, Radar } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useNav } from '../lib/nav';
import { useToast } from '../lib/toast';
import { formatWhen } from '../lib/utils';
import { StatusBadge } from '../components/app/badges';
import { DataTable, type ColumnDef } from '../components/app/data-table';
import { PageHeader } from '../components/app/page-header';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { Field, Input, Select } from '../components/ui/input';
import { ConfirmDialog, Modal } from '../components/ui/overlay';
import { EmptyState, InlineError } from '../components/ui/states';
import { Tabs } from '../components/ui/tabs';
import type { Network } from '../types/network';
import type { ScanSchedule } from '../types/schedule';

const PRESETS: { label: string; minutes: number }[] = [
  { label: 'Every 6 hours', minutes: 360 },
  { label: 'Daily', minutes: 1440 },
  { label: 'Weekly', minutes: 10080 },
];

function intervalLabel(minutes: number): string {
  const preset = PRESETS.find((p) => p.minutes === minutes);
  if (preset) return preset.label;
  if (minutes % 1440 === 0) return `Every ${minutes / 1440} days`;
  if (minutes % 60 === 0) return `Every ${minutes / 60} hours`;
  return `Every ${minutes} minutes`;
}

/** Scans: scheduled scans in tabs (Running / Scheduled / Completed / Failed),
 *  with creation moved into a modal. Recurring runs are executed by the
 *  network's bound Scout; intrusive runs stay manual. */
export function ScansPage() {
  const { token, user, logout } = useAuth();
  const { current } = useNav();
  const { toast } = useToast();
  const [schedules, setSchedules] = useState<ScanSchedule[]>([]);
  const [networks, setNetworks] = useState<Network[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState(current.params.tab ?? 'scheduled');
  const [createOpen, setCreateOpen] = useState(false);
  const [toDelete, setToDelete] = useState<ScanSchedule | null>(null);
  const [busy, setBusy] = useState(false);

  const isOperator = user?.role === 'administrator' || user?.role === 'security_operator';

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [scheds, nets] = await Promise.all([api.listSchedules(token), api.listNetworks(token)]);
      setSchedules(scheds);
      setNetworks(nets);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        logout();
        return;
      }
      setError(err instanceof Error ? err.message : 'Failed to load schedules.');
    } finally {
      setLoading(false);
    }
  }, [token, logout]);

  useEffect(() => {
    void load();
  }, [load]);

  const netName = useCallback(
    (id: string) => networks.find((n) => n.id === id)?.name ?? id.slice(0, 8),
    [networks],
  );

  const act = async (fn: () => Promise<unknown>, success: string) => {
    if (!token) return;
    setError(null);
    setBusy(true);
    try {
      await fn();
      await load();
      toast('success', success);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed.');
    } finally {
      setBusy(false);
    }
  };

  const scheduled = schedules.filter((s) => s.enabled && !s.last_error);
  const failed = schedules.filter((s) => s.last_error);
  const completed = schedules.filter((s) => s.last_run_at && !s.last_error);
  const paused = schedules.filter((s) => !s.enabled);

  const tabRows: Record<string, ScanSchedule[]> = {
    running: [], // No live-jobs API yet; active jobs will appear here when it lands.
    scheduled: [...scheduled, ...paused],
    completed,
    failed,
  };

  const columns: ColumnDef<ScanSchedule>[] = useMemo(
    () => [
      {
        id: 'name',
        header: 'Scan name',
        cell: (s) => <span className="font-medium text-text">{s.name}</span>,
        sortValue: (s) => s.name,
        csvValue: (s) => s.name,
      },
      {
        id: 'network',
        header: 'Target network',
        cell: (s) => <span className="text-xs text-muted">{netName(s.network_id)}</span>,
        sortValue: (s) => netName(s.network_id),
        csvValue: (s) => netName(s.network_id),
      },
      {
        id: 'mode',
        header: 'Profile',
        defaultHidden: true,
        cell: (s) => <span className="text-xs text-muted">{s.mode.replace(/_/g, ' ')}</span>,
        sortValue: (s) => s.mode,
        csvValue: (s) => s.mode,
      },
      {
        id: 'cadence',
        header: 'Cadence',
        cell: (s) => (
          <span className="text-xs text-muted">
            {intervalLabel(s.interval_minutes)}
            {!s.enabled && <span className="ml-1.5 text-warn">(paused)</span>}
          </span>
        ),
        sortValue: (s) => s.interval_minutes,
        csvValue: (s) => intervalLabel(s.interval_minutes),
      },
      {
        id: 'next',
        header: 'Next run',
        cell: (s) => (
          <span className="text-xs text-muted">{s.enabled ? formatWhen(s.next_run_at) : '—'}</span>
        ),
        sortValue: (s) => (s.enabled ? s.next_run_at : ''),
        csvValue: (s) => (s.enabled ? s.next_run_at : ''),
      },
      {
        id: 'last',
        header: 'Last run',
        cell: (s) => <span className="text-xs text-muted">{formatWhen(s.last_run_at)}</span>,
        sortValue: (s) => s.last_run_at ?? '',
        csvValue: (s) => s.last_run_at ?? '',
      },
      {
        id: 'status',
        header: 'Status',
        cell: (s) => (
          <StatusBadge
            status={
              s.last_error
                ? 'failed'
                : !s.enabled
                  ? 'paused'
                  : s.last_run_at
                    ? 'completed'
                    : 'pending'
            }
          />
        ),
        sortValue: (s) => (s.last_error ? 'failed' : s.enabled ? 'ok' : 'paused'),
        csvValue: (s) => (s.last_error ? 'failed' : s.enabled ? 'enabled' : 'paused'),
      },
      {
        id: 'error',
        header: 'Last error',
        defaultHidden: true,
        cell: (s) =>
          s.last_error ? (
            <span className="block max-w-56 truncate text-xs text-bad" title={s.last_error}>
              {s.last_error}
            </span>
          ) : (
            <span className="text-faint">—</span>
          ),
        csvValue: (s) => s.last_error ?? '',
      },
      {
        id: 'actions',
        header: 'Actions',
        align: 'right',
        cell: (s) =>
          isOperator ? (
            <span
              className="flex items-center justify-end gap-1"
              onClick={(e) => e.stopPropagation()}
            >
              <Button
                size="sm"
                variant="ghost"
                title="Run now"
                disabled={busy}
                onClick={() => void act(() => api.runSchedule(token!, s.id), `“${s.name}” queued.`)}
              >
                <Play size={12} aria-hidden /> Run
              </Button>
              <Button
                size="sm"
                variant="ghost"
                disabled={busy}
                onClick={() =>
                  void act(
                    () => api.updateSchedule(token!, s.id, { enabled: !s.enabled }),
                    s.enabled ? `“${s.name}” paused.` : `“${s.name}” resumed.`,
                  )
                }
              >
                {s.enabled ? 'Pause' : 'Resume'}
              </Button>
              <Button
                size="sm"
                variant="ghost"
                className="text-bad"
                disabled={busy}
                onClick={() => setToDelete(s)}
              >
                Delete
              </Button>
            </span>
          ) : null,
      },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [netName, isOperator, busy, token],
  );

  return (
    <div aria-label="Scans">
      <PageHeader
        crumbs={[{ label: 'Operations' }, { label: 'Scans' }]}
        title="Scans"
        description="Recurring, unattended assessments run by each network's bound Scout. Intrusive runs stay manual and need approval."
        actions={
          isOperator && (
            <Button variant="primary" onClick={() => setCreateOpen(true)}>
              <Plus size={14} aria-hidden /> New schedule
            </Button>
          )
        }
      />

      {error && <InlineError message={error} className="mb-3" />}

      <Tabs
        className="mb-3"
        tabs={[
          { id: 'running', label: 'Running', count: tabRows.running.length },
          { id: 'scheduled', label: 'Scheduled', count: tabRows.scheduled.length },
          { id: 'completed', label: 'Completed', count: tabRows.completed.length },
          { id: 'failed', label: 'Failed', count: tabRows.failed.length },
        ]}
        value={tab}
        onChange={setTab}
      />

      {tab === 'running' ? (
        <Card>
          <EmptyState
            icon={Radar}
            title="No scans running right now"
            description="Active scans appear here with live progress while they run. Use “Run” on a scheduled scan to start one."
          />
        </Card>
      ) : (
        <DataTable<ScanSchedule>
          columns={columns}
          rows={tabRows[tab] ?? []}
          rowKey={(s) => s.id}
          searchText={(s) => `${s.name} ${netName(s.network_id)}`}
          searchPlaceholder="Search scans…"
          loading={loading}
          error={null}
          emptyTitle={
            tab === 'failed'
              ? 'No failed scans'
              : tab === 'completed'
                ? 'No completed scans yet'
                : 'No scheduled scans yet'
          }
          emptyDescription={
            tab === 'scheduled'
              ? 'Create a schedule to run recurring assessments of a network.'
              : tab === 'failed'
                ? 'Scan failures show up here with their error message.'
                : 'Completed runs appear here after their first execution.'
          }
          emptyAction={
            tab === 'scheduled' && isOperator ? (
              <Button variant="primary" size="sm" onClick={() => setCreateOpen(true)}>
                <Plus size={13} aria-hidden /> New schedule
              </Button>
            ) : undefined
          }
          exportName={`scans-${tab}`}
          storageKey="vulnadash.scans"
        />
      )}

      {isOperator && (
        <CreateScheduleModal
          open={createOpen}
          networks={networks}
          onClose={() => setCreateOpen(false)}
          onCreated={() => {
            setCreateOpen(false);
            void load();
          }}
        />
      )}

      <ConfirmDialog
        open={toDelete !== null}
        onClose={() => setToDelete(null)}
        destructive
        busy={busy}
        title={`Delete schedule “${toDelete?.name}”?`}
        body="The recurring scan stops immediately. Past results are not affected."
        confirmLabel="Delete schedule"
        onConfirm={() => {
          if (toDelete) {
            void act(() => api.deleteSchedule(token!, toDelete.id), 'Schedule deleted.').then(() =>
              setToDelete(null),
            );
          }
        }}
      />
    </div>
  );
}

function CreateScheduleModal({
  open,
  networks,
  onClose,
  onCreated,
}: {
  open: boolean;
  networks: Network[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const { token } = useAuth();
  const { toast } = useToast();
  const [networkId, setNetworkId] = useState('');
  const [name, setName] = useState('');
  const [minutes, setMinutes] = useState(1440);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!token || !networkId || !name) return;
    setError(null);
    setSubmitting(true);
    try {
      await api.createSchedule(token, { network_id: networkId, name, interval_minutes: minutes });
      setName('');
      setNetworkId('');
      toast('success', 'Schedule created.');
      onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create schedule.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Add a schedule"
      description="Recurring, unattended vulnerability assessment of a network, run by its bound Scout."
    >
      {networks.length === 0 ? (
        <EmptyState
          compact
          icon={CalendarClock}
          title="No networks available"
          description="Create a network with a bound scout first — schedules run against a network."
        />
      ) : (
        <form className="flex flex-col gap-3" onSubmit={handleSubmit}>
          <Field label="Network" htmlFor="sched-network">
            <Select
              id="sched-network"
              value={networkId}
              onChange={(e) => setNetworkId(e.target.value)}
              required
            >
              <option value="">Choose a network…</option>
              {networks.map((n) => (
                <option key={n.id} value={n.id}>
                  {n.name}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Name" htmlFor="sched-name">
            <Input
              id="sched-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Nightly HQ sweep"
              required
            />
          </Field>
          <Field label="Cadence" htmlFor="sched-cadence">
            <Select
              id="sched-cadence"
              value={minutes}
              onChange={(e) => setMinutes(Number(e.target.value))}
            >
              {PRESETS.map((p) => (
                <option key={p.minutes} value={p.minutes}>
                  {p.label}
                </option>
              ))}
            </Select>
          </Field>
          {error && <InlineError message={error} />}
          <div className="mt-1 flex justify-end gap-2">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={submitting}>
              {submitting ? 'Creating…' : 'Create schedule'}
            </Button>
          </div>
        </form>
      )}
    </Modal>
  );
}

/** Backwards-compatible export (older imports/tests may reference SchedulesPage). */
export { ScansPage as SchedulesPage };
