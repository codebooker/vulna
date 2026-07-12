import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { CalendarClock, Crosshair, Play, Plus, Radar } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useNav } from '../lib/nav';
import { useToast } from '../lib/toast';
import { formatRelative, formatWhen, humanize } from '../lib/utils';
import { StatusBadge } from '../components/app/badges';
import { DataTable, type ColumnDef } from '../components/app/data-table';
import { PageHeader } from '../components/app/page-header';
import { Button } from '../components/ui/button';
import { Field, Input, Select } from '../components/ui/input';
import { ConfirmDialog, Modal } from '../components/ui/overlay';
import { EmptyState, InlineError } from '../components/ui/states';
import { Tabs } from '../components/ui/tabs';
import type { Network } from '../types/network';
import type { ProbeSummary } from '../types/onboarding';
import type { Job, ScanSchedule } from '../types/schedule';

const PRESETS: { label: string; minutes: number }[] = [
  { label: 'Every 6 hours', minutes: 360 },
  { label: 'Daily', minutes: 1440 },
  { label: 'Weekly', minutes: 10080 },
];

const ACTIVE_STATES = ['queued', 'offered', 'accepted', 'running'];
const FAILED_STATES = ['failed', 'cancelled', 'expired', 'rejected_by_probe'];

function intervalLabel(minutes: number): string {
  const preset = PRESETS.find((p) => p.minutes === minutes);
  if (preset) return preset.label;
  if (minutes % 1440 === 0) return `Every ${minutes / 1440} days`;
  if (minutes % 60 === 0) return `Every ${minutes / 60} hours`;
  return `Every ${minutes} minutes`;
}

/** Scans: one-off scan jobs (Running / Completed / Failed) and recurring
 *  Schedules, in tabs. A manual scan runs immediately on a chosen Scout; a
 *  schedule runs recurring assessments of a network's bound Scout. */
export function ScansPage() {
  const { token, user, logout } = useAuth();
  const { current } = useNav();
  const { toast } = useToast();
  const [schedules, setSchedules] = useState<ScanSchedule[]>([]);
  const [networks, setNetworks] = useState<Network[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [probes, setProbes] = useState<ProbeSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState(current.params.tab ?? 'running');
  const [scheduleOpen, setScheduleOpen] = useState(false);
  const [scanOpen, setScanOpen] = useState(false);
  const [toDelete, setToDelete] = useState<ScanSchedule | null>(null);
  const [busy, setBusy] = useState(false);

  const isOperator = user?.role === 'administrator' || user?.role === 'security_operator';

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [scheds, nets, jobPage, probePage] = await Promise.all([
        api.listSchedules(token),
        api.listNetworks(token).catch(() => []),
        api.listJobs(token, undefined, 200).catch(() => null),
        api.listProbes(token).catch(() => null),
      ]);
      setSchedules(scheds);
      setNetworks(nets);
      setJobs(jobPage?.items ?? []);
      setProbes(probePage?.items ?? []);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        logout();
        return;
      }
      setError(err instanceof Error ? err.message : 'Failed to load scans.');
    } finally {
      setLoading(false);
    }
  }, [token, logout]);

  useEffect(() => {
    void load();
  }, [load]);

  // Auto-refresh while scans are active so progress is visible.
  const hasActive = jobs.some((j) => ACTIVE_STATES.includes(j.status));
  useEffect(() => {
    if (!hasActive) return;
    const t = setInterval(() => void load(), 5000);
    return () => clearInterval(t);
  }, [hasActive, load]);

  const netName = useCallback(
    (id: string) => networks.find((n) => n.id === id)?.name ?? id.slice(0, 8),
    [networks],
  );
  const probeName = useCallback(
    (id: string) => probes.find((p) => p.id === id)?.name ?? id.slice(0, 8),
    [probes],
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

  const runningJobs = jobs.filter((j) => ACTIVE_STATES.includes(j.status));
  const completedJobs = jobs.filter((j) => j.status === 'completed');
  const failedJobs = jobs.filter((j) => FAILED_STATES.includes(j.status));
  const scheduled = [...schedules].sort((a, b) => Number(b.enabled) - Number(a.enabled));

  const counts = {
    running: runningJobs.length,
    scheduled: scheduled.length,
    completed: completedJobs.length,
    failed: failedJobs.length,
  };

  const jobColumns: ColumnDef<Job>[] = useMemo(
    () => [
      {
        id: 'targets',
        header: 'Targets',
        cell: (j) => (
          <span className="font-mono text-xs text-text">
            {j.requested_targets_json.join(', ') || '—'}
          </span>
        ),
        sortValue: (j) => j.requested_targets_json.join(', '),
        csvValue: (j) => j.requested_targets_json.join(' '),
      },
      {
        id: 'scout',
        header: 'Scout',
        cell: (j) => <span className="text-xs text-muted">{probeName(j.probe_id)}</span>,
        sortValue: (j) => probeName(j.probe_id),
        csvValue: (j) => probeName(j.probe_id),
      },
      {
        id: 'mode',
        header: 'Mode',
        defaultHidden: true,
        cell: (j) => <span className="text-xs text-muted">{humanize(j.mode)}</span>,
        sortValue: (j) => j.mode,
        csvValue: (j) => j.mode,
      },
      {
        id: 'status',
        header: 'Status',
        cell: (j) => <StatusBadge status={j.status} />,
        sortValue: (j) => j.status,
        csvValue: (j) => j.status,
      },
      {
        id: 'started',
        header: 'Started',
        cell: (j) => <span className="text-xs text-muted">{formatRelative(j.started_at)}</span>,
        sortValue: (j) => j.started_at ?? j.created_at,
        csvValue: (j) => j.started_at ?? '',
      },
      {
        id: 'finished',
        header: 'Finished',
        defaultHidden: true,
        cell: (j) => <span className="text-xs text-muted">{formatRelative(j.finished_at)}</span>,
        sortValue: (j) => j.finished_at ?? '',
        csvValue: (j) => j.finished_at ?? '',
      },
      {
        id: 'error',
        header: 'Error',
        defaultHidden: true,
        cell: (j) =>
          j.error_message ? (
            <span className="block max-w-56 truncate text-xs text-bad" title={j.error_message}>
              {j.error_message}
            </span>
          ) : (
            <span className="text-faint">—</span>
          ),
        csvValue: (j) => j.error_message ?? '',
      },
      {
        id: 'actions',
        header: 'Actions',
        align: 'right',
        cell: (j) =>
          isOperator && ACTIVE_STATES.includes(j.status) ? (
            <span className="flex items-center justify-end" onClick={(e) => e.stopPropagation()}>
              <Button
                size="sm"
                variant="ghost"
                className="text-bad"
                disabled={busy}
                onClick={() => void act(() => api.cancelJob(token!, j.id), 'Scan cancelled.')}
              >
                Cancel
              </Button>
            </span>
          ) : null,
      },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [probeName, isOperator, busy, token],
  );

  const scheduleColumns: ColumnDef<ScanSchedule>[] = useMemo(
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

  const jobRows: Record<string, Job[]> = {
    running: runningJobs,
    completed: completedJobs,
    failed: failedJobs,
  };

  return (
    <div aria-label="Scans">
      <PageHeader
        crumbs={[{ label: 'Operations' }, { label: 'Scans' }]}
        title="Scans"
        description="Run a one-off scan on a Scout now, or schedule recurring assessments of a network. Intrusive runs stay manual and need approval."
        actions={
          isOperator && (
            <div className="flex items-center gap-2">
              <Button variant="ghost" onClick={() => setScheduleOpen(true)}>
                <CalendarClock size={14} aria-hidden /> New schedule
              </Button>
              <Button variant="primary" onClick={() => setScanOpen(true)}>
                <Crosshair size={14} aria-hidden /> New scan
              </Button>
            </div>
          )
        }
      />

      {error && <InlineError message={error} className="mb-3" />}

      <Tabs
        className="mb-3"
        tabs={[
          { id: 'running', label: 'Running', count: counts.running },
          { id: 'scheduled', label: 'Scheduled', count: counts.scheduled },
          { id: 'completed', label: 'Completed', count: counts.completed },
          { id: 'failed', label: 'Failed', count: counts.failed },
        ]}
        value={tab}
        onChange={setTab}
      />

      {tab === 'scheduled' ? (
        <DataTable<ScanSchedule>
          columns={scheduleColumns}
          rows={scheduled}
          rowKey={(s) => s.id}
          searchText={(s) => `${s.name} ${netName(s.network_id)}`}
          searchPlaceholder="Search schedules…"
          loading={loading}
          error={null}
          emptyTitle="No scheduled scans yet"
          emptyDescription="Create a schedule to run recurring assessments of a network."
          emptyAction={
            isOperator ? (
              <Button variant="primary" size="sm" onClick={() => setScheduleOpen(true)}>
                <Plus size={13} aria-hidden /> New schedule
              </Button>
            ) : undefined
          }
          exportName="scan-schedules"
          storageKey="vulnadash.schedules"
        />
      ) : (
        <DataTable<Job>
          columns={jobColumns}
          rows={jobRows[tab] ?? []}
          rowKey={(j) => j.id}
          searchText={(j) =>
            `${j.requested_targets_json.join(' ')} ${probeName(j.probe_id)} ${j.status}`
          }
          searchPlaceholder="Search scans…"
          loading={loading}
          error={null}
          emptyTitle={
            tab === 'running'
              ? 'No scans running'
              : tab === 'completed'
                ? 'No completed scans yet'
                : 'No failed scans'
          }
          emptyDescription={
            tab === 'running'
              ? 'Start a one-off scan with “New scan”, or run a schedule.'
              : tab === 'completed'
                ? 'Completed scans appear here with their results.'
                : 'Scan failures show up here with their error message.'
          }
          emptyAction={
            tab === 'running' && isOperator ? (
              <Button variant="primary" size="sm" onClick={() => setScanOpen(true)}>
                <Crosshair size={13} aria-hidden /> New scan
              </Button>
            ) : undefined
          }
          exportName={`scans-${tab}`}
          storageKey="vulnadash.scans"
          defaultSort={{ id: 'started', dir: 'desc' }}
        />
      )}

      {isOperator && (
        <>
          <CreateScanModal
            open={scanOpen}
            networks={networks}
            onClose={() => setScanOpen(false)}
            onCreated={() => {
              setScanOpen(false);
              setTab('running');
              void load();
            }}
          />
          <CreateScheduleModal
            open={scheduleOpen}
            networks={networks}
            onClose={() => setScheduleOpen(false)}
            onCreated={() => {
              setScheduleOpen(false);
              setTab('scheduled');
              void load();
            }}
          />
        </>
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

function CreateScanModal({
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
  const [targets, setTargets] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const net = networks.find((n) => n.id === networkId) ?? null;
  const scout = net ? (net.scouts.find((s) => s.is_primary) ?? net.scouts[0] ?? null) : null;

  const pickNetwork = (id: string) => {
    setNetworkId(id);
    const n = networks.find((x) => x.id === id);
    setTargets(n ? n.ranges.map((r) => r.cidr).join(', ') : '');
    setError(null);
  };

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    const list = targets
      .split(/[\s,]+/)
      .map((t) => t.trim())
      .filter(Boolean);
    if (!token || !net) return;
    if (!scout) {
      setError('This network has no bound Scout. Bind one on the Networks page first.');
      return;
    }
    if (list.length === 0) {
      setError('Enter at least one target.');
      return;
    }
    setError(null);
    setSubmitting(true);
    try {
      await api.createJob(token, scout.probe_id, list);
      setNetworkId('');
      setTargets('');
      toast('success', 'Scan started.');
      onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start the scan.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Run a scan"
      description="A one-off vulnerability assessment of a network, run now by its bound Scout."
    >
      {networks.length === 0 ? (
        <EmptyState
          compact
          icon={Radar}
          title="No networks yet"
          description="Create a network with a bound Scout and approved ranges first — scans run against a network."
        />
      ) : (
        <form className="flex flex-col gap-3" onSubmit={handleSubmit}>
          <Field label="Network" htmlFor="scan-network">
            <Select
              id="scan-network"
              value={networkId}
              onChange={(e) => pickNetwork(e.target.value)}
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
          {net && (
            <p className="text-xs text-muted">
              {scout ? (
                <>
                  Runs on <span className="text-text">{scout.probe_name}</span>.
                </>
              ) : (
                <span className="text-warn">
                  No bound Scout — bind one on the Networks page first.
                </span>
              )}
            </p>
          )}
          <Field
            label="Targets"
            htmlFor="scan-targets"
            hint="Defaults to the network's ranges. Edit to narrow; must stay within an approved scope."
          >
            <Input
              id="scan-targets"
              value={targets}
              onChange={(e) => setTargets(e.target.value)}
              placeholder="e.g. 10.0.0.0/24, 192.168.1.5"
              required
            />
          </Field>
          {error && <InlineError message={error} />}
          <div className="mt-1 flex justify-end gap-2">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={submitting} disabled={!net || !scout}>
              {submitting ? 'Starting…' : 'Start scan'}
            </Button>
          </div>
        </form>
      )}
    </Modal>
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
