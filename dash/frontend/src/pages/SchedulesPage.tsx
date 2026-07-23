import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { CalendarClock, Crosshair, FileText, Play, Plus, Radar } from 'lucide-react';
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
import { Progress } from '../components/ui/misc';
import type { Network } from '../types/network';
import type { ProbeSummary } from '../types/onboarding';
import type { Preset } from '../types/presets';
import type { Job, JobDiagnostics, ScanSchedule } from '../types/schedule';

const CADENCE_PRESETS: { label: string; minutes: number }[] = [
  { label: 'Every 6 hours', minutes: 360 },
  { label: 'Daily', minutes: 1440 },
  { label: 'Weekly', minutes: 10080 },
];

const ACTIVE_STATES = ['queued', 'offered', 'accepted', 'running'];
const FAILED_STATES = ['failed', 'cancelled', 'expired', 'rejected_by_probe'];

function intervalLabel(minutes: number): string {
  const preset = CADENCE_PRESETS.find((p) => p.minutes === minutes);
  if (preset) return preset.label;
  if (minutes % 1440 === 0) return `Every ${minutes / 1440} days`;
  if (minutes % 60 === 0) return `Every ${minutes / 60} hours`;
  return `Every ${minutes} minutes`;
}

function remainingLabel(estimatedAt: string | null): string | null {
  if (!estimatedAt) return null;
  const seconds = Math.round((new Date(estimatedAt).getTime() - Date.now()) / 1000);
  if (seconds <= 0) return 'estimate elapsed; scan still running';
  if (seconds < 60) return 'less than a minute remaining';
  const minutes = Math.ceil(seconds / 60);
  if (minutes < 60) return `about ${minutes} min remaining`;
  const hours = Math.floor(minutes / 60);
  const remainder = minutes % 60;
  return `about ${hours}h${remainder ? ` ${remainder}m` : ''} remaining`;
}

function elapsedLabel(job: Job): string {
  const reported = job.progress_json?.elapsed_seconds ?? 0;
  const sinceReport =
    ACTIVE_STATES.includes(job.status) && job.last_progress_at
      ? Math.max(0, Math.round((Date.now() - new Date(job.last_progress_at).getTime()) / 1000))
      : 0;
  const seconds = reported + sinceReport;
  if (seconds < 60) return `${seconds}s elapsed`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m elapsed`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m elapsed`;
}

function durationLabel(seconds: number | undefined): string | null {
  if (!seconds || !Number.isFinite(seconds) || seconds <= 0) return null;
  const hours = seconds / 3600;
  return Number.isInteger(hours) ? `${hours}h` : `${Math.round(seconds / 60)}m`;
}

function executionDeadline(job: Job): string | null {
  if (!job.started_at || !job.max_duration_seconds || job.max_duration_seconds <= 0) return null;
  const signedExpiry = new Date(job.expires_at).getTime();
  const durationExpiry =
    new Date(job.started_at).getTime() + job.max_duration_seconds * 1000;
  return new Date(Math.min(signedExpiry, durationExpiry)).toISOString();
}

/** Scans: one-off scan jobs (Running / Completed / Failed) and recurring
 *  Schedules, in tabs. A manual scan runs immediately on a chosen Scout; a
 *  schedule runs recurring assessments of a network's bound Scout. */
export function ScansPage() {
  const { token, user, logout } = useAuth();
  const { current, go } = useNav();
  const { toast } = useToast();
  const [schedules, setSchedules] = useState<ScanSchedule[]>([]);
  const [networks, setNetworks] = useState<Network[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [probes, setProbes] = useState<ProbeSummary[]>([]);
  const [scanPresets, setScanPresets] = useState<Preset[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState(current.params.tab ?? 'running');
  const [scheduleOpen, setScheduleOpen] = useState(false);
  const [scanOpen, setScanOpen] = useState(false);
  const [toDelete, setToDelete] = useState<ScanSchedule | null>(null);
  const [busy, setBusy] = useState(false);
  const [diagnosticJob, setDiagnosticJob] = useState<Job | null>(null);
  const [diagnostics, setDiagnostics] = useState<JobDiagnostics | null>(null);
  const [diagnosticsLoading, setDiagnosticsLoading] = useState(false);
  const [diagnosticsError, setDiagnosticsError] = useState<string | null>(null);

  const isOperator =
    user?.permissions !== undefined
      ? user.permissions.includes('jobs.manage')
      : user?.role === 'administrator' || user?.role === 'security_operator';
  const canGenerateReports = user?.permissions
    ? user.permissions.includes('reports.create')
    : user?.role === 'administrator' || user?.role === 'security_operator';

  const load = useCallback(
    async (silent = false) => {
      if (!token) return;
      // Background polls and post-action refreshes update in place; only the
      // first load shows the skeleton, so the table doesn't flicker every 5s.
      if (!silent) setLoading(true);
      try {
        const [scheds, nets, jobPage, probePage, presetPage] = await Promise.all([
          api.listSchedules(token),
          api.listNetworks(token).catch(() => []),
          api.listAllJobs(token).catch(() => null),
          api.listProbes(token).catch(() => null),
          api.listPresets(token).catch(() => ({ presets: [] })),
        ]);
        setSchedules(scheds);
        setNetworks(nets);
        setJobs(jobPage?.items ?? []);
        setProbes(probePage?.items ?? []);
        setScanPresets(presetPage.presets);
        setError(null);
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          logout();
          return;
        }
        setError(err instanceof Error ? err.message : 'Failed to load scans.');
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [token, logout],
  );

  useEffect(() => {
    void load();
  }, [load]);

  // Auto-refresh while scans are active so progress is visible.
  const hasActive = jobs.some((j) => ACTIVE_STATES.includes(j.status));
  useEffect(() => {
    if (!hasActive) return;
    const t = setInterval(() => void load(true), 5000);
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
      await load(true);
      toast('success', success);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed.');
    } finally {
      setBusy(false);
    }
  };

  const generateReport = useCallback(
    async (jobId: string) => {
      if (!token) return;
      setBusy(true);
      setError(null);
      try {
        await api.createReports(token, jobId, ['executive_pdf', 'technical_pdf', 'findings_csv']);
        toast('success', 'Report generated. Opening Reports…');
        go('reports');
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to generate report.');
      } finally {
        setBusy(false);
      }
    },
    [token, go, toast],
  );

  const showDiagnostics = useCallback(
    async (job: Job) => {
      if (!token) return;
      setDiagnosticJob(job);
      setDiagnostics(null);
      setDiagnosticsError(null);
      setDiagnosticsLoading(true);
      try {
        setDiagnostics(await api.jobDiagnostics(token, job.id));
      } catch (err) {
        setDiagnosticsError(
          err instanceof Error ? err.message : 'Failed to load scan diagnostics.',
        );
      } finally {
        setDiagnosticsLoading(false);
      }
    },
    [token],
  );

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

  useEffect(() => {
    const jobId = current.params.job;
    if (!jobId) return;
    const job = jobs.find((item) => item.id === jobId);
    if (!job) return;
    setTab(
      ACTIVE_STATES.includes(job.status)
        ? 'running'
        : job.status === 'completed'
          ? 'completed'
          : 'failed',
    );
    if (FAILED_STATES.includes(job.status)) void showDiagnostics(job);
  }, [current.params.job, jobs, showDiagnostics]);

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
        id: 'progress',
        header: 'Progress',
        cell: (j) => {
          const stats = j.progress_json ?? {};
          const completed = stats.stages_completed ?? 0;
          const total = stats.stages_total ?? 0;
          const remaining = remainingLabel(j.estimated_completion_at);
          const deadline = executionDeadline(j);
          const signedLimit = durationLabel(j.max_duration_seconds);
          return (
            <div className="w-52" aria-label={`Scan ${j.progress_percent}% complete`}>
              <div className="mb-1 flex items-center justify-between gap-2 text-[11px]">
                <span className="font-medium text-text">{j.progress_percent}%</span>
                <span className="truncate text-muted">
                  {stats.current_stage ? humanize(stats.current_stage) : humanize(j.status)}
                </span>
              </div>
              <Progress
                value={j.progress_percent}
                tone={j.status === 'failed' ? 'bad' : j.status === 'completed' ? 'ok' : 'accent'}
                label={`Scan progress: ${j.progress_percent}%`}
              />
              <div className="mt-1 text-[10px] leading-4 text-muted">
                <div>
                  {total > 0 ? `${completed} of ${total} stages` : 'Waiting for stage data'}
                </div>
                <div>
                  {stats.target_addresses ?? j.requested_targets_json.length} address
                  {(stats.target_addresses ?? j.requested_targets_json.length) === 1
                    ? ''
                    : 'es'} · {elapsedLabel(j)}
                </div>
                {remaining && <div>{remaining}</div>}
                {signedLimit && (
                  <div>
                    Signed limit {signedLimit}
                    {deadline ? ` · deadline ${formatWhen(deadline)}` : ''}
                  </div>
                )}
                {(stats.stages_failed ?? 0) + (stats.stages_skipped ?? 0) > 0 && (
                  <div className="text-warn">
                    {stats.stages_failed ?? 0} failed · {stats.stages_skipped ?? 0} skipped
                  </div>
                )}
              </div>
            </div>
          );
        },
        sortValue: (j) => j.progress_percent,
        csvValue: (j) => `${j.progress_percent}%`,
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
          !isOperator ? null : ACTIVE_STATES.includes(j.status) ? (
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
          ) : j.status === 'completed' && canGenerateReports ? (
            <span className="flex items-center justify-end" onClick={(e) => e.stopPropagation()}>
              <Button
                size="sm"
                variant="ghost"
                disabled={busy}
                title="Generate a report from this scan"
                onClick={() => void generateReport(j.id)}
              >
                <FileText size={12} aria-hidden /> Report
              </Button>
            </span>
          ) : FAILED_STATES.includes(j.status) ? (
            <span className="flex items-center justify-end" onClick={(e) => e.stopPropagation()}>
              <Button
                size="sm"
                variant="ghost"
                disabled={diagnosticsLoading && diagnosticJob?.id === j.id}
                onClick={() => void showDiagnostics(j)}
              >
                Diagnostics
              </Button>
            </span>
          ) : null,
      },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [
      probeName,
      isOperator,
      canGenerateReports,
      busy,
      token,
      generateReport,
      diagnosticsLoading,
      diagnosticJob?.id,
      showDiagnostics,
    ],
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
          rows={
            current.params.job
              ? (jobRows[tab] ?? []).filter((job) => job.id === current.params.job)
              : (jobRows[tab] ?? [])
          }
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
            presets={scanPresets}
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
            presets={scanPresets}
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

      <Modal
        open={diagnosticJob !== null}
        onClose={() => setDiagnosticJob(null)}
        title="Scan diagnostics"
        description={
          diagnosticJob
            ? `Sanitized diagnostics for ${diagnosticJob.requested_targets_json.join(', ')}`
            : undefined
        }
        wide
      >
        {diagnosticsLoading ? (
          <p className="text-sm text-muted">Loading scan diagnostics…</p>
        ) : diagnosticsError ? (
          <InlineError message={diagnosticsError} />
        ) : diagnostics?.failures.length ? (
          <div className="space-y-3">
            {diagnostics.failures.map((failure, index) => (
              <section
                key={`${failure.received_at}-${index}`}
                className="rounded-lg border border-border bg-surface-2 p-3"
              >
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="font-mono font-medium text-bad">{failure.code}</span>
                  {failure.stage && <span className="text-muted">Stage: {failure.stage}</span>}
                  {failure.plugin && <span className="text-muted">Scanner: {failure.plugin}</span>}
                  <span className="ml-auto text-faint">{formatWhen(failure.received_at)}</span>
                </div>
                <p className="mt-2 break-words font-mono text-xs leading-relaxed text-text">
                  {failure.message}
                </p>
              </section>
            ))}
          </div>
        ) : (
          <p className="text-sm text-muted">
            No structured Scout diagnostic was recorded for this scan. The summary error is{' '}
            {diagnosticJob?.error_message ?? 'unavailable'}.
          </p>
        )}
      </Modal>
    </div>
  );
}

function CreateScanModal({
  open,
  networks,
  presets,
  onClose,
  onCreated,
}: {
  open: boolean;
  networks: Network[];
  presets: Preset[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const { token } = useAuth();
  const { toast } = useToast();
  const [networkId, setNetworkId] = useState('');
  const [targets, setTargets] = useState('');
  const [presetKey, setPresetKey] = useState('standard');
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
      await api.createJob(token, scout.probe_id, list, net.id, presetKey);
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
          <Field
            label="Scan profile"
            htmlFor="scan-preset"
            hint="Quick is fastest; Standard adds safe vulnerability, TLS, and passive web checks."
          >
            <Select
              id="scan-preset"
              value={presetKey}
              onChange={(e) => setPresetKey(e.target.value)}
            >
              {(presets.length
                ? presets
                : [{ key: 'standard', name: 'Standard Security Check' }]
              ).map((preset) => (
                <option key={preset.key} value={preset.key}>
                  {preset.name}
                </option>
              ))}
            </Select>
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
  presets,
  onClose,
  onCreated,
}: {
  open: boolean;
  networks: Network[];
  presets: Preset[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const { token } = useAuth();
  const { toast } = useToast();
  const [networkId, setNetworkId] = useState('');
  const [name, setName] = useState('');
  const [minutes, setMinutes] = useState(1440);
  const [presetKey, setPresetKey] = useState('standard');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!token || !networkId || !name) return;
    setError(null);
    setSubmitting(true);
    try {
      await api.createSchedule(token, {
        network_id: networkId,
        name,
        interval_minutes: minutes,
        preset_key: presetKey,
      });
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
              {CADENCE_PRESETS.map((p) => (
                <option key={p.minutes} value={p.minutes}>
                  {p.label}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Scan profile" htmlFor="sched-preset">
            <Select
              id="sched-preset"
              value={presetKey}
              onChange={(e) => setPresetKey(e.target.value)}
            >
              {(presets.length
                ? presets
                : [{ key: 'standard', name: 'Standard Security Check' }]
              ).map((preset) => (
                <option key={preset.key} value={preset.key}>
                  {preset.name}
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
