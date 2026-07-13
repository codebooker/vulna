import { useCallback, useEffect, useMemo, useState } from 'react';
import { ClipboardCheck, KanbanSquare, Rows3 } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useToast } from '../lib/toast';
import { formatWhenFull, humanize } from '../lib/utils';
import {
  normalizeSeverity,
  PriorityBadge,
  SeverityBadge,
  StatusBadge,
} from '../components/app/badges';
import { DataTable, type ColumnDef, type FilterDef } from '../components/app/data-table';
import { PageHeader } from '../components/app/page-header';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { EmptyState, InlineError, TableSkeleton } from '../components/ui/states';
import { Segmented } from '../components/ui/tabs';
import type { Finding } from '../types/finding';

/** Remediation work items are the actionable findings themselves (assigned,
 *  in verification, or awaiting triage). Everything here is live data; the
 *  only actions offered are ones the findings API actually supports. */

const WORK_STATUSES = ['new', 'assigned', 'ready_for_verification', 'verified_fixed'] as const;
type WorkStatus = (typeof WORK_STATUSES)[number];

const COLUMN_LABEL: Record<WorkStatus, string> = {
  new: 'To triage',
  assigned: 'In progress',
  ready_for_verification: 'Verifying',
  verified_fixed: 'Done',
};

function isWorkStatus(s: string): s is WorkStatus {
  return (WORK_STATUSES as readonly string[]).includes(s);
}

/** Estimated risk reduction if this finding is fixed (CVSS-weighted). */
function riskReduction(f: Finding): number {
  const sevWeight = { critical: 40, high: 25, medium: 10, low: 4, info: 1 }[
    normalizeSeverity(f.severity)
  ];
  return Math.round(sevWeight * (f.known_exploited ? 1.5 : 1));
}

export function RemediationPage() {
  const { token, user } = useAuth();
  const { toast } = useToast();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<'table' | 'kanban'>('table');
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const page = await api.listAllFindings(token);
      setFindings(page.items.filter((f) => isWorkStatus(f.status)));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load remediation work.');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const act = async (f: Finding, patch: Record<string, unknown>, success: string) => {
    if (!token) return;
    setBusy(f.id);
    setError(null);
    try {
      await api.updateFinding(token, f.id, patch);
      if (patch.status === 'ready_for_verification') await api.rescanFinding(token, f.id);
      await load();
      toast('success', success);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed.');
    } finally {
      setBusy(null);
    }
  };

  const actionsFor = (f: Finding) => (
    <span className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
      {f.status === 'new' && (
        <Button
          size="sm"
          variant="ghost"
          disabled={busy === f.id}
          onClick={() =>
            void act(f, { status: 'assigned', owner_user_id: user?.id }, 'Assigned to you.')
          }
        >
          Assign to me
        </Button>
      )}
      {(f.status === 'new' || f.status === 'assigned') && (
        <Button
          size="sm"
          variant="ghost"
          disabled={busy === f.id}
          onClick={() =>
            void act(
              f,
              { status: 'ready_for_verification' },
              'Re-check queued — closes automatically when verified.',
            )
          }
        >
          Mark fixed
        </Button>
      )}
    </span>
  );

  const columns: ColumnDef<Finding>[] = useMemo(
    () => [
      {
        id: 'task',
        header: 'Task',
        cell: (f) => (
          <span className="block max-w-80 truncate font-medium text-text" title={f.title}>
            {f.title}
          </span>
        ),
        sortValue: (f) => f.title,
        csvValue: (f) => f.title,
      },
      {
        id: 'severity',
        header: 'Severity',
        cell: (f) => <SeverityBadge severity={f.severity} />,
        sortValue: (f) =>
          ['info', 'low', 'medium', 'high', 'critical'].indexOf(normalizeSeverity(f.severity)),
        csvValue: (f) => f.severity,
      },
      {
        id: 'priority',
        header: 'Priority',
        cell: (f) => <PriorityBadge priority={f.priority} />,
        sortValue: (f) => ['informational', 'watch', 'plan', 'fix_now'].indexOf(f.priority),
        csvValue: (f) => f.priority,
      },
      {
        id: 'asset',
        header: 'Affected asset',
        cell: (f) =>
          f.asset_id ? (
            <span className="font-mono text-xs text-muted">{f.asset_id.slice(0, 12)}</span>
          ) : (
            <span className="text-faint">—</span>
          ),
        sortValue: (f) => f.asset_id ?? '',
        csvValue: (f) => f.asset_id ?? '',
      },
      {
        id: 'owner',
        header: 'Owner',
        cell: (f) =>
          f.owner_user_id ? (
            f.owner_user_id === user?.id ? (
              <Badge tone="accent">You</Badge>
            ) : (
              <span className="font-mono text-xs text-muted">{f.owner_user_id.slice(0, 8)}</span>
            )
          ) : (
            <span className="text-faint">Unassigned</span>
          ),
        sortValue: (f) => f.owner_user_id ?? '',
        csvValue: (f) => f.owner_user_id ?? '',
      },
      {
        id: 'risk',
        header: 'Est. risk reduction',
        cell: (f) => <span className="text-xs font-medium text-ok">−{riskReduction(f)} pts</span>,
        sortValue: (f) => riskReduction(f),
        csvValue: (f) => String(riskReduction(f)),
        align: 'right',
      },
      {
        id: 'status',
        header: 'Status',
        cell: (f) => <StatusBadge status={f.status} />,
        sortValue: (f) => WORK_STATUSES.indexOf(f.status as WorkStatus),
        csvValue: (f) => f.status,
      },
      {
        id: 'verified',
        header: 'Last verified',
        defaultHidden: true,
        cell: (f) => (
          <span className="text-xs text-muted">{formatWhenFull(f.last_verified_at)}</span>
        ),
        sortValue: (f) => f.last_verified_at ?? '',
        csvValue: (f) => f.last_verified_at ?? '',
      },
      { id: 'actions', header: 'Actions', align: 'right', cell: actionsFor },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [user?.id, busy],
  );

  const filters: FilterDef<Finding>[] = useMemo(
    () => [
      {
        id: 'status',
        label: 'Status',
        options: WORK_STATUSES.map((s) => ({ value: s, label: COLUMN_LABEL[s] })),
        predicate: (f, v) => f.status === v,
      },
      {
        id: 'severity',
        label: 'Severity',
        options: ['critical', 'high', 'medium', 'low'].map((s) => ({
          value: s,
          label: humanize(s),
        })),
        predicate: (f, v) => normalizeSeverity(f.severity) === v,
      },
      {
        id: 'owner',
        label: 'Owner',
        options: [
          { value: 'me', label: 'Assigned to me' },
          { value: 'unassigned', label: 'Unassigned' },
        ],
        predicate: (f, v) =>
          v === 'me' ? f.owner_user_id === user?.id : v === 'unassigned' ? !f.owner_user_id : true,
      },
    ],
    [user?.id],
  );

  return (
    <div aria-label="Remediation">
      <PageHeader
        crumbs={[{ label: 'Management' }, { label: 'Remediation' }]}
        title="Remediation"
        description="Actionable findings as a work queue — assign, fix, and verify."
        actions={
          <Segmented
            ariaLabel="View"
            options={[
              { id: 'table', label: <Rows3 size={14} aria-label="Table view" />, title: 'Table' },
              {
                id: 'kanban',
                label: <KanbanSquare size={14} aria-label="Board view" />,
                title: 'Board',
              },
            ]}
            value={view}
            onChange={(v) => setView(v as 'table' | 'kanban')}
          />
        }
      />

      {error && <InlineError message={error} className="mb-3" />}

      {view === 'table' ? (
        <DataTable<Finding>
          columns={columns}
          rows={findings}
          rowKey={(f) => f.id}
          searchText={(f) => `${f.title} ${f.id}`}
          searchPlaceholder="Search tasks…"
          filters={filters}
          loading={loading}
          error={null}
          emptyTitle="No remediation work"
          emptyDescription="Actionable findings appear here as a triage-to-done work queue."
          exportName="remediation"
          storageKey="vulnadash.remediation"
          defaultSort={{ id: 'priority', dir: 'desc' }}
        />
      ) : loading ? (
        <Card>
          <TableSkeleton rows={4} cols={4} />
        </Card>
      ) : findings.length === 0 ? (
        <Card>
          <EmptyState
            icon={ClipboardCheck}
            title="No remediation work"
            description="Actionable findings appear here as a triage-to-done work queue."
          />
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
          {WORK_STATUSES.map((status) => {
            const cards = findings.filter((f) => f.status === status);
            return (
              <div
                key={status}
                className="flex flex-col rounded-xl border border-border bg-surface-2/50 p-2"
              >
                <div className="mb-2 flex items-center justify-between px-1">
                  <p className="text-xs font-semibold uppercase tracking-wide text-muted">
                    {COLUMN_LABEL[status]}
                  </p>
                  <span className="rounded-full bg-surface-3 px-1.5 text-[11px] text-muted">
                    {cards.length}
                  </span>
                </div>
                <div className="flex min-h-24 flex-col gap-2">
                  {cards.length === 0 ? (
                    <p className="py-4 text-center text-[11px] text-faint">Empty</p>
                  ) : (
                    cards.map((f) => (
                      <Card key={f.id} className="p-3">
                        <p className="mb-1.5 line-clamp-2 text-[13px] font-medium leading-snug text-text">
                          {f.title}
                        </p>
                        <div className="mb-2 flex flex-wrap items-center gap-1.5">
                          <SeverityBadge severity={f.severity} />
                          {f.owner_user_id === user?.id && <Badge tone="accent">You</Badge>}
                          <span className="ml-auto text-[11px] font-medium text-ok">
                            −{riskReduction(f)} pts
                          </span>
                        </div>
                        {(f.status === 'new' || f.status === 'assigned') && (
                          <div className="flex gap-1">
                            {f.status === 'new' && (
                              <Button
                                size="sm"
                                variant="outline"
                                className="flex-1 justify-center"
                                disabled={busy === f.id}
                                onClick={() =>
                                  void act(
                                    f,
                                    { status: 'assigned', owner_user_id: user?.id },
                                    'Assigned to you.',
                                  )
                                }
                              >
                                Assign to me
                              </Button>
                            )}
                            <Button
                              size="sm"
                              variant="outline"
                              className="flex-1 justify-center"
                              disabled={busy === f.id}
                              onClick={() =>
                                void act(
                                  f,
                                  { status: 'ready_for_verification' },
                                  'Re-check queued.',
                                )
                              }
                            >
                              Mark fixed
                            </Button>
                          </div>
                        )}
                      </Card>
                    ))
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
