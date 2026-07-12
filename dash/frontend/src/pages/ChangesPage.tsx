import { useCallback, useEffect, useMemo, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { formatWhenFull, humanize } from '../lib/utils';
import { SeverityBadge } from '../components/app/badges';
import { DataTable, type ColumnDef, type FilterDef } from '../components/app/data-table';
import { PageHeader } from '../components/app/page-header';
import type { ChangeEvent } from '../types/inventory';

const LABELS: Record<string, string> = {
  asset_discovered: 'Asset discovered',
  asset_disappeared: 'Asset disappeared',
  ip_changed: 'IP changed',
  new_port_opened: 'Port opened',
  port_closed: 'Port closed',
  service_version_changed: 'Version changed',
};

/** Activity: what changed and when, as a filterable table. */
export function ChangesPage() {
  const { token, logout } = useAuth();
  const [changes, setChanges] = useState<ChangeEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const page = await api.listChanges(token, 200);
      setChanges(page.items);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        logout();
        return;
      }
      setError(err instanceof Error ? err.message : 'Failed to load changes.');
    } finally {
      setLoading(false);
    }
  }, [token, logout]);

  useEffect(() => {
    void load();
  }, [load]);

  const columns: ColumnDef<ChangeEvent>[] = useMemo(
    () => [
      {
        id: 'event',
        header: 'Event',
        cell: (c) => (
          <span className="font-medium text-text">
            {LABELS[c.event_type] ?? humanize(c.event_type)}
          </span>
        ),
        sortValue: (c) => c.event_type,
        csvValue: (c) => c.event_type,
      },
      {
        id: 'summary',
        header: 'Summary',
        cell: (c) => <span className="text-[13px] text-text">{c.summary}</span>,
        sortValue: (c) => c.summary,
        csvValue: (c) => c.summary,
      },
      {
        id: 'severity',
        header: 'Severity',
        cell: (c) => <SeverityBadge severity={c.severity} />,
        sortValue: (c) => c.severity,
        csvValue: (c) => c.severity,
      },
      {
        id: 'asset',
        header: 'Asset',
        defaultHidden: true,
        cell: (c) =>
          c.asset_id ? (
            <span className="font-mono text-xs text-muted">{c.asset_id.slice(0, 12)}</span>
          ) : (
            <span className="text-faint">—</span>
          ),
        sortValue: (c) => c.asset_id ?? '',
        csvValue: (c) => c.asset_id ?? '',
      },
      {
        id: 'when',
        header: 'When',
        cell: (c) => <span className="text-xs text-muted">{formatWhenFull(c.created_at)}</span>,
        sortValue: (c) => c.created_at,
        csvValue: (c) => c.created_at,
      },
    ],
    [],
  );

  const filters: FilterDef<ChangeEvent>[] = useMemo(
    () => [
      {
        id: 'type',
        label: 'Event type',
        options: [...new Set(changes.map((c) => c.event_type))].map((t) => ({
          value: t,
          label: LABELS[t] ?? humanize(t),
        })),
        predicate: (c, v) => c.event_type === v,
      },
    ],
    [changes],
  );

  return (
    <div aria-label="Activity">
      <PageHeader
        crumbs={[{ label: 'Operations' }, { label: 'Activity' }]}
        title="Activity"
        description="What changed across your environment, newest first."
      />
      <DataTable<ChangeEvent>
        columns={columns}
        rows={changes}
        rowKey={(c) => c.id}
        searchText={(c) => `${c.summary} ${c.event_type}`}
        searchPlaceholder="Search activity…"
        filters={filters}
        loading={loading}
        error={error}
        onRetry={() => void load()}
        emptyTitle="No changes yet"
        emptyDescription="Run an assessment to populate the delta view."
        exportName="activity"
        storageKey="vulnadash.activity"
        defaultSort={{ id: 'when', dir: 'desc' }}
      />
    </div>
  );
}
