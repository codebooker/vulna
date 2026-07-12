import { useCallback, useEffect, useMemo, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useToast } from '../lib/toast';
import { formatWhenFull } from '../lib/utils';
import { StatusBadge } from '../components/app/badges';
import { DataTable, type ColumnDef } from '../components/app/data-table';
import { PageHeader } from '../components/app/page-header';
import { Button } from '../components/ui/button';
import type { FeedHealth, FeedStatus } from '../types/intelligence';

const SOURCE_LABELS: Record<string, string> = {
  nvd: 'NVD (CVE)',
  kev: 'CISA KEV',
  epss: 'EPSS',
};

const STATUS_LABELS: Record<FeedStatus, string> = {
  ok: 'OK',
  degraded: 'Degraded',
  failed: 'Failed',
  stale: 'Stale',
  never_synced: 'Never synced',
};

/** Threat-intelligence feed health: NVD, CISA KEV, and EPSS sync status. */
export function FeedsPage() {
  const { token, user, logout } = useAuth();
  const { toast } = useToast();
  const [feeds, setFeeds] = useState<FeedHealth[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [syncing, setSyncing] = useState<string | null>(null);

  const isAdmin = user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      setFeeds(await api.listFeedHealth(token));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        logout();
        return;
      }
      setError(err instanceof Error ? err.message : 'Failed to load feed health.');
    } finally {
      setLoading(false);
    }
  }, [token, logout]);

  useEffect(() => {
    void load();
  }, [load]);

  const sync = useCallback(
    async (source: string) => {
      if (!token) return;
      setSyncing(source);
      setError(null);
      try {
        await api.syncFeed(token, source);
        await load();
        toast('success', `${SOURCE_LABELS[source] ?? source} synced.`);
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          logout();
          return;
        }
        setError(err instanceof Error ? err.message : `Failed to sync ${source}.`);
      } finally {
        setSyncing(null);
      }
    },
    [token, logout, load, toast],
  );

  const columns: ColumnDef<FeedHealth>[] = useMemo(
    () => [
      {
        id: 'source',
        header: 'Source',
        cell: (f) => (
          <span className="font-medium text-text">{SOURCE_LABELS[f.source] ?? f.source}</span>
        ),
        sortValue: (f) => f.source,
        csvValue: (f) => f.source,
      },
      {
        id: 'status',
        header: 'Status',
        cell: (f) => (
          <span>
            <StatusBadge status={STATUS_LABELS[f.status] ?? f.status} />
            {f.error && <span className="mt-0.5 block text-[11px] text-bad">{f.error}</span>}
          </span>
        ),
        sortValue: (f) => f.status,
        csvValue: (f) => f.status,
      },
      {
        id: 'lastSync',
        header: 'Last successful sync',
        cell: (f) => (
          <span className="text-xs text-muted">{formatWhenFull(f.last_success_at)}</span>
        ),
        sortValue: (f) => f.last_success_at ?? '',
        csvValue: (f) => f.last_success_at ?? '',
      },
      {
        id: 'records',
        header: 'Records',
        cell: (f) => (
          <span className="text-xs tabular-nums text-muted">
            {f.records_processed.toLocaleString()}
          </span>
        ),
        sortValue: (f) => f.records_processed,
        csvValue: (f) => String(f.records_processed),
        align: 'right',
      },
      {
        id: 'actions',
        header: 'Actions',
        align: 'right',
        cell: (f) =>
          isAdmin ? (
            <Button
              size="sm"
              variant="outline"
              disabled={syncing === f.source}
              onClick={(e) => {
                e.stopPropagation();
                void sync(f.source);
              }}
            >
              <RefreshCw
                size={12}
                aria-hidden
                className={syncing === f.source ? 'animate-spin' : ''}
              />
              {syncing === f.source ? 'Syncing…' : 'Sync now'}
            </Button>
          ) : null,
      },
    ],
    [isAdmin, syncing, sync],
  );

  return (
    <div aria-label="Threat intelligence feeds">
      <PageHeader
        crumbs={[{ label: 'Administration' }, { label: 'CVE feeds' }]}
        title="Threat intelligence feeds"
        description="NVD, CISA KEV, and EPSS keep prioritization current. Sync happens automatically; force one here if needed."
      />
      <DataTable<FeedHealth>
        columns={columns}
        rows={feeds}
        rowKey={(f) => f.source}
        loading={loading}
        error={error}
        onRetry={() => void load()}
        emptyTitle="No feed data"
        emptyDescription="Feed health appears once the intelligence service starts."
        exportName="feeds"
      />
    </div>
  );
}
