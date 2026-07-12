import { useCallback, useEffect, useMemo, useState } from 'react';
import { ChevronRight, Server } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useNav } from '../lib/nav';
import { formatRelative, formatWhenFull, humanize } from '../lib/utils';
import { normalizeSeverity, SeverityBadge, StatusBadge } from '../components/app/badges';
import { DataTable, type ColumnDef, type FilterDef } from '../components/app/data-table';
import { PageHeader } from '../components/app/page-header';
import { Badge } from '../components/ui/badge';
import { DetailRow } from '../components/ui/misc';
import { Drawer } from '../components/ui/overlay';
import type { Asset, Site } from '../types/inventory';
import type { Finding } from '../types/finding';

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Asset inventory, from the live `/assets` API. Per-asset critical/high counts
 *  are derived from open findings so the columns reflect real risk. */
interface AssetRow extends Asset {
  critical: number;
  high: number;
  findingTotal: number;
}

export function AssetsPage() {
  const { token } = useAuth();
  const { current, go } = useNav();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AssetRow | null>(null);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [a, s, f] = await Promise.all([
        api.listAssets(token),
        api.listSites(token),
        api.listFindings(token, 500).catch(() => null),
      ]);
      setAssets(a.items);
      setSites(s.items);
      setFindings(f?.items ?? []);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load assets.');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const siteName = useCallback(
    (id: string) => sites.find((s) => s.id === id)?.name ?? '—',
    [sites],
  );

  const rows: AssetRow[] = useMemo(() => {
    const counts = new Map<string, { critical: number; high: number; total: number }>();
    for (const f of findings) {
      if (!f.asset_id || f.resolved_at !== null) continue;
      const cur = counts.get(f.asset_id) ?? { critical: 0, high: 0, total: 0 };
      const sev = normalizeSeverity(f.severity);
      if (sev === 'critical') cur.critical += 1;
      if (sev === 'high') cur.high += 1;
      cur.total += 1;
      counts.set(f.asset_id, cur);
    }
    return assets.map((a) => {
      const c = counts.get(a.id) ?? { critical: 0, high: 0, total: 0 };
      return { ...a, critical: c.critical, high: c.high, findingTotal: c.total };
    });
  }, [assets, findings]);

  // Open findings for the asset in the drawer, worst severity first.
  const assetFindings = useMemo(() => {
    if (!selected) return [];
    return findings
      .filter((f) => f.asset_id === selected.id && f.resolved_at === null)
      .sort(
        (a, b) =>
          (SEV_ORDER[normalizeSeverity(a.severity)] ?? 9) -
          (SEV_ORDER[normalizeSeverity(b.severity)] ?? 9),
      );
  }, [findings, selected]);

  const columns: ColumnDef<AssetRow>[] = useMemo(
    () => [
      {
        id: 'name',
        header: 'Name',
        cell: (a) => <span className="font-medium text-text">{a.canonical_name}</span>,
        sortValue: (a) => a.canonical_name,
        csvValue: (a) => a.canonical_name,
      },
      {
        id: 'type',
        header: 'Type',
        cell: (a) => <Badge tone="neutral">{humanize(a.asset_type)}</Badge>,
        sortValue: (a) => a.asset_type,
        csvValue: (a) => a.asset_type,
      },
      {
        id: 'os',
        header: 'Operating system',
        cell: (a) => <span className="text-xs text-muted">{a.operating_system ?? '—'}</span>,
        sortValue: (a) => a.operating_system ?? '',
        csvValue: (a) => a.operating_system ?? '',
      },
      {
        id: 'manufacturer',
        header: 'Manufacturer',
        defaultHidden: true,
        cell: (a) => <span className="text-xs text-muted">{a.manufacturer ?? '—'}</span>,
        sortValue: (a) => a.manufacturer ?? '',
        csvValue: (a) => a.manufacturer ?? '',
      },
      {
        id: 'site',
        header: 'Site',
        cell: (a) => <span className="text-xs text-muted">{siteName(a.site_id)}</span>,
        sortValue: (a) => siteName(a.site_id),
        csvValue: (a) => siteName(a.site_id),
      },
      {
        id: 'critical',
        header: 'Critical',
        align: 'right',
        cell: (a) =>
          a.critical > 0 ? (
            <Badge tone="critical">{a.critical} Critical</Badge>
          ) : (
            <span className="text-faint">0</span>
          ),
        sortValue: (a) => a.critical,
        csvValue: (a) => String(a.critical),
      },
      {
        id: 'high',
        header: 'High',
        align: 'right',
        cell: (a) =>
          a.high > 0 ? (
            <Badge tone="high">{a.high} High</Badge>
          ) : (
            <span className="text-faint">0</span>
          ),
        sortValue: (a) => a.high,
        csvValue: (a) => String(a.high),
      },
      {
        id: 'confidence',
        header: 'Confidence',
        defaultHidden: true,
        align: 'right',
        cell: (a) => (
          <span className="text-xs tabular-nums text-muted">{a.identity_confidence}%</span>
        ),
        sortValue: (a) => a.identity_confidence,
        csvValue: (a) => String(a.identity_confidence),
      },
      {
        id: 'lastSeen',
        header: 'Last seen',
        cell: (a) => <span className="text-xs text-muted">{formatRelative(a.last_seen_at)}</span>,
        sortValue: (a) => a.last_seen_at ?? '',
        csvValue: (a) => a.last_seen_at ?? '',
      },
      {
        id: 'lastAssessed',
        header: 'Last assessed',
        defaultHidden: true,
        cell: (a) => (
          <span className="text-xs text-muted">{formatRelative(a.last_assessed_at)}</span>
        ),
        sortValue: (a) => a.last_assessed_at ?? '',
        csvValue: (a) => a.last_assessed_at ?? '',
      },
      {
        id: 'status',
        header: 'Status',
        cell: (a) => <StatusBadge status={a.status} />,
        sortValue: (a) => a.status,
        csvValue: (a) => a.status,
      },
    ],
    [siteName],
  );

  const filters: FilterDef<AssetRow>[] = useMemo(
    () => [
      {
        id: 'site',
        label: 'Site',
        options: sites.map((s) => ({ value: s.id, label: s.name })),
        predicate: (a, v) => a.site_id === v,
      },
      {
        id: 'status',
        label: 'Status',
        options: [...new Set(rows.map((r) => r.status))].map((s) => ({
          value: s,
          label: humanize(s),
        })),
        predicate: (a, v) => a.status === v,
      },
      {
        id: 'type',
        label: 'Type',
        options: [...new Set(rows.map((r) => r.asset_type))].map((t) => ({
          value: t,
          label: humanize(t),
        })),
        predicate: (a, v) => a.asset_type === v,
      },
      {
        id: 'attention',
        label: 'Attention',
        options: [{ value: 'attention', label: 'Has critical or high findings' }],
        predicate: (a, v) => (v === 'attention' ? a.critical > 0 || a.high > 0 : true),
      },
    ],
    [sites, rows],
  );

  const preFiltered =
    current.params.filter === 'attention' ? rows.filter((a) => a.critical > 0 || a.high > 0) : rows;

  return (
    <div aria-label="Assets">
      <PageHeader
        crumbs={[{ label: 'Operations' }, { label: 'Assets' }]}
        title="Assets"
        description="Searchable inventory of everything Vulna has seen on your networks."
      />

      <DataTable<AssetRow>
        columns={columns}
        rows={preFiltered}
        rowKey={(a) => a.id}
        searchText={(a) =>
          `${a.canonical_name} ${a.operating_system ?? ''} ${a.manufacturer ?? ''}`
        }
        searchPlaceholder="Search name, OS, manufacturer…"
        filters={filters}
        onRowClick={setSelected}
        selectable
        loading={loading}
        error={error}
        onRetry={() => void load()}
        emptyTitle="No assets discovered yet"
        emptyDescription="Assets appear automatically after your first assessment approves a scope and a scan runs."
        exportName="assets"
        storageKey="vulnadash.assets"
        defaultSort={{ id: 'lastSeen', dir: 'desc' }}
      />

      <Drawer
        open={selected !== null}
        onClose={() => setSelected(null)}
        title={
          selected ? (
            <span className="flex items-center gap-2">
              <Server size={15} className="shrink-0 text-accent" aria-hidden />
              {selected.canonical_name}
            </span>
          ) : (
            ''
          )
        }
        description={selected ? siteName(selected.site_id) : undefined}
      >
        {selected && (
          <div className="flex flex-col gap-4">
            <div className="flex flex-wrap items-center gap-1.5">
              <StatusBadge status={selected.status} />
              {selected.critical > 0 && <Badge tone="critical">{selected.critical} Critical</Badge>}
              {selected.high > 0 && <Badge tone="high">{selected.high} High</Badge>}
            </div>
            <dl className="divide-y divide-border rounded-lg border border-border px-3">
              <DetailRow label="Type">{humanize(selected.asset_type)}</DetailRow>
              <DetailRow label="Operating system">{selected.operating_system ?? '—'}</DetailRow>
              <DetailRow label="Manufacturer">{selected.manufacturer ?? '—'}</DetailRow>
              <DetailRow label="Site">{siteName(selected.site_id)}</DetailRow>
              <DetailRow label="Identity confidence">{selected.identity_confidence}%</DetailRow>
              <DetailRow label="Open findings">{selected.findingTotal}</DetailRow>
              <DetailRow label="First seen">{formatWhenFull(selected.first_seen_at)}</DetailRow>
              <DetailRow label="Last seen">{formatWhenFull(selected.last_seen_at)}</DetailRow>
              <DetailRow label="Last assessed">
                {formatWhenFull(selected.last_assessed_at)}
              </DetailRow>
            </dl>

            <div>
              <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted">
                Vulnerabilities ({assetFindings.length})
              </p>
              {assetFindings.length === 0 ? (
                <p className="text-xs text-faint">No open vulnerabilities on this asset.</p>
              ) : (
                <ul className="flex flex-col gap-1.5">
                  {assetFindings.map((f) => (
                    <li key={f.id}>
                      <button
                        type="button"
                        onClick={() => {
                          setSelected(null);
                          go('findings', { finding: f.id });
                        }}
                        className="group flex w-full items-center gap-2 rounded-lg border border-border px-3 py-2 text-left transition-colors hover:border-border-strong hover:bg-surface-2"
                        title={`Open “${f.title}”`}
                      >
                        <SeverityBadge severity={f.severity} />
                        <span className="min-w-0 flex-1 truncate text-[13px] text-text group-hover:text-accent">
                          {f.title}
                        </span>
                        <ChevronRight
                          size={14}
                          aria-hidden
                          className="shrink-0 text-faint group-hover:text-accent"
                        />
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
}
