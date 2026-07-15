import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useNav } from '../lib/nav';
import { formatWhenFull, humanize } from '../lib/utils';
import {
  normalizeSeverity,
  PriorityBadge,
  RiskIndicator,
  SeverityBadge,
  StatusBadge,
} from '../components/app/badges';
import { DataTable, type ColumnDef, type FilterDef } from '../components/app/data-table';
import { FindingDetailDrawer } from '../components/app/finding-detail-drawer';
import { PageHeader } from '../components/app/page-header';
import type { Finding } from '../types/finding';

/** Findings: a professional data table over the live findings API, with a
 *  tabbed detail drawer and the original one-click workflows. */
export function FindingsPage() {
  const { token } = useAuth();
  const { current, go } = useNav();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingTotal, setFindingTotal] = useState(0);
  const [assetNames, setAssetNames] = useState<Map<string, string>>(new Map());
  const [selected, setSelected] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [page, assets] = await Promise.all([
        api.listAllFindings(token),
        api.listAllAssets(token).catch(() => null),
      ]);
      setFindings(page.items);
      setFindingTotal(page.total);
      if (assets) setAssetNames(new Map(assets.items.map((a) => [a.id, a.canonical_name])));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load findings.');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const openDetail = (f: Finding) => setSelected(f);

  // Deep link from elsewhere (e.g. an asset's vulnerabilities): #findings?finding=<id>
  // opens that finding's detail once, without reopening after the user closes it.
  const deepFindingId = current.params.finding;
  const handledDeepLink = useRef<string | null>(null);
  useEffect(() => {
    if (!deepFindingId || handledDeepLink.current === deepFindingId) return;
    const match = findings.find((f) => f.id === deepFindingId);
    if (match) {
      handledDeepLink.current = deepFindingId;
      openDetail(match);
      return;
    }
    if (!token || loading) return;
    handledDeepLink.current = deepFindingId;
    void api
      .getFinding(token, deepFindingId)
      .then(openDetail)
      .catch((err) => setError(err instanceof Error ? err.message : 'Finding not found.'));
  }, [deepFindingId, findings, loading, token]);

  const columns: ColumnDef<Finding>[] = useMemo(
    () => [
      {
        id: 'title',
        header: 'Finding',
        cell: (f) => (
          <span className="block max-w-72 truncate font-medium text-text" title={f.title}>
            {f.title}
          </span>
        ),
        sortValue: (f) => f.title,
        csvValue: (f) => f.title,
      },
      {
        id: 'id',
        header: 'Identifier',
        defaultHidden: true,
        cell: (f) => <span className="font-mono text-xs text-muted">{f.id.slice(0, 8)}</span>,
        sortValue: (f) => f.id,
        csvValue: (f) => f.id,
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
        id: 'risk',
        header: 'Risk score',
        cell: (f) => <RiskIndicator score={f.cvss_score} />,
        sortValue: (f) => f.cvss_score ?? -1,
        csvValue: (f) => (f.cvss_score != null ? String(f.cvss_score) : ''),
        align: 'right',
      },
      {
        id: 'cves',
        header: 'CVEs',
        cell: (f) =>
          f.cve_ids_json.length > 0 ? (
            <span className="font-mono text-xs text-muted" title={f.cve_ids_json.join(', ')}>
              {f.cve_ids_json[0]}
              {f.cve_ids_json.length > 1 ? ` +${f.cve_ids_json.length - 1}` : ''}
            </span>
          ) : (
            <span className="text-faint">—</span>
          ),
        sortValue: (f) => f.cve_ids_json[0] ?? '',
        csvValue: (f) => f.cve_ids_json.join(' '),
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
        id: 'site',
        header: 'Site',
        defaultHidden: true,
        cell: (f) => <span className="font-mono text-xs text-muted">{f.site_id.slice(0, 8)}</span>,
        sortValue: (f) => f.site_id,
        csvValue: (f) => f.site_id,
      },
      {
        id: 'kev',
        header: 'Exploited',
        cell: (f) =>
          f.known_exploited ? (
            <span className="text-xs font-semibold text-sev-critical">KEV</span>
          ) : (
            <span className="text-faint">—</span>
          ),
        sortValue: (f) => (f.known_exploited ? 1 : 0),
        csvValue: (f) => (f.known_exploited ? 'yes' : 'no'),
      },
      {
        id: 'confidence',
        header: 'Confidence',
        defaultHidden: true,
        cell: (f) => <span className="text-xs text-muted">{f.confidence_label}</span>,
        sortValue: (f) => f.confidence,
        csvValue: (f) => f.confidence_label,
      },
      {
        id: 'fix',
        header: 'Fix available',
        cell: (f) =>
          f.remediation ? (
            <span className="text-xs text-ok">Yes</span>
          ) : (
            <span className="text-faint">—</span>
          ),
        sortValue: (f) => (f.remediation ? 1 : 0),
        csvValue: (f) => (f.remediation ? 'yes' : 'no'),
      },
      {
        id: 'owner',
        header: 'Owner',
        defaultHidden: true,
        cell: (f) =>
          f.owner_user_id ? (
            <span className="font-mono text-xs text-muted">{f.owner_user_id.slice(0, 8)}</span>
          ) : (
            <span className="text-faint">Unassigned</span>
          ),
        sortValue: (f) => f.owner_user_id ?? '',
        csvValue: (f) => f.owner_user_id ?? '',
      },
      {
        id: 'status',
        header: 'Status',
        cell: (f) => <StatusBadge status={f.status} />,
        sortValue: (f) => f.status,
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
    ],
    [],
  );

  const filters: FilterDef<Finding>[] = useMemo(
    () => [
      {
        id: 'severity',
        label: 'Severity',
        options: ['critical', 'high', 'medium', 'low', 'info'].map((s) => ({
          value: s,
          label: humanize(s),
        })),
        predicate: (f, v) => normalizeSeverity(f.severity) === v,
      },
      {
        id: 'priority',
        label: 'Priority',
        options: [
          { value: 'fix_now', label: 'Fix now' },
          { value: 'plan', label: 'Plan a fix' },
          { value: 'watch', label: 'Watch' },
          { value: 'informational', label: 'Informational' },
        ],
        predicate: (f, v) => f.priority === v,
      },
      {
        id: 'status',
        label: 'Status',
        options: [...new Set(findings.map((f) => f.status))].map((s) => ({
          value: s,
          label: humanize(s),
        })),
        predicate: (f, v) => f.status === v,
      },
      {
        id: 'kev',
        label: 'Exploited',
        options: [{ value: 'yes', label: 'Known exploited (KEV)' }],
        predicate: (f, v) => (v === 'yes' ? f.known_exploited : true),
      },
    ],
    [findings],
  );

  // Honor deep links: #findings?severity=critical&q=…
  const initialSeverity = current.params.severity;
  const initialQuery = current.params.q;

  return (
    <div aria-label="Findings">
      <PageHeader
        crumbs={[{ label: 'Operations' }, { label: 'Findings' }]}
        title="Findings"
        description="Tracked vulnerabilities across your assets, prioritized by risk."
      />

      {findingTotal > findings.length && (
        <p className="mb-3 rounded border border-warn/30 bg-warn/10 px-3 py-2 text-xs text-muted">
          Showing the newest {findings.length.toLocaleString()} of {findingTotal.toLocaleString()}{' '}
          findings. Narrow the dataset with an API filter for complete large-scale exports.
        </p>
      )}

      <DataTable<Finding>
        key={`${initialSeverity ?? ''}|${initialQuery ?? ''}`}
        columns={columns}
        rows={
          initialSeverity
            ? findings.filter((f) => normalizeSeverity(f.severity) === initialSeverity)
            : initialQuery
              ? findings.filter((f) => f.title.toLowerCase().includes(initialQuery.toLowerCase()))
              : findings
        }
        rowKey={(f) => f.id}
        searchText={(f) => `${f.title} ${f.id} ${f.scanner_name} ${f.cve_ids_json.join(' ')}`}
        searchPlaceholder="Search findings…"
        filters={filters}
        onRowClick={openDetail}
        selectable
        loading={loading}
        error={error}
        onRetry={() => void load()}
        emptyTitle="No findings yet"
        emptyDescription="Run an assessment to populate findings across your assets."
        exportName="findings"
        storageKey="vulnadash.findings"
        defaultSort={{ id: 'severity', dir: 'desc' }}
      />

      <FindingDetailDrawer
        finding={selected}
        onClose={() => setSelected(null)}
        onChanged={load}
        assetName={selected?.asset_id ? (assetNames.get(selected.asset_id) ?? null) : null}
        onViewAsset={(id) => go('assets', { asset: id })}
      />
    </div>
  );
}
