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
import { Button } from '../components/ui/button';
import type { Finding } from '../types/finding';

interface FindingRow extends Finding {
  occurrence_count: number;
  affected_asset_count: number;
}

const PRIORITY_ORDER = ['informational', 'watch', 'plan', 'fix_now'];
const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];
const NON_ACTIONABLE_SUMMARIES = new Set([
  'cipher negotiated',
  'cipherlist strong',
  'protocol negotiated',
]);

function findingFamily(title: string): { key: string; label: string } {
  const normalized = title.trim().toLocaleLowerCase();
  if (normalized === 'beast cbc tls1' || normalized === 'beast (tls 1.0 cbc)') {
    return { key: 'beast-tls-cbc', label: 'BEAST (TLS 1.0 CBC)' };
  }
  if (
    normalized === 'certificate expiry' ||
    normalized === 'certificate validity (notafter)' ||
    normalized === 'expired ssl certificate'
  ) {
    return { key: 'certificate-expiry', label: 'Certificate expiry' };
  }
  return { key: normalized, label: title };
}

function findingRank(finding: Finding): number {
  const priority = PRIORITY_ORDER.indexOf(finding.priority);
  const severity = SEVERITY_ORDER.indexOf(normalizeSeverity(finding.severity));
  return Math.max(priority, 0) * 10 + Math.max(severity, 0);
}

/** Findings: a professional data table over the live findings API, with a
 *  tabbed detail drawer and the original one-click workflows. */
export function FindingsPage() {
  const { token } = useAuth();
  const { current, go } = useNav();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingTotal, setFindingTotal] = useState(0);
  const [assetNames, setAssetNames] = useState<Map<string, string>>(new Map());
  const [selected, setSelected] = useState<Finding | null>(null);
  const [groupSimilar, setGroupSimilar] = useState(true);
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

  const displayFindings: FindingRow[] = useMemo(() => {
    if (!groupSimilar) {
      return findings.map((finding) => ({
        ...finding,
        occurrence_count: 1,
        affected_asset_count: finding.asset_id ? 1 : 0,
      }));
    }
    const groups = new Map<string, { label: string; findings: Finding[] }>();
    for (const finding of findings) {
      const normalizedTitle = finding.title.trim().toLocaleLowerCase();
      if (NON_ACTIONABLE_SUMMARIES.has(normalizedTitle)) continue;
      const family = findingFamily(finding.title);
      const group = groups.get(family.key) ?? { label: family.label, findings: [] };
      group.findings.push(finding);
      groups.set(family.key, group);
    }
    return [...groups.values()].map((group) => {
      const representative = [...group.findings].sort((a, b) => findingRank(b) - findingRank(a))[0];
      return {
        ...representative,
        title: group.label,
        occurrence_count: group.findings.length,
        affected_asset_count: new Set(
          group.findings
            .map((finding) => finding.asset_id)
            .filter((assetId): assetId is string => assetId !== null),
        ).size,
      };
    });
  }, [findings, groupSimilar]);

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

  const columns: ColumnDef<FindingRow>[] = useMemo(
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
      ...(groupSimilar
        ? [
            {
              id: 'occurrences',
              header: 'Occurrences',
              align: 'right' as const,
              cell: (f: FindingRow) => (
                <span className="font-mono text-xs tabular-nums text-text">
                  {f.occurrence_count.toLocaleString()}
                </span>
              ),
              sortValue: (f: FindingRow) => f.occurrence_count,
              csvValue: (f: FindingRow) => String(f.occurrence_count),
            },
            {
              id: 'affectedAssetCount',
              header: 'Assets',
              align: 'right' as const,
              cell: (f: FindingRow) => (
                <span className="font-mono text-xs tabular-nums text-text">
                  {f.affected_asset_count.toLocaleString()}
                </span>
              ),
              sortValue: (f: FindingRow) => f.affected_asset_count,
              csvValue: (f: FindingRow) => String(f.affected_asset_count),
            },
          ]
        : []),
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
        cell: (f) => (
          <span className="font-mono text-xs tabular-nums text-text">
            {f.risk_score != null ? f.risk_score.toFixed(1) : '—'}
          </span>
        ),
        sortValue: (f) => f.risk_score ?? -1,
        csvValue: (f) => (f.risk_score != null ? String(f.risk_score) : ''),
        align: 'right',
      },
      {
        id: 'cvss',
        header: 'CVSS',
        defaultHidden: true,
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
          groupSimilar && f.affected_asset_count > 1 ? (
            <span className="text-xs text-muted">Multiple assets</span>
          ) : f.asset_id ? (
            <span className="text-xs text-muted">{assetNames.get(f.asset_id) ?? f.asset_id}</span>
          ) : (
            <span className="text-faint">—</span>
          ),
        sortValue: (f) => (f.asset_id ? (assetNames.get(f.asset_id) ?? f.asset_id) : ''),
        csvValue: (f) => (f.asset_id ? (assetNames.get(f.asset_id) ?? f.asset_id) : ''),
      },
      {
        id: 'assetId',
        header: 'Asset ID',
        defaultHidden: true,
        cell: (f) => <span className="font-mono text-xs text-muted">{f.asset_id ?? '—'}</span>,
        sortValue: (f) => f.asset_id ?? '',
        csvValue: (f) => f.asset_id ?? '',
      },
      {
        id: 'serviceId',
        header: 'Service ID',
        defaultHidden: true,
        cell: (f) => <span className="font-mono text-xs text-muted">{f.service_id ?? '—'}</span>,
        sortValue: (f) => f.service_id ?? '',
        csvValue: (f) => f.service_id ?? '',
      },
      {
        id: 'scanner',
        header: 'Scanner',
        defaultHidden: true,
        cell: (f) => <span className="text-xs text-muted">{f.scanner_name}</span>,
        sortValue: (f) => f.scanner_name,
        csvValue: (f) => f.scanner_name,
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
    [assetNames, groupSimilar],
  );

  const filters: FilterDef<FindingRow>[] = useMemo(
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
        actions={
          <Button variant="secondary" size="sm" onClick={() => setGroupSimilar((value) => !value)}>
            {groupSimilar ? 'All occurrences' : 'Group similar'}
          </Button>
        }
      />

      {groupSimilar && findings.length > 0 && (
        <p className="mb-3 text-xs text-muted">
          Grouped {findings.length.toLocaleString()} occurrences into{' '}
          {displayFindings.length.toLocaleString()} finding families. Open “All occurrences” for
          service-level detail.
        </p>
      )}

      {findingTotal > findings.length && (
        <p className="mb-3 rounded border border-warn/30 bg-warn/10 px-3 py-2 text-xs text-muted">
          Showing the newest {findings.length.toLocaleString()} of {findingTotal.toLocaleString()}{' '}
          findings. Narrow the dataset with an API filter for complete large-scale exports.
        </p>
      )}

      <DataTable<FindingRow>
        key={`${initialSeverity ?? ''}|${initialQuery ?? ''}|${groupSimilar ? 'grouped' : 'all'}`}
        columns={columns}
        rows={
          initialSeverity
            ? displayFindings.filter((f) => normalizeSeverity(f.severity) === initialSeverity)
            : initialQuery
              ? displayFindings.filter((f) =>
                  f.title.toLowerCase().includes(initialQuery.toLowerCase()),
                )
              : displayFindings
        }
        rowKey={(f) => (groupSimilar ? `family:${f.title.toLocaleLowerCase()}` : f.id)}
        searchText={(f) =>
          `${f.title} ${f.id} ${f.scanner_name} ${f.asset_id ? (assetNames.get(f.asset_id) ?? f.asset_id) : ''} ${f.cve_ids_json.join(' ')}`
        }
        searchPlaceholder="Search findings…"
        filters={filters}
        onRowClick={openDetail}
        selectable={!groupSimilar}
        loading={loading}
        error={error}
        onRetry={() => void load()}
        emptyTitle="No findings yet"
        emptyDescription="Run an assessment to populate findings across your assets."
        exportName="findings"
        exportAllColumns
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
