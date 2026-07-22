import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ChevronRight, FolderTree, Pencil, Server, Tag, Trash2 } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useNav } from '../lib/nav';
import { useToast } from '../lib/toast';
import { formatRelative, formatWhenFull, humanize } from '../lib/utils';
import { normalizeSeverity, SeverityBadge, StatusBadge } from '../components/app/badges';
import { DataTable, type ColumnDef, type FilterDef } from '../components/app/data-table';
import { FindingDetailDrawer } from '../components/app/finding-detail-drawer';
import { PageHeader } from '../components/app/page-header';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Field, Input, Select, Textarea } from '../components/ui/input';
import { DetailRow } from '../components/ui/misc';
import { ConfirmDialog, Drawer, Modal } from '../components/ui/overlay';
import { InlineError } from '../components/ui/states';
import type {
  Asset,
  AssetContextPatch,
  AssetDetail,
  DepartmentOwner,
  AssetGroup,
  AssetTag,
  OwnershipHistory,
  OwnershipResolution,
  Site,
} from '../types/inventory';
import type { Finding } from '../types/finding';
import type { UserSummary } from '../types/auth';

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Asset inventory, from the live `/assets` API. Per-asset critical/high counts
 *  are derived from open findings so the columns reflect real risk. */
interface AssetRow extends Asset {
  critical: number;
  high: number;
  findingTotal: number;
}

export function AssetsPage() {
  const { token, user } = useAuth();
  const { current } = useNav();
  const { toast } = useToast();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [tags, setTags] = useState<AssetTag[]>([]);
  const [groups, setGroups] = useState<AssetGroup[]>([]);
  const [users, setUsers] = useState<UserSummary[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AssetRow | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [ownership, setOwnership] = useState<OwnershipResolution | null>(null);
  const [detail, setDetail] = useState<AssetDetail | null>(null);
  const [ownershipHistory, setOwnershipHistory] = useState<OwnershipHistory[]>([]);
  const [departmentOwners, setDepartmentOwners] = useState<DepartmentOwner[]>([]);
  const [editAsset, setEditAsset] = useState<AssetRow | null>(null);
  const [bulkAssets, setBulkAssets] = useState<AssetRow[]>([]);
  const [deleteTargets, setDeleteTargets] = useState<AssetRow[]>([]);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [tagOpen, setTagOpen] = useState(false);
  const [groupOpen, setGroupOpen] = useState(false);
  const [ownershipRulesOpen, setOwnershipRulesOpen] = useState(false);
  const canManage =
    user?.permissions?.includes('assets.manage') === true || user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [a, s, f, t, g, u, d] = await Promise.all([
        api.listAllAssets(token),
        api.listAllSites(token),
        api.listAllFindings(token).catch(() => null),
        api.listAssetTags(token).catch(() => null),
        api.listAssetGroups(token).catch(() => null),
        canManage ? api.listUsers(token).catch(() => null) : Promise.resolve(null),
        api.listDepartmentOwners(token).catch(() => null),
      ]);
      setAssets(a.items);
      setSites(s.items);
      setFindings(f?.items ?? []);
      setTags(t?.items ?? []);
      setGroups(g?.items ?? []);
      setUsers(
        (u?.items ?? []).filter(
          (candidate) =>
            candidate.is_active !== false &&
            (!candidate.account_status || candidate.account_status === 'active'),
        ),
      );
      setDepartmentOwners(d ?? []);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load assets.');
    } finally {
      setLoading(false);
    }
  }, [token, canManage]);

  useEffect(() => {
    if (!token || !selected) {
      setOwnership(null);
      setOwnershipHistory([]);
      return;
    }
    void Promise.all([
      api.assetOwnership(token, selected.id),
      api.assetOwnershipHistory(token, selected.id).catch(() => null),
    ])
      .then(([resolved, history]) => {
        setOwnership(resolved);
        setOwnershipHistory(history?.items ?? []);
      })
      .catch(() => {
        setOwnership(null);
        setOwnershipHistory([]);
      });
  }, [selected, token]);

  // Fetch the asset's discovered identifiers (hostname, MAC, IPs) for the drawer.
  useEffect(() => {
    if (!token || !selected) {
      setDetail(null);
      return;
    }
    api
      .getAsset(token, selected.id)
      .then(setDetail)
      .catch(() => setDetail(null));
  }, [selected, token]);

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

  const groupName = useCallback(
    (id: string) => groups.find((group) => group.id === id)?.name ?? id,
    [groups],
  );
  const userName = useCallback(
    (id: string | null) =>
      id
        ? users.find((candidate) => candidate.id === id)?.full_name || 'Assigned user'
        : 'Unassigned',
    [users],
  );

  // Deep link from the Findings page (#assets?asset=<id>): open that asset's
  // drawer once, without reopening after the user closes it.
  const deepAssetId = current.params.asset;
  const handledAssetLink = useRef<string | null>(null);
  useEffect(() => {
    if (!deepAssetId || handledAssetLink.current === deepAssetId) return;
    const match = rows.find((r) => r.id === deepAssetId);
    if (match) {
      handledAssetLink.current = deepAssetId;
      setSelected(match);
    }
  }, [deepAssetId, rows]);

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
        id: 'id',
        header: 'Asset ID',
        defaultHidden: true,
        cell: (a) => <span className="font-mono text-xs text-muted">{a.id}</span>,
        sortValue: (a) => a.id,
        csvValue: (a) => a.id,
      },
      {
        id: 'ipAddresses',
        header: 'IP addresses',
        cell: (a) => (
          <span className="font-mono text-xs text-muted">{a.ip_addresses.join(', ') || '—'}</span>
        ),
        sortValue: (a) => a.ip_addresses.join(', '),
        csvValue: (a) => a.ip_addresses.join(', '),
      },
      {
        id: 'hostnames',
        header: 'Hostnames',
        defaultHidden: true,
        cell: (a) => <span className="text-xs text-muted">{a.hostnames.join(', ') || '—'}</span>,
        sortValue: (a) => a.hostnames.join(', '),
        csvValue: (a) => a.hostnames.join(', '),
      },
      {
        id: 'macAddresses',
        header: 'MAC addresses',
        defaultHidden: true,
        cell: (a) => (
          <span className="font-mono text-xs text-muted">{a.mac_addresses.join(', ') || '—'}</span>
        ),
        sortValue: (a) => a.mac_addresses.join(', '),
        csvValue: (a) => a.mac_addresses.join(', '),
      },
      {
        id: 'type',
        header: 'Type',
        cell: (a) => <Badge tone="neutral">{humanize(a.asset_type)}</Badge>,
        sortValue: (a) => a.asset_type,
        csvValue: (a) => a.asset_type,
      },
      {
        id: 'criticality',
        header: 'Criticality',
        cell: (a) => <Badge tone="neutral">{humanize(a.criticality)}</Badge>,
        sortValue: (a) => a.criticality,
        csvValue: (a) => a.criticality,
      },
      {
        id: 'environment',
        header: 'Environment',
        defaultHidden: true,
        cell: (a) => <span className="text-xs text-muted">{humanize(a.environment)}</span>,
        sortValue: (a) => a.environment,
        csvValue: (a) => a.environment,
      },
      {
        id: 'department',
        header: 'Department',
        defaultHidden: true,
        cell: (a) => <span className="text-xs text-muted">{a.department ?? '—'}</span>,
        sortValue: (a) => a.department ?? '',
        csvValue: (a) => a.department ?? '',
      },
      {
        id: 'tags',
        header: 'Tags',
        cell: (a) => (
          <span className="text-xs text-muted">
            {a.tags.length ? a.tags.map((tagValue) => tagValue.name).join(', ') : '—'}
          </span>
        ),
        sortValue: (a) => a.tags.map((tagValue) => tagValue.name).join(', '),
        csvValue: (a) => a.tags.map((tagValue) => tagValue.name).join(', '),
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
        id: 'criticality',
        label: 'Criticality',
        options: [...new Set(rows.map((row) => row.criticality))].map((value) => ({
          value,
          label: humanize(value),
        })),
        predicate: (asset, value) => asset.criticality === value,
      },
      {
        id: 'environment',
        label: 'Environment',
        options: [...new Set(rows.map((row) => row.environment))].map((value) => ({
          value,
          label: humanize(value),
        })),
        predicate: (asset, value) => asset.environment === value,
      },
      {
        id: 'tag',
        label: 'Tag',
        options: tags.map((tagValue) => ({ value: tagValue.id, label: tagValue.name })),
        predicate: (asset, value) => asset.tags.some((tagValue) => tagValue.id === value),
      },
      {
        id: 'group',
        label: 'Group',
        options: groups.map((group) => ({ value: group.id, label: group.name })),
        predicate: (asset, value) => asset.group_ids.includes(value),
      },
      {
        id: 'attention',
        label: 'Attention',
        options: [{ value: 'attention', label: 'Has critical or high findings' }],
        predicate: (a, v) => (v === 'attention' ? a.critical > 0 || a.high > 0 : true),
      },
    ],
    [sites, rows, tags, groups],
  );

  const preFiltered =
    current.params.filter === 'attention' ? rows.filter((a) => a.critical > 0 || a.high > 0) : rows;

  // Discovered network identifiers for the selected asset's drawer. `detail` may
  // briefly belong to a previously-selected asset while the new one loads.
  const detailReady = !!detail && !!selected && detail.id === selected.id;
  const identifierValues = (type: string): string[] =>
    detailReady
      ? detail!.identifiers.filter((i) => i.identifier_type === type).map((i) => i.identifier_value)
      : [];
  const hostnames = [...identifierValues('hostname'), ...identifierValues('fqdn')];
  const macAddresses = identifierValues('mac_address');
  const ipAddresses = identifierValues('ip_address');
  const identifierText = (values: string[]) =>
    !detailReady ? 'Loading…' : values.length ? values.join(', ') : '—';

  const requestDelete = (targets: AssetRow[]) => {
    setDeleteError(null);
    setDeleteTargets(targets);
  };

  const removeAssets = async () => {
    if (!token || deleteTargets.length === 0) return;
    setDeleteBusy(true);
    setDeleteError(null);
    try {
      let deletedCount = 1;
      let skippedCount = 0;
      if (deleteTargets.length === 1) {
        await api.deleteAsset(token, deleteTargets[0].id);
      } else {
        const result = await api.bulkDeleteAssets(
          token,
          deleteTargets.map((asset) => asset.id),
        );
        deletedCount = result.deleted_assets;
        skippedCount = result.skipped_assets;
      }
      setDeleteTargets([]);
      setSelected(null);
      setBulkAssets([]);
      if (skippedCount > 0) {
        toast(
          'warning',
          deletedCount > 0
            ? `${deletedCount} ${deletedCount === 1 ? 'asset' : 'assets'} deleted.`
            : 'No assets needed deletion.',
          `${skippedCount} ${skippedCount === 1 ? 'selection was' : 'selections were'} already missing or no longer accessible.`,
        );
      } else {
        toast('success', `${deletedCount} ${deletedCount === 1 ? 'asset' : 'assets'} deleted.`);
      }
      await load();
    } catch (deleteFailure) {
      setDeleteError(errorMessage(deleteFailure, 'Failed to delete assets.'));
    } finally {
      setDeleteBusy(false);
    }
  };

  return (
    <div aria-label="Assets">
      <PageHeader
        crumbs={[{ label: 'Operations' }, { label: 'Assets' }]}
        title="Assets"
        description="Searchable inventory of everything Vulna has seen on your networks."
        actions={
          canManage ? (
            <>
              <Button variant="outline" onClick={() => setOwnershipRulesOpen(true)}>
                Ownership rules
              </Button>
              <Button variant="outline" onClick={() => setTagOpen(true)}>
                <Tag size={14} aria-hidden /> New tag
              </Button>
              <Button variant="primary" onClick={() => setGroupOpen(true)}>
                <FolderTree size={14} aria-hidden /> New group
              </Button>
            </>
          ) : undefined
        }
      />

      <DataTable<AssetRow>
        columns={columns}
        rows={preFiltered}
        rowKey={(a) => a.id}
        searchText={(a) =>
          `${a.canonical_name} ${a.ip_addresses.join(' ')} ${a.hostnames.join(' ')} ${a.mac_addresses.join(' ')} ${a.operating_system ?? ''} ${a.manufacturer ?? ''} ${a.department ?? ''} ${a.business_function ?? ''} ${a.tags.map((tagValue) => tagValue.name).join(' ')}`
        }
        searchPlaceholder="Search name, context, tags…"
        filters={filters}
        onRowClick={setSelected}
        selectable
        toolbar={({ selected: selectedRows }) =>
          canManage && selectedRows.length > 0 ? (
            <div className="flex items-center gap-2">
              <Button size="sm" variant="outline" onClick={() => setBulkAssets(selectedRows)}>
                <Pencil size={12} aria-hidden /> Edit {selectedRows.length}
              </Button>
              <Button size="sm" variant="destructive" onClick={() => requestDelete(selectedRows)}>
                <Trash2 size={12} aria-hidden /> Delete {selectedRows.length}
              </Button>
            </div>
          ) : null
        }
        loading={loading}
        error={error}
        onRetry={() => void load()}
        emptyTitle="No assets discovered yet"
        emptyDescription="Assets appear automatically after your first assessment approves a scope and a scan runs."
        exportName="assets"
        exportAllColumns
        storageKey="vulnadash.assets"
        defaultSort={{ id: 'lastSeen', dir: 'desc' }}
      />

      <Drawer
        open={selected !== null && selectedFinding === null}
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
        footer={
          selected && canManage ? (
            <>
              <Button variant="destructive" onClick={() => requestDelete([selected])}>
                <Trash2 size={13} aria-hidden /> Delete asset
              </Button>
              <Button variant="primary" onClick={() => setEditAsset(selected)}>
                <Pencil size={13} aria-hidden /> Edit context
              </Button>
            </>
          ) : undefined
        }
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
              <DetailRow label="Hostname">{identifierText(hostnames)}</DetailRow>
              <DetailRow label="IP address">{identifierText(ipAddresses)}</DetailRow>
              <DetailRow label="MAC address">{identifierText(macAddresses)}</DetailRow>
              <DetailRow label="Manufacturer">{selected.manufacturer ?? '—'}</DetailRow>
              <DetailRow label="Site">{siteName(selected.site_id)}</DetailRow>
              <DetailRow label="Department">{selected.department ?? '—'}</DetailRow>
              <DetailRow label="Business function">{selected.business_function ?? '—'}</DetailRow>
              <DetailRow label="Environment">{humanize(selected.environment)}</DetailRow>
              <DetailRow label="Criticality">{humanize(selected.criticality)}</DetailRow>
              <DetailRow label="Data classification">
                {humanize(selected.data_classification)}
              </DetailRow>
              <DetailRow label="Internet exposed">
                {selected.internet_exposed ? 'Yes' : 'No'}
              </DetailRow>
              <DetailRow label="Effective owner">
                {ownership ? userName(ownership.owner_user_id) : 'Loading…'}
                {ownership && (
                  <span className="ml-1 text-faint">({humanize(ownership.source)})</span>
                )}
              </DetailRow>
              <DetailRow label="Tags">
                {selected.tags.length
                  ? selected.tags.map((tagValue) => tagValue.name).join(', ')
                  : '—'}
              </DetailRow>
              <DetailRow label="Groups">
                {selected.group_ids.length ? selected.group_ids.map(groupName).join(', ') : '—'}
              </DetailRow>
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
                Ownership history
              </p>
              {ownershipHistory.length === 0 ? (
                <p className="text-xs text-faint">No effective-owner changes recorded yet.</p>
              ) : (
                <ul className="flex flex-col gap-1.5">
                  {ownershipHistory.slice(0, 5).map((entry) => (
                    <li
                      key={entry.id}
                      className="flex items-center justify-between gap-3 rounded-lg border border-border px-3 py-2 text-xs"
                    >
                      <span className="text-text">
                        {userName(entry.owner_user_id)} · {humanize(entry.source)}
                      </span>
                      <span className="text-faint">{formatWhenFull(entry.created_at)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

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
                        onClick={() => setSelectedFinding(f)}
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

      <AssetContextModal
        asset={editAsset}
        tags={tags}
        groups={groups}
        users={users}
        onClose={() => setEditAsset(null)}
        onSaved={() => {
          setEditAsset(null);
          setSelected(null);
          toast('success', 'Asset context updated.');
          void load();
        }}
      />
      <BulkAssetModal
        assets={bulkAssets}
        tags={tags}
        groups={groups}
        onClose={() => setBulkAssets([])}
        onSaved={(count) => {
          setBulkAssets([]);
          toast('success', `${count} assets updated.`);
          void load();
        }}
      />
      <CreateTagModal
        open={tagOpen}
        onClose={() => setTagOpen(false)}
        onCreated={() => {
          setTagOpen(false);
          toast('success', 'Asset tag created.');
          void load();
        }}
      />
      <CreateGroupModal
        open={groupOpen}
        sites={sites}
        users={users}
        onClose={() => setGroupOpen(false)}
        onCreated={() => {
          setGroupOpen(false);
          toast('success', 'Asset group created and evaluated.');
          void load();
        }}
      />
      <DepartmentOwnershipModal
        open={ownershipRulesOpen}
        owners={departmentOwners}
        users={users}
        onClose={() => setOwnershipRulesOpen(false)}
        onChanged={() => void load()}
      />
      <ConfirmDialog
        open={deleteTargets.length > 0}
        onClose={() => {
          if (!deleteBusy) setDeleteTargets([]);
        }}
        onConfirm={() => void removeAssets()}
        destructive
        busy={deleteBusy}
        title={
          deleteTargets.length === 1
            ? `Delete asset “${deleteTargets[0].canonical_name}”?`
            : `Delete ${deleteTargets.length} assets?`
        }
        confirmLabel={deleteTargets.length === 1 ? 'Delete asset' : 'Delete assets'}
        body={
          <div className="flex flex-col gap-3">
            <p>
              This permanently removes the selected{' '}
              {deleteTargets.length === 1 ? 'asset' : 'assets'} and associated services, findings,
              current inventory links, lifecycle history, and context. Source observations and audit
              records remain for security traceability. This cannot be undone.
            </p>
            <p>
              A future scan or inventory run can add the{' '}
              {deleteTargets.length === 1 ? 'asset' : 'assets'} again if the source still reports
              them.
            </p>
            {deleteError && <InlineError message={deleteError} />}
          </div>
        }
      />

      {/* A vulnerability opens in a slider on this page; the back arrow returns
          to the asset it was opened from. */}
      <FindingDetailDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onBack={() => setSelectedFinding(null)}
        onChanged={load}
        assetName={selected?.canonical_name ?? null}
      />
    </div>
  );
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

function DepartmentOwnershipModal({
  open,
  owners,
  users,
  onClose,
  onChanged,
}: {
  open: boolean;
  owners: DepartmentOwner[];
  users: UserSummary[];
  onClose: () => void;
  onChanged: () => void;
}) {
  const { token } = useAuth();
  const { toast } = useToast();
  const [department, setDepartment] = useState('');
  const [ownerId, setOwnerId] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const save = async () => {
    if (!token || !department.trim() || !ownerId) return;
    setBusy(true);
    setError(null);
    try {
      await api.upsertDepartmentOwner(token, {
        department: department.trim(),
        owner_user_id: ownerId,
      });
      setDepartment('');
      setOwnerId('');
      toast('success', 'Department ownership rule saved.');
      onChanged();
    } catch (saveError) {
      setError(errorMessage(saveError, 'Failed to save the ownership rule.'));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (owner: DepartmentOwner) => {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await api.deleteDepartmentOwner(token, owner.id);
      toast('success', 'Department ownership rule removed.');
      onChanged();
    } catch (removeError) {
      setError(errorMessage(removeError, 'Failed to remove the ownership rule.'));
    } finally {
      setBusy(false);
    }
  };

  const userName = (id: string) =>
    users.find((candidate) => candidate.id === id)?.full_name ||
    users.find((candidate) => candidate.id === id)?.email ||
    'Assigned user';

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Department ownership rules"
      description="Used after explicit asset, group, and site ownership rules."
      footer={
        <Button variant="ghost" onClick={onClose}>
          Close
        </Button>
      }
    >
      <div className="flex flex-col gap-4">
        {error && <InlineError message={error} />}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Department">
            <Input
              value={department}
              onChange={(event) => setDepartment(event.target.value)}
              placeholder="Finance"
            />
          </Field>
          <Field label="Fallback owner">
            <Select value={ownerId} onChange={(event) => setOwnerId(event.target.value)}>
              <option value="">Select a user</option>
              {users.map((candidate) => (
                <option key={candidate.id} value={candidate.id}>
                  {candidate.full_name || candidate.email}
                </option>
              ))}
            </Select>
          </Field>
        </div>
        <Button
          variant="primary"
          loading={busy}
          disabled={!department.trim() || !ownerId}
          onClick={() => void save()}
        >
          Save rule
        </Button>
        <div className="divide-y divide-border rounded-lg border border-border">
          {owners.length === 0 ? (
            <p className="px-3 py-3 text-xs text-faint">No department fallback owners.</p>
          ) : (
            owners.map((owner) => (
              <div key={owner.id} className="flex items-center justify-between gap-3 px-3 py-2">
                <div>
                  <p className="text-xs font-medium text-text">{owner.department}</p>
                  <p className="text-[11px] text-muted">{userName(owner.owner_user_id)}</p>
                </div>
                <Button
                  size="sm"
                  variant="destructive"
                  disabled={busy}
                  onClick={() => void remove(owner)}
                >
                  Remove
                </Button>
              </div>
            ))
          )}
        </div>
      </div>
    </Modal>
  );
}

function AssetContextModal({
  asset,
  tags,
  groups,
  users,
  onClose,
  onSaved,
}: {
  asset: AssetRow | null;
  tags: AssetTag[];
  groups: AssetGroup[];
  users: UserSummary[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const { token } = useAuth();
  const [patch, setPatch] = useState<AssetContextPatch>({});
  const [tagIds, setTagIds] = useState<string[]>([]);
  const [groupIds, setGroupIds] = useState<string[]>([]);
  const [contextText, setContextText] = useState('{}');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const staticGroups = groups.filter(
    (group) =>
      group.group_type === 'static' && (!group.site_id || group.site_id === asset?.site_id),
  );

  useEffect(() => {
    if (!asset) return;
    setPatch({
      canonical_name: asset.canonical_name,
      department: asset.department,
      business_function: asset.business_function,
      environment: asset.environment,
      criticality: asset.criticality,
      data_classification: asset.data_classification,
      internet_exposed: asset.internet_exposed,
      owner_user_id: asset.owner_user_id,
    });
    setTagIds(asset.tags.map((tagValue) => tagValue.id));
    setGroupIds(asset.group_ids.filter((id) => staticGroups.some((group) => group.id === id)));
    setContextText(JSON.stringify(asset.context_json, null, 2));
    setError(null);
  }, [asset]); // eslint-disable-line react-hooks/exhaustive-deps

  const submit = async () => {
    if (!token || !asset) return;
    setBusy(true);
    setError(null);
    try {
      let context: Record<string, unknown>;
      try {
        context = JSON.parse(contextText) as Record<string, unknown>;
      } catch {
        throw new Error('Custom context must be valid JSON.');
      }
      const previousTags = new Set(asset.tags.map((tagValue) => tagValue.id));
      const previousGroups = new Set(
        asset.group_ids.filter((id) => staticGroups.some((group) => group.id === id)),
      );
      await api.bulkUpdateAssets(token, {
        asset_ids: [asset.id],
        context: { ...patch, context_json: context },
        add_tag_ids: tagIds.filter((id) => !previousTags.has(id)),
        remove_tag_ids: [...previousTags].filter((id) => !tagIds.includes(id)),
        add_static_group_ids: groupIds.filter((id) => !previousGroups.has(id)),
        remove_static_group_ids: [...previousGroups].filter((id) => !groupIds.includes(id)),
      });
      onSaved();
    } catch (submitError) {
      setError(errorMessage(submitError, 'Failed to update asset context.'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={asset !== null}
      onClose={onClose}
      title="Edit asset context"
      description={asset?.canonical_name}
      wide
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={busy} onClick={() => void submit()}>
            Save context
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {error && <InlineError className="sm:col-span-2" message={error} />}
        <Field label="Canonical name">
          <Input
            value={patch.canonical_name ?? ''}
            onChange={(event) =>
              setPatch((current) => ({ ...current, canonical_name: event.target.value }))
            }
          />
        </Field>
        <Field label="Department">
          <Input
            value={patch.department ?? ''}
            onChange={(event) =>
              setPatch((current) => ({ ...current, department: event.target.value || null }))
            }
          />
        </Field>
        <Field label="Business function">
          <Input
            value={patch.business_function ?? ''}
            onChange={(event) =>
              setPatch((current) => ({ ...current, business_function: event.target.value || null }))
            }
          />
        </Field>
        <Field label="Environment">
          <Select
            value={patch.environment ?? 'unknown'}
            onChange={(event) =>
              setPatch((current) => ({
                ...current,
                environment: event.target.value as Asset['environment'],
              }))
            }
          >
            {['unknown', 'production', 'staging', 'development', 'test'].map((value) => (
              <option key={value} value={value}>
                {humanize(value)}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Criticality">
          <Select
            value={patch.criticality ?? 'unknown'}
            onChange={(event) =>
              setPatch((current) => ({
                ...current,
                criticality: event.target.value as Asset['criticality'],
              }))
            }
          >
            {['unknown', 'low', 'moderate', 'high', 'mission_critical'].map((value) => (
              <option key={value} value={value}>
                {humanize(value)}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Data classification">
          <Select
            value={patch.data_classification ?? 'unknown'}
            onChange={(event) =>
              setPatch((current) => ({
                ...current,
                data_classification: event.target.value as Asset['data_classification'],
              }))
            }
          >
            {['unknown', 'public', 'internal', 'confidential', 'restricted'].map((value) => (
              <option key={value} value={value}>
                {humanize(value)}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Explicit owner">
          <Select
            value={patch.owner_user_id ?? ''}
            onChange={(event) =>
              setPatch((current) => ({ ...current, owner_user_id: event.target.value || null }))
            }
          >
            <option value="">Use ownership rules</option>
            {users.map((candidate) => (
              <option key={candidate.id} value={candidate.id}>
                {candidate.full_name || candidate.email}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Exposure">
          <label className="flex h-8.5 items-center gap-2 rounded-lg border border-border px-3 text-xs text-muted">
            <input
              type="checkbox"
              checked={patch.internet_exposed ?? false}
              onChange={(event) =>
                setPatch((current) => ({ ...current, internet_exposed: event.target.checked }))
              }
            />
            Internet exposed
          </label>
        </Field>
        <Field label="Tags" hint="Command-click or Ctrl-click to select multiple tags.">
          <Select
            multiple
            className="h-28"
            value={tagIds}
            onChange={(event) =>
              setTagIds([...event.target.selectedOptions].map((option) => option.value))
            }
          >
            {tags.map((tagValue) => (
              <option key={tagValue.id} value={tagValue.id}>
                {tagValue.name}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Static groups" hint="Dynamic membership is always rule-derived.">
          <Select
            multiple
            className="h-28"
            value={groupIds}
            onChange={(event) =>
              setGroupIds([...event.target.selectedOptions].map((option) => option.value))
            }
          >
            {staticGroups.map((group) => (
              <option key={group.id} value={group.id}>
                {group.name}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Custom context (JSON)" className="sm:col-span-2">
          <Textarea
            className="min-h-28 font-mono"
            value={contextText}
            onChange={(event) => setContextText(event.target.value)}
          />
        </Field>
      </div>
    </Modal>
  );
}

function BulkAssetModal({
  assets,
  tags,
  groups,
  onClose,
  onSaved,
}: {
  assets: AssetRow[];
  tags: AssetTag[];
  groups: AssetGroup[];
  onClose: () => void;
  onSaved: (count: number) => void;
}) {
  const { token } = useAuth();
  const [department, setDepartment] = useState('');
  const [environment, setEnvironment] = useState('');
  const [criticality, setCriticality] = useState('');
  const [tagId, setTagId] = useState('');
  const [groupId, setGroupId] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const siteIds = new Set(assets.map((asset) => asset.site_id));
  const staticGroups = groups.filter(
    (group) => group.group_type === 'static' && (!group.site_id || siteIds.has(group.site_id)),
  );

  useEffect(() => {
    if (!assets.length) return;
    setDepartment('');
    setEnvironment('');
    setCriticality('');
    setTagId('');
    setGroupId('');
    setError(null);
  }, [assets]);

  const submit = async () => {
    if (!token || !assets.length) return;
    if (!department && !environment && !criticality && !tagId && !groupId) {
      setError('Choose at least one change.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const result = await api.bulkUpdateAssets(token, {
        asset_ids: assets.map((asset) => asset.id),
        context: {
          ...(department ? { department } : {}),
          ...(environment ? { environment: environment as Asset['environment'] } : {}),
          ...(criticality ? { criticality: criticality as Asset['criticality'] } : {}),
        },
        add_tag_ids: tagId ? [tagId] : [],
        add_static_group_ids: groupId ? [groupId] : [],
      });
      onSaved(result.updated_assets);
    } catch (submitError) {
      setError(errorMessage(submitError, 'Failed to update assets.'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={assets.length > 0}
      onClose={onClose}
      title={`Edit ${assets.length} assets`}
      description="Only populated fields are changed."
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={busy} onClick={() => void submit()}>
            Apply changes
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        {error && <InlineError message={error} />}
        <Field label="Department">
          <Input
            value={department}
            onChange={(event) => setDepartment(event.target.value)}
            placeholder="Leave unchanged"
          />
        </Field>
        <Field label="Environment">
          <Select value={environment} onChange={(event) => setEnvironment(event.target.value)}>
            <option value="">Leave unchanged</option>
            {['unknown', 'production', 'staging', 'development', 'test'].map((value) => (
              <option key={value} value={value}>
                {humanize(value)}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Criticality">
          <Select value={criticality} onChange={(event) => setCriticality(event.target.value)}>
            <option value="">Leave unchanged</option>
            {['unknown', 'low', 'moderate', 'high', 'mission_critical'].map((value) => (
              <option key={value} value={value}>
                {humanize(value)}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Add tag">
          <Select value={tagId} onChange={(event) => setTagId(event.target.value)}>
            <option value="">None</option>
            {tags.map((tagValue) => (
              <option key={tagValue.id} value={tagValue.id}>
                {tagValue.name}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Add static group">
          <Select value={groupId} onChange={(event) => setGroupId(event.target.value)}>
            <option value="">None</option>
            {staticGroups.map((group) => (
              <option key={group.id} value={group.id}>
                {group.name}
              </option>
            ))}
          </Select>
        </Field>
      </div>
    </Modal>
  );
}

function CreateTagModal({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}) {
  const { token } = useAuth();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [color, setColor] = useState('#3366ff');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!token || !name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await api.createAssetTag(token, { name, description: description || null, color });
      setName('');
      setDescription('');
      onCreated();
    } catch (submitError) {
      setError(errorMessage(submitError, 'Failed to create tag.'));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Create asset tag"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            loading={busy}
            disabled={!name.trim()}
            onClick={() => void submit()}
          >
            Create tag
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        {error && <InlineError message={error} />}
        <Field label="Name">
          <Input value={name} onChange={(event) => setName(event.target.value)} />
        </Field>
        <Field label="Description">
          <Input value={description} onChange={(event) => setDescription(event.target.value)} />
        </Field>
        <Field label="Color">
          <Input type="color" value={color} onChange={(event) => setColor(event.target.value)} />
        </Field>
      </div>
    </Modal>
  );
}

function CreateGroupModal({
  open,
  sites,
  users,
  onClose,
  onCreated,
}: {
  open: boolean;
  sites: Site[];
  users: UserSummary[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const { token } = useAuth();
  const [name, setName] = useState('');
  const [groupType, setGroupType] = useState<'static' | 'dynamic'>('static');
  const [siteId, setSiteId] = useState('');
  const [priority, setPriority] = useState('0');
  const [ownerId, setOwnerId] = useState('');
  const [ruleText, setRuleText] = useState(
    '{\n  "field": "environment",\n  "operator": "eq",\n  "value": "production"\n}',
  );
  const [preview, setPreview] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const parseRule = () => {
    try {
      return JSON.parse(ruleText) as Record<string, unknown>;
    } catch {
      throw new Error('Dynamic rule must be valid JSON.');
    }
  };
  const runPreview = async () => {
    if (!token) return;
    setError(null);
    try {
      const result = await api.previewAssetGroup(token, parseRule(), siteId || null);
      setPreview(result.total);
    } catch (previewError) {
      setError(errorMessage(previewError, 'Failed to preview group.'));
    }
  };
  const submit = async () => {
    if (!token || !name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await api.createAssetGroup(token, {
        name,
        group_type: groupType,
        site_id: siteId || null,
        priority: Number(priority) || 0,
        owner_user_id: ownerId || null,
        rule_json: groupType === 'dynamic' ? parseRule() : null,
      });
      setName('');
      setPreview(null);
      onCreated();
    } catch (submitError) {
      setError(errorMessage(submitError, 'Failed to create asset group.'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Create asset group"
      description="Equal ownership priorities that could overlap are rejected."
      wide
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          {groupType === 'dynamic' && (
            <Button variant="outline" onClick={() => void runPreview()}>
              Preview
            </Button>
          )}
          <Button
            variant="primary"
            loading={busy}
            disabled={!name.trim()}
            onClick={() => void submit()}
          >
            Create group
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {error && <InlineError className="sm:col-span-2" message={error} />}
        <Field label="Name">
          <Input value={name} onChange={(event) => setName(event.target.value)} />
        </Field>
        <Field label="Type">
          <Select
            value={groupType}
            onChange={(event) => {
              setGroupType(event.target.value as 'static' | 'dynamic');
              setPreview(null);
            }}
          >
            <option value="static">Static</option>
            <option value="dynamic">Dynamic</option>
          </Select>
        </Field>
        <Field label="Site">
          <Select value={siteId} onChange={(event) => setSiteId(event.target.value)}>
            <option value="">All sites</option>
            {sites.map((site) => (
              <option key={site.id} value={site.id}>
                {site.name}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Ownership priority">
          <Input
            type="number"
            value={priority}
            onChange={(event) => setPriority(event.target.value)}
          />
        </Field>
        <Field label="Group owner" className="sm:col-span-2">
          <Select value={ownerId} onChange={(event) => setOwnerId(event.target.value)}>
            <option value="">No ownership rule</option>
            {users.map((candidate) => (
              <option key={candidate.id} value={candidate.id}>
                {candidate.full_name || candidate.email}
              </option>
            ))}
          </Select>
        </Field>
        {groupType === 'dynamic' && (
          <Field
            label="Rule JSON"
            hint="Allowed fields and operators are validated server-side; expressions are never executed."
            className="sm:col-span-2"
          >
            <Textarea
              className="min-h-40 font-mono"
              value={ruleText}
              onChange={(event) => {
                setRuleText(event.target.value);
                setPreview(null);
              }}
            />
            {preview !== null && <p className="text-xs text-ok">Matches {preview} assets.</p>}
          </Field>
        )}
      </div>
    </Modal>
  );
}
