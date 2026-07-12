import { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, CheckCircle2, HardDrive, Plus, XCircle } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { humanize } from '../lib/utils';
import { StatusBadge } from '../components/app/badges';
import { DataTable, type ColumnDef, type FilterDef } from '../components/app/data-table';
import { StatTile } from '../components/app/metric-card';
import { PageHeader } from '../components/app/page-header';
import { Button } from '../components/ui/button';
import { Drawer } from '../components/ui/overlay';
import { Tabs } from '../components/ui/tabs';
import { AddScoutPage } from './AddScoutPage';
import { RelayPage } from './RelayPage';
import { useNav } from '../lib/nav';
import type { ProbeSummary } from '../types/onboarding';
import type { Site } from '../types/inventory';

const ONLINE_STATES = ['connected', 'online', 'enrolled', 'active'];
const WARN_STATES = ['degraded', 'stale', 'pending', 'warning', 'pending_enrollment'];

/** Appliances: fleet health for Scouts, plus the opt-in Relay mode as a tab.
 *  Shows the live probe fields the API exposes (name, site, status, pentest
 *  mode); per-appliance resource telemetry is not surfaced until the API
 *  reports it. */
export function AppliancesPage() {
  const { token, user } = useAuth();
  const { current } = useNav();
  const [probes, setProbes] = useState<ProbeSummary[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState(current.params.tab === 'relay' ? 'relay' : 'scouts');
  const [addOpen, setAddOpen] = useState(false);

  const isAdmin = user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [probePage, sitePage] = await Promise.all([
        api.listProbes(token),
        api.listSites(token),
      ]);
      setProbes(probePage.items);
      setSites(sitePage.items);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load appliances.');
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

  const online = probes.filter((r) => ONLINE_STATES.includes(r.status.toLowerCase()));
  const warning = probes.filter((r) => WARN_STATES.includes(r.status.toLowerCase()));
  const offline = probes.filter(
    (r) =>
      !ONLINE_STATES.includes(r.status.toLowerCase()) &&
      !WARN_STATES.includes(r.status.toLowerCase()),
  );

  const columns: ColumnDef<ProbeSummary>[] = useMemo(
    () => [
      {
        id: 'name',
        header: 'Appliance',
        cell: (r) => <span className="font-medium text-text">{r.name}</span>,
        sortValue: (r) => r.name,
        csvValue: (r) => r.name,
      },
      {
        id: 'site',
        header: 'Site',
        cell: (r) => <span className="text-xs text-muted">{siteName(r.site_id)}</span>,
        sortValue: (r) => siteName(r.site_id),
        csvValue: (r) => siteName(r.site_id),
      },
      {
        id: 'status',
        header: 'Status',
        cell: (r) => <StatusBadge status={r.status} />,
        sortValue: (r) => r.status,
        csvValue: (r) => r.status,
      },
      {
        id: 'pentest',
        header: 'Pentest',
        cell: (r) =>
          r.pentest_enabled ? (
            <span className="text-xs text-warn">Enabled</span>
          ) : (
            <span className="text-faint">Scan-only</span>
          ),
        sortValue: (r) => (r.pentest_enabled ? 1 : 0),
        csvValue: (r) => (r.pentest_enabled ? 'enabled' : 'scan-only'),
      },
    ],
    [siteName],
  );

  const filters: FilterDef<ProbeSummary>[] = useMemo(
    () => [
      {
        id: 'site',
        label: 'Site',
        options: sites.map((s) => ({ value: s.id, label: s.name })),
        predicate: (r, v) => r.site_id === v,
      },
      {
        id: 'status',
        label: 'Status',
        options: [...new Set(probes.map((r) => r.status))].map((s) => ({
          value: s,
          label: humanize(s),
        })),
        predicate: (r, v) => r.status === v,
      },
    ],
    [sites, probes],
  );

  return (
    <div aria-label="Appliances">
      <PageHeader
        crumbs={[{ label: 'Management' }, { label: 'Appliances' }]}
        title="Appliances"
        description="VulnaScout probes and relay endpoints across your sites."
        actions={
          isAdmin &&
          tab === 'scouts' && (
            <Button variant="primary" onClick={() => setAddOpen(true)}>
              <Plus size={14} aria-hidden /> Add Scout
            </Button>
          )
        }
      />

      <div className="mb-4 grid grid-cols-3 gap-3">
        <StatTile
          loading={loading}
          label="Online"
          value={online.length}
          icon={CheckCircle2}
          tone="ok"
        />
        <StatTile
          loading={loading}
          label="Warning"
          value={warning.length}
          icon={AlertTriangle}
          tone={warning.length > 0 ? 'warn' : 'default'}
        />
        <StatTile
          loading={loading}
          label="Offline"
          value={offline.length}
          icon={XCircle}
          tone={offline.length > 0 ? 'bad' : 'default'}
        />
      </div>

      <Tabs
        className="mb-3"
        tabs={[
          { id: 'scouts', label: 'Scouts', count: probes.length },
          { id: 'relay', label: 'Relay' },
        ]}
        value={tab}
        onChange={setTab}
      />

      {tab === 'scouts' ? (
        <DataTable<ProbeSummary>
          columns={columns}
          rows={probes}
          rowKey={(r) => r.id}
          searchText={(r) => `${r.name} ${siteName(r.site_id)} ${r.status}`}
          searchPlaceholder="Search appliances…"
          filters={filters}
          loading={loading}
          error={error}
          onRetry={() => void load()}
          emptyTitle="No appliances enrolled"
          emptyDescription="Add a VulnaScout to start assessing a site — it enrolls outbound, with no inbound port required."
          emptyAction={
            isAdmin ? (
              <Button variant="primary" size="sm" onClick={() => setAddOpen(true)}>
                <Plus size={13} aria-hidden /> Add Scout
              </Button>
            ) : undefined
          }
          exportName="appliances"
          storageKey="vulnadash.appliances"
          defaultSort={{ id: 'name', dir: 'asc' }}
        />
      ) : (
        <RelayPage />
      )}

      <Drawer
        open={addOpen}
        onClose={() => setAddOpen(false)}
        title={
          <span className="flex items-center gap-2">
            <HardDrive size={15} className="text-accent" aria-hidden /> Add a remote VulnaScout
          </span>
        }
      >
        <AddScoutPage />
      </Drawer>
    </div>
  );
}
