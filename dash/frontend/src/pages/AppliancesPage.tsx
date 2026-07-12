import { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, CheckCircle2, HardDrive, Plus, XCircle } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useNav } from '../lib/nav';
import { useToast } from '../lib/toast';
import { formatRelative, formatWhenFull, humanize } from '../lib/utils';
import { StatusBadge } from '../components/app/badges';
import { DataTable, type ColumnDef, type FilterDef } from '../components/app/data-table';
import { StatTile } from '../components/app/metric-card';
import { PageHeader } from '../components/app/page-header';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Field, Input } from '../components/ui/input';
import { Code, DetailRow } from '../components/ui/misc';
import { ConfirmDialog, Drawer } from '../components/ui/overlay';
import { InlineError } from '../components/ui/states';
import { Tabs } from '../components/ui/tabs';
import { AddScoutPage } from './AddScoutPage';
import { RelayPage } from './RelayPage';
import type { ProbeDetail, ProbeSummary } from '../types/onboarding';
import type { Site } from '../types/inventory';

const ONLINE_STATES = ['connected', 'online', 'enrolled', 'active'];
const WARN_STATES = ['degraded', 'stale', 'pending', 'warning', 'pending_enrollment'];

/** Appliances: fleet health for Scouts, plus Relay endpoints as a tab. Click a
 *  Scout to rename it and manage its lifecycle (approve, disable, revoke,
 *  pentest mode). */
export function AppliancesPage() {
  const { token, user } = useAuth();
  const { current } = useNav();
  const [probes, setProbes] = useState<ProbeSummary[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState(current.params.tab === 'relay' ? 'relay' : 'scouts');
  const [addOpen, setAddOpen] = useState(false);
  const [selected, setSelected] = useState<ProbeSummary | null>(null);

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

      {error && <InlineError message={error} className="mb-3" />}

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
          onRowClick={setSelected}
          loading={loading}
          error={null}
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

      <ApplianceDrawer
        probe={selected}
        siteName={siteName}
        isAdmin={isAdmin}
        onClose={() => setSelected(null)}
        onChanged={load}
      />

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

function ApplianceDrawer({
  probe,
  siteName,
  isAdmin,
  onClose,
  onChanged,
}: {
  probe: ProbeSummary | null;
  siteName: (id: string) => string;
  isAdmin: boolean;
  onClose: () => void;
  onChanged: () => void;
}) {
  const { token } = useAuth();
  const { toast } = useToast();
  const [detail, setDetail] = useState<ProbeDetail | null>(null);
  const [name, setName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmRevoke, setConfirmRevoke] = useState(false);

  useEffect(() => {
    if (!probe || !token) {
      setDetail(null);
      return;
    }
    setError(null);
    setDetail(null);
    api
      .getProbe(token, probe.id)
      .then((d) => {
        setDetail(d);
        setName(d.name);
      })
      .catch((e) => setError(e instanceof Error ? e.message : 'Failed to load appliance.'));
  }, [probe, token]);

  const run = async (fn: () => Promise<unknown>, success: string) => {
    if (!token || !probe) return;
    setBusy(true);
    setError(null);
    try {
      await fn();
      onChanged();
      setDetail(await api.getProbe(token, probe.id));
      toast('success', success);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Action failed.');
    } finally {
      setBusy(false);
    }
  };

  const canApprove = detail && ['pending_enrollment', 'disabled'].includes(detail.status);

  return (
    <Drawer
      open={probe !== null}
      onClose={onClose}
      title={
        <span className="flex items-center gap-2">
          <HardDrive size={15} className="shrink-0 text-accent" aria-hidden />
          {detail?.name ?? probe?.name}
        </span>
      }
      description={probe ? siteName(probe.site_id) : undefined}
    >
      {error && <InlineError message={error} className="mb-3" />}
      {!detail ? (
        <p className="text-sm text-muted">Loading…</p>
      ) : (
        <div className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center gap-1.5">
            <StatusBadge status={detail.status} />
            {detail.online && <Badge tone="ok">Online</Badge>}
            {detail.pentest_enabled && <Badge tone="warn">Pentest</Badge>}
          </div>

          {isAdmin && (
            <div className="flex items-end gap-2">
              <Field label="Name" htmlFor="probe-name" className="flex-1">
                <Input id="probe-name" value={name} onChange={(e) => setName(e.target.value)} />
              </Field>
              <Button
                variant="outline"
                disabled={busy || !name.trim() || name === detail.name}
                onClick={() =>
                  void run(
                    () => api.updateProbe(token!, detail.id, { name: name.trim() }),
                    'Appliance renamed.',
                  )
                }
              >
                Save
              </Button>
            </div>
          )}

          <dl className="divide-y divide-border rounded-lg border border-border px-3">
            <DetailRow label="Site">{siteName(detail.site_id)}</DetailRow>
            <DetailRow label="Status">{humanize(detail.status)}</DetailRow>
            <DetailRow label="Operating system">
              {detail.operating_system ?? '—'}
              {detail.architecture ? ` (${detail.architecture})` : ''}
            </DetailRow>
            <DetailRow label="Hostname">{detail.hostname ?? '—'}</DetailRow>
            <DetailRow label="IP address">
              {detail.primary_ip ? <Code>{detail.primary_ip}</Code> : '—'}
            </DetailRow>
            <DetailRow label="Agent version">{detail.agent_version ?? '—'}</DetailRow>
            <DetailRow label="Certificate">
              <Code>{detail.certificate_fingerprint.slice(0, 24)}…</Code>
            </DetailRow>
            <DetailRow label="Last seen">{formatRelative(detail.last_seen_at)}</DetailRow>
            <DetailRow label="Enrolled">{formatWhenFull(detail.enrolled_at)}</DetailRow>
          </dl>

          {isAdmin && (
            <div className="flex flex-wrap gap-2">
              {canApprove && (
                <Button
                  variant="primary"
                  size="sm"
                  disabled={busy}
                  onClick={() =>
                    void run(
                      () => api.probeLifecycle(token!, detail.id, 'approve'),
                      'Appliance approved.',
                    )
                  }
                >
                  Approve
                </Button>
              )}
              {detail.status === 'enrolled' && (
                <Button
                  variant="outline"
                  size="sm"
                  disabled={busy}
                  onClick={() =>
                    void run(
                      () => api.probeLifecycle(token!, detail.id, 'disable'),
                      'Appliance disabled.',
                    )
                  }
                >
                  Disable
                </Button>
              )}
              <Button
                variant="outline"
                size="sm"
                disabled={busy}
                onClick={() =>
                  void run(
                    () => api.setProbePentest(token!, detail.id, !detail.pentest_enabled),
                    detail.pentest_enabled ? 'Pentest mode disabled.' : 'Pentest mode enabled.',
                  )
                }
              >
                {detail.pentest_enabled ? 'Disable pentest' : 'Enable pentest'}
              </Button>
              {detail.status !== 'revoked' && (
                <Button
                  variant="destructive"
                  size="sm"
                  disabled={busy}
                  onClick={() => setConfirmRevoke(true)}
                >
                  Revoke
                </Button>
              )}
            </div>
          )}
        </div>
      )}

      <ConfirmDialog
        open={confirmRevoke}
        onClose={() => setConfirmRevoke(false)}
        destructive
        busy={busy}
        title={`Revoke “${detail?.name}”?`}
        body="The appliance's certificate is revoked; it can no longer connect or run scans. To use it again you would re-enroll it."
        confirmLabel="Revoke appliance"
        onConfirm={() => {
          if (token && detail) {
            void run(
              () => api.probeLifecycle(token, detail.id, 'revoke'),
              'Appliance revoked.',
            ).then(() => {
              setConfirmRevoke(false);
              onClose();
            });
          }
        }}
      />
    </Drawer>
  );
}
