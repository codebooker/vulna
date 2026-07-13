import { useCallback, useEffect, useMemo, useState } from 'react';
import { BarChart3, Boxes, FileText, Link2, Play, Plus, RefreshCw } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { DataTable, type ColumnDef } from '../components/app/data-table';
import { PageHeader } from '../components/app/page-header';
import { StatTile } from '../components/app/metric-card';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card, CardBody, CardHeader } from '../components/ui/card';
import { Field, Input, Select, Textarea } from '../components/ui/input';
import { InlineError } from '../components/ui/states';
import { Tabs } from '../components/ui/tabs';
import { useToast } from '../lib/toast';
import { humanize } from '../lib/utils';
import type { Site } from '../types/inventory';
import type {
  InventoryConnector,
  InventoryDashboard,
  PassiveConnectorType,
  ReconciliationCandidate,
  ReportTemplate,
} from '../types/passive-inventory';

const CONNECTOR_TYPES: PassiveConnectorType[] = [
  'dhcp',
  'dns',
  'active_directory',
  'entra',
  'unifi',
  'vcenter',
  'proxmox',
  'xcp_ng',
  'aws',
  'azure',
  'google_cloud',
  'csv',
  'generic_api',
];

export function PassiveInventoryPage() {
  const { token, user } = useAuth();
  const { toast } = useToast();
  const [tab, setTab] = useState('overview');
  const [dashboard, setDashboard] = useState<InventoryDashboard | null>(null);
  const [connectors, setConnectors] = useState<InventoryConnector[]>([]);
  const [candidates, setCandidates] = useState<ReconciliationCandidate[]>([]);
  const [templates, setTemplates] = useState<ReportTemplate[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [connectorForm, setConnectorForm] = useState({
    name: '',
    siteId: '',
    type: 'csv' as PassiveConnectorType,
    baseUrl: '',
    username: '',
    secret: '',
    allowPrivate: false,
    legacyControlAgent: false,
    dnsZones: '',
    tsigName: '',
    allowUnsigned: false,
    directoryBaseDn: '',
    trustPem: '',
    entraTenantId: '',
    entraClientId: '',
    entraCloud: 'global',
  });
  const [csvFile, setCsvFile] = useState<File | null>(null);
  const [templateForm, setTemplateForm] = useState({
    name: '',
    siteId: '',
    password: '',
  });
  const canManageConnectors =
    user?.permissions?.includes('connectors.manage') ?? user?.role === 'administrator';
  const canRunConnectors =
    user?.permissions?.includes('connectors.run') ?? user?.role === 'administrator';
  const canReconcile =
    user?.permissions?.includes('reconciliation.manage') ?? user?.role === 'administrator';
  const canManageTemplates =
    user?.permissions?.includes('report_templates.manage') ?? user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    setError(null);
    const results = await Promise.allSettled([
      api.inventoryDashboard(token),
      api.listInventoryConnectors(token),
      api.listReconciliationCandidates(token),
      api.listReportTemplates(token),
      api.listSites(token),
    ]);
    if (results[0].status === 'fulfilled') setDashboard(results[0].value);
    if (results[1].status === 'fulfilled') setConnectors(results[1].value);
    if (results[2].status === 'fulfilled') setCandidates(results[2].value);
    if (results[3].status === 'fulfilled') setTemplates(results[3].value);
    const siteResult = results[4];
    if (siteResult.status === 'fulfilled') {
      const loadedSites = siteResult.value.items;
      setSites(loadedSites);
      setConnectorForm((current) => ({
        ...current,
        siteId: current.siteId || loadedSites[0]?.id || '',
      }));
      setTemplateForm((current) => ({
        ...current,
        siteId: current.siteId || loadedSites[0]?.id || '',
      }));
    }
    const rejected = results.find((result) => result.status === 'rejected');
    if (rejected?.status === 'rejected') {
      setError(
        rejected.reason instanceof Error ? rejected.reason.message : 'Some data could not load.',
      );
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const createConnector = useCallback(async () => {
    if (!token || !connectorForm.name || !connectorForm.siteId) return;
    const dnsZones = connectorForm.dnsZones
      .split(/[\n,]/)
      .map((zone) => zone.trim())
      .filter(Boolean);
    if (connectorForm.type === 'csv' && !csvFile) {
      setError('Select a CSV file before saving this source.');
      return;
    }
    if (
      connectorForm.type === 'dhcp' &&
      (!connectorForm.baseUrl || !connectorForm.username || !connectorForm.secret)
    ) {
      setError('Kea DHCP sources require an HTTPS URL, username, and password.');
      return;
    }
    if (
      connectorForm.type === 'dns' &&
      (!connectorForm.baseUrl ||
        dnsZones.length === 0 ||
        (!connectorForm.allowUnsigned && (!connectorForm.tsigName || !connectorForm.secret)) ||
        ((connectorForm.tsigName || connectorForm.secret) &&
          (!connectorForm.tsigName || !connectorForm.secret)))
    ) {
      setError(
        'DNS sources require a server, at least one zone, and either a TSIG key name with base64 secret or explicit unsigned AXFR.',
      );
      return;
    }
    if (
      connectorForm.type === 'active_directory' &&
      (!connectorForm.baseUrl ||
        !connectorForm.username ||
        !connectorForm.secret ||
        !connectorForm.directoryBaseDn)
    ) {
      setError('Active Directory sources require a server, bind user, password, and base DN.');
      return;
    }
    if (
      connectorForm.type === 'entra' &&
      (!connectorForm.entraTenantId || !connectorForm.entraClientId || !connectorForm.secret)
    ) {
      setError('Microsoft Entra sources require a tenant ID, application client ID, and secret.');
      return;
    }
    setBusy('connector');
    setError(null);
    let connectorCreated = false;
    try {
      const connector = await api.createInventoryConnector(token, {
        site_id: connectorForm.siteId,
        name: connectorForm.name,
        connector_type: connectorForm.type,
        ...(connectorForm.type !== 'csv' &&
        connectorForm.type !== 'dns' &&
        connectorForm.type !== 'active_directory' &&
        connectorForm.type !== 'entra' &&
        connectorForm.baseUrl
          ? { base_url: connectorForm.baseUrl }
          : {}),
        ...(connectorForm.type !== 'csv' && connectorForm.secret
          ? { secret: connectorForm.secret }
          : {}),
        ...(connectorForm.type === 'dhcp'
          ? {
              config: {
                username: connectorForm.username,
                allow_private: connectorForm.allowPrivate,
                legacy_control_agent: connectorForm.legacyControlAgent,
              },
            }
          : {}),
        ...(connectorForm.type === 'dns'
          ? {
              config: {
                server: connectorForm.baseUrl,
                zones: dnsZones,
                allow_private: connectorForm.allowPrivate,
                allow_unsigned: connectorForm.allowUnsigned,
                ...(connectorForm.tsigName
                  ? {
                      tsig_name: connectorForm.tsigName,
                      tsig_algorithm: 'hmac-sha256',
                    }
                  : {}),
              },
            }
          : {}),
        ...(connectorForm.type === 'active_directory'
          ? {
              config: {
                server: connectorForm.baseUrl,
                bind_user: connectorForm.username,
                base_dn: connectorForm.directoryBaseDn,
                allow_private: connectorForm.allowPrivate,
                ...(connectorForm.trustPem ? { trust_pem: connectorForm.trustPem } : {}),
              },
            }
          : {}),
        ...(connectorForm.type === 'entra'
          ? {
              config: {
                tenant_id: connectorForm.entraTenantId,
                client_id: connectorForm.entraClientId,
                cloud: connectorForm.entraCloud,
              },
            }
          : {}),
        interval_minutes: 1440,
      });
      connectorCreated = true;
      if (connectorForm.type === 'csv' && csvFile) {
        await api.uploadInventoryCsv(token, connector.id, csvFile);
      }
      setConnectorForm((current) => ({
        ...current,
        name: '',
        baseUrl: '',
        username: '',
        secret: '',
        allowPrivate: false,
        legacyControlAgent: false,
        dnsZones: '',
        tsigName: '',
        allowUnsigned: false,
        directoryBaseDn: '',
        trustPem: '',
        entraTenantId: '',
        entraClientId: '',
        entraCloud: 'global',
      }));
      setCsvFile(null);
      toast('success', 'Inventory source saved disabled. Test it before enabling collection.');
      await load();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Inventory source could not be saved.';
      setError(
        connectorCreated
          ? `The source was created disabled, but its CSV upload failed: ${message} Replace the file from the source row.`
          : message,
      );
      if (connectorCreated) await load();
    } finally {
      setBusy(null);
    }
  }, [connectorForm, csvFile, load, toast, token]);

  const replaceCsv = useCallback(
    async (connector: InventoryConnector, file: File) => {
      if (!token) return;
      if (file.size > 5 * 1024 * 1024) {
        setError('CSV files cannot exceed 5 MiB.');
        return;
      }
      setBusy(connector.id);
      setError(null);
      try {
        await api.uploadInventoryCsv(token, connector.id, file);
        toast('success', 'Encrypted CSV source replaced. Test it before enabling collection.');
        await load();
      } catch (err) {
        setError(err instanceof Error ? err.message : 'CSV source could not be uploaded.');
      } finally {
        setBusy(null);
      }
    },
    [load, toast, token],
  );

  const decide = useCallback(
    async (candidate: ReconciliationCandidate, action: 'approve' | 'reject' | 'split') => {
      if (!token) return;
      setBusy(candidate.id);
      try {
        await api.decideReconciliation(token, candidate.id, action);
        toast('success', `Reconciliation ${action} recorded with an audit trail.`);
        await load();
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Reconciliation could not be updated.');
      } finally {
        setBusy(null);
      }
    },
    [load, toast, token],
  );

  const actOnConnector = useCallback(
    async (connector: InventoryConnector, action: 'test' | 'toggle' | 'run' | 'clear_csv') => {
      if (!token) return;
      if (
        action === 'clear_csv' &&
        !window.confirm('Clear this encrypted CSV source? Collected observations are retained.')
      ) {
        return;
      }
      setBusy(connector.id);
      setError(null);
      try {
        if (action === 'test') {
          const result = await api.testInventoryConnector(token, connector.id);
          if (!result.succeeded) throw new Error(result.error || 'Connector test failed.');
          toast('success', 'Read-only connector test succeeded.');
        } else if (action === 'toggle') {
          await api.updateInventoryConnector(token, connector.id, {
            enabled: !connector.enabled,
          });
          toast('success', connector.enabled ? 'Connector disabled.' : 'Connector enabled.');
        } else if (action === 'run') {
          await api.runInventoryConnector(token, connector.id);
          toast('success', 'Inventory collection queued.');
        } else {
          await api.clearInventoryCsv(token, connector.id);
          toast('success', 'Encrypted CSV source cleared. Existing observations were retained.');
        }
        await load();
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Connector action failed.');
      } finally {
        setBusy(null);
      }
    },
    [load, toast, token],
  );

  const createTemplate = useCallback(async () => {
    if (!token || !templateForm.name) return;
    setBusy('template');
    try {
      await api.createReportTemplate(token, {
        ...(templateForm.siteId ? { site_id: templateForm.siteId } : {}),
        name: templateForm.name,
        report_types: ['executive_pdf', 'findings_csv'],
        sections: ['summary', 'findings'],
        redaction: { fields: [] },
        branding: {},
        ...(templateForm.password ? { export_password: templateForm.password } : {}),
      });
      setTemplateForm((current) => ({ ...current, name: '', password: '' }));
      toast('success', 'Reusable report template created.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Report template could not be created.');
    } finally {
      setBusy(null);
    }
  }, [load, templateForm, toast, token]);

  const connectorColumns: ColumnDef<InventoryConnector>[] = useMemo(
    () => [
      {
        id: 'name',
        header: 'Source',
        cell: (row) => (
          <div>
            <p className="font-medium text-text">{row.name}</p>
            <p className="text-xs text-muted">{humanize(row.connector_type)}</p>
            {row.connector_type === 'csv' && row.has_source_data && (
              <p className="text-xs text-muted">
                {row.source_filename} · {Math.ceil((row.source_size_bytes ?? 0) / 1024)} KiB
              </p>
            )}
          </div>
        ),
      },
      { id: 'site', header: 'Site', cell: (row) => row.site_id },
      {
        id: 'test',
        header: 'Qualification',
        cell: (row) => (
          <Badge tone={row.successful_test_at ? 'ok' : row.last_test_error ? 'bad' : 'warn'}>
            {row.successful_test_at ? 'Tested' : row.last_test_error ? 'Failed' : 'Test required'}
          </Badge>
        ),
      },
      {
        id: 'state',
        header: 'State',
        cell: (row) => (
          <Badge tone={row.enabled ? 'ok' : 'neutral'}>
            {row.enabled ? 'Enabled' : 'Disabled'}
          </Badge>
        ),
      },
      {
        id: 'actions',
        header: 'Actions',
        cell: (row) => (
          <div className="flex flex-wrap gap-1">
            {canManageConnectors && (
              <Button
                size="sm"
                variant="secondary"
                onClick={() => void actOnConnector(row, 'test')}
                disabled={busy === row.id}
              >
                Test
              </Button>
            )}
            {canManageConnectors && row.successful_test_at && (
              <Button
                size="sm"
                variant="secondary"
                onClick={() => void actOnConnector(row, 'toggle')}
                disabled={busy === row.id}
              >
                {row.enabled ? 'Disable' : 'Enable'}
              </Button>
            )}
            {canRunConnectors && row.enabled && (
              <Button
                size="sm"
                onClick={() => void actOnConnector(row, 'run')}
                disabled={busy === row.id}
              >
                <Play size={13} /> Run
              </Button>
            )}
            {canManageConnectors && row.connector_type === 'csv' && row.has_source_data && (
              <Button
                size="sm"
                variant="secondary"
                onClick={() => void actOnConnector(row, 'clear_csv')}
                disabled={busy === row.id}
              >
                Clear file
              </Button>
            )}
            {canManageConnectors && row.connector_type === 'csv' && (
              <Input
                aria-label={`Replace CSV for ${row.name}`}
                type="file"
                accept=".csv,text/csv"
                className="max-w-48 text-xs"
                disabled={busy === row.id}
                onChange={(event) => {
                  const file = event.target.files?.[0];
                  event.target.value = '';
                  if (file) void replaceCsv(row, file);
                }}
              />
            )}
          </div>
        ),
      },
    ],
    [actOnConnector, busy, canManageConnectors, canRunConnectors, replaceCsv],
  );

  const candidateColumns: ColumnDef<ReconciliationCandidate>[] = useMemo(
    () => [
      { id: 'asset', header: 'Candidate asset', cell: (row) => row.candidate_asset_id },
      {
        id: 'score',
        header: 'Confidence',
        cell: (row) => <span className="font-semibold tabular-nums">{row.score.toFixed(0)}</span>,
      },
      {
        id: 'explanation',
        header: 'Explanation',
        cell: (row) => (
          <span className="text-xs text-muted">
            {row.conflicts_json.length
              ? `${row.conflicts_json.length} conflict(s) block auto-merge`
              : `${row.reasons_json.length} exact identifier match(es)`}
          </span>
        ),
      },
      { id: 'status', header: 'Status', cell: (row) => <Badge>{humanize(row.status)}</Badge> },
      {
        id: 'actions',
        header: 'Actions',
        cell: (row) =>
          canReconcile && row.status === 'pending' ? (
            <div className="flex gap-1">
              <Button
                size="sm"
                onClick={() => void decide(row, 'approve')}
                disabled={busy === row.id}
              >
                Approve
              </Button>
              <Button size="sm" variant="secondary" onClick={() => void decide(row, 'reject')}>
                Separate
              </Button>
            </div>
          ) : null,
      },
    ],
    [busy, canReconcile, decide],
  );

  return (
    <div className="space-y-4">
      <PageHeader
        title="Inventory intelligence"
        description="Read-only sources, explainable reconciliation, scoped analytics, and reusable reports."
        actions={
          <Button variant="secondary" onClick={() => void load()}>
            <RefreshCw size={14} /> Refresh
          </Button>
        }
      />
      {error && <InlineError message={error} />}
      <Tabs
        tabs={[
          { id: 'overview', label: 'Overview' },
          { id: 'sources', label: 'Sources', count: connectors.length },
          { id: 'reconciliation', label: 'Reconciliation', count: candidates.length },
          { id: 'reports', label: 'Report builder', count: templates.length },
        ]}
        value={tab}
        onChange={setTab}
      />

      {tab === 'overview' && (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <StatTile label="Tracked assets" value={dashboard?.inventory.total ?? 0} icon={Boxes} />
          <StatTile label="Open findings" value={dashboard?.findings.open ?? 0} icon={BarChart3} />
          <StatTile
            label="SLA breaches"
            value={dashboard?.findings.breached ?? 0}
            icon={FileText}
            tone={dashboard?.findings.breached ? 'bad' : 'ok'}
          />
          <StatTile
            label="Needs reconciliation"
            value={dashboard?.inventory.pending_reconciliation ?? 0}
            icon={Link2}
            tone={dashboard?.inventory.pending_reconciliation ? 'warn' : 'ok'}
          />
        </div>
      )}

      {tab === 'sources' && (
        <div className="space-y-4">
          {canManageConnectors && (
            <Card>
              <CardHeader
                title="Add a read-only source"
                description="Secrets are encrypted and never returned. New sources stay disabled until a successful test."
              />
              <CardBody className="grid gap-3 md:grid-cols-6">
                <Field label="Name">
                  <Input
                    aria-label="Name"
                    value={connectorForm.name}
                    onChange={(event) =>
                      setConnectorForm((current) => ({ ...current, name: event.target.value }))
                    }
                  />
                </Field>
                <Field label="Site">
                  <Select
                    aria-label="Site"
                    value={connectorForm.siteId}
                    onChange={(event) =>
                      setConnectorForm((current) => ({ ...current, siteId: event.target.value }))
                    }
                  >
                    {sites.map((site) => (
                      <option key={site.id} value={site.id}>
                        {site.name}
                      </option>
                    ))}
                  </Select>
                </Field>
                <Field label="Type">
                  <Select
                    aria-label="Type"
                    value={connectorForm.type}
                    onChange={(event) =>
                      setConnectorForm((current) => ({
                        ...current,
                        type: event.target.value as PassiveConnectorType,
                      }))
                    }
                  >
                    {CONNECTOR_TYPES.map((type) => (
                      <option key={type} value={type}>
                        {humanize(type)}
                      </option>
                    ))}
                  </Select>
                </Field>
                {connectorForm.type === 'csv' ? (
                  <Field label="CSV file (5 MiB maximum)">
                    <Input
                      aria-label="CSV file (5 MiB maximum)"
                      type="file"
                      accept=".csv,text/csv"
                      onChange={(event) => {
                        const file = event.target.files?.[0] ?? null;
                        if (file && file.size > 5 * 1024 * 1024) {
                          setCsvFile(null);
                          setError('CSV files cannot exceed 5 MiB.');
                          event.target.value = '';
                        } else {
                          setCsvFile(file);
                        }
                      }}
                    />
                  </Field>
                ) : (
                  <>
                    {connectorForm.type !== 'entra' && (
                      <Field
                        label={
                          connectorForm.type === 'dns'
                            ? 'Authoritative DNS server'
                            : connectorForm.type === 'active_directory'
                              ? 'Directory server'
                              : 'HTTPS URL (when required)'
                        }
                      >
                        <Input
                          aria-label={
                            connectorForm.type === 'dns'
                              ? 'Authoritative DNS server'
                              : connectorForm.type === 'active_directory'
                                ? 'Directory server'
                                : 'HTTPS URL (when required)'
                          }
                          value={connectorForm.baseUrl}
                          onChange={(event) =>
                            setConnectorForm((current) => ({
                              ...current,
                              baseUrl: event.target.value,
                            }))
                          }
                        />
                      </Field>
                    )}
                    {connectorForm.type === 'entra' && (
                      <>
                        <Field label="Microsoft Entra tenant ID">
                          <Input
                            aria-label="Microsoft Entra tenant ID"
                            placeholder="00000000-0000-0000-0000-000000000000"
                            value={connectorForm.entraTenantId}
                            onChange={(event) =>
                              setConnectorForm((current) => ({
                                ...current,
                                entraTenantId: event.target.value,
                              }))
                            }
                          />
                        </Field>
                        <Field label="Application client ID">
                          <Input
                            aria-label="Application client ID"
                            placeholder="00000000-0000-0000-0000-000000000000"
                            value={connectorForm.entraClientId}
                            onChange={(event) =>
                              setConnectorForm((current) => ({
                                ...current,
                                entraClientId: event.target.value,
                              }))
                            }
                          />
                        </Field>
                        <Field label="Microsoft cloud">
                          <Select
                            aria-label="Microsoft cloud"
                            value={connectorForm.entraCloud}
                            onChange={(event) =>
                              setConnectorForm((current) => ({
                                ...current,
                                entraCloud: event.target.value,
                              }))
                            }
                          >
                            <option value="global">Global</option>
                            <option value="us_government">US Government</option>
                            <option value="us_government_dod">US Government DoD</option>
                            <option value="china">China (21Vianet)</option>
                          </Select>
                        </Field>
                      </>
                    )}
                    {connectorForm.type === 'dhcp' && (
                      <>
                        <Field label="Kea username">
                          <Input
                            aria-label="Kea username"
                            value={connectorForm.username}
                            onChange={(event) =>
                              setConnectorForm((current) => ({
                                ...current,
                                username: event.target.value,
                              }))
                            }
                          />
                        </Field>
                        <Field label="Legacy Control Agent">
                          <Select
                            aria-label="Legacy Control Agent"
                            value={connectorForm.legacyControlAgent ? 'yes' : 'no'}
                            onChange={(event) =>
                              setConnectorForm((current) => ({
                                ...current,
                                legacyControlAgent: event.target.value === 'yes',
                              }))
                            }
                          >
                            <option value="no">No, direct daemon</option>
                            <option value="yes">Yes, route to dhcp4</option>
                          </Select>
                        </Field>
                      </>
                    )}
                    {connectorForm.type === 'active_directory' && (
                      <>
                        <Field label="Bind user">
                          <Input
                            aria-label="Bind user"
                            placeholder="vulna-reader@example.com"
                            value={connectorForm.username}
                            onChange={(event) =>
                              setConnectorForm((current) => ({
                                ...current,
                                username: event.target.value,
                              }))
                            }
                          />
                        </Field>
                        <Field label="Base DN">
                          <Input
                            aria-label="Base DN"
                            placeholder="DC=example,DC=com"
                            value={connectorForm.directoryBaseDn}
                            onChange={(event) =>
                              setConnectorForm((current) => ({
                                ...current,
                                directoryBaseDn: event.target.value,
                              }))
                            }
                          />
                        </Field>
                        <Field label="Directory CA PEM (optional)">
                          <Textarea
                            aria-label="Directory CA PEM (optional)"
                            placeholder="Use system trust, or paste the issuing CA certificate"
                            value={connectorForm.trustPem}
                            onChange={(event) =>
                              setConnectorForm((current) => ({
                                ...current,
                                trustPem: event.target.value,
                              }))
                            }
                          />
                        </Field>
                      </>
                    )}
                    {(connectorForm.type === 'dhcp' ||
                      connectorForm.type === 'dns' ||
                      connectorForm.type === 'active_directory') && (
                      <Field
                        label={
                          connectorForm.type === 'dns'
                            ? 'Private network server'
                            : connectorForm.type === 'active_directory'
                              ? 'Private directory server'
                              : 'Private network URL'
                        }
                      >
                        <Select
                          aria-label={
                            connectorForm.type === 'dns'
                              ? 'Private network server'
                              : connectorForm.type === 'active_directory'
                                ? 'Private directory server'
                                : 'Private network URL'
                          }
                          value={connectorForm.allowPrivate ? 'yes' : 'no'}
                          onChange={(event) =>
                            setConnectorForm((current) => ({
                              ...current,
                              allowPrivate: event.target.value === 'yes',
                            }))
                          }
                        >
                          <option value="no">No</option>
                          <option value="yes">Yes, explicitly allow</option>
                        </Select>
                      </Field>
                    )}
                    {connectorForm.type === 'dns' && (
                      <>
                        <Field label="Authoritative zones">
                          <Input
                            aria-label="Authoritative zones"
                            placeholder="example.com, 2.0.192.in-addr.arpa"
                            value={connectorForm.dnsZones}
                            onChange={(event) =>
                              setConnectorForm((current) => ({
                                ...current,
                                dnsZones: event.target.value,
                              }))
                            }
                          />
                        </Field>
                        <Field label="TSIG key name">
                          <Input
                            aria-label="TSIG key name"
                            placeholder="vulna-transfer.example.com."
                            value={connectorForm.tsigName}
                            onChange={(event) =>
                              setConnectorForm((current) => ({
                                ...current,
                                tsigName: event.target.value,
                              }))
                            }
                          />
                        </Field>
                        <Field label="Unsigned AXFR">
                          <Select
                            aria-label="Unsigned AXFR"
                            value={connectorForm.allowUnsigned ? 'yes' : 'no'}
                            onChange={(event) =>
                              setConnectorForm((current) => ({
                                ...current,
                                allowUnsigned: event.target.value === 'yes',
                              }))
                            }
                          >
                            <option value="no">No, require TSIG</option>
                            <option value="yes">Yes, explicitly allow</option>
                          </Select>
                        </Field>
                      </>
                    )}
                    <Field
                      label={
                        connectorForm.type === 'dhcp'
                          ? 'Kea password'
                          : connectorForm.type === 'dns'
                            ? 'TSIG secret (base64)'
                            : connectorForm.type === 'active_directory'
                              ? 'Bind password'
                              : connectorForm.type === 'entra'
                                ? 'Application client secret'
                                : 'Secret (optional)'
                      }
                    >
                      <Input
                        aria-label={
                          connectorForm.type === 'dhcp'
                            ? 'Kea password'
                            : connectorForm.type === 'dns'
                              ? 'TSIG secret (base64)'
                              : connectorForm.type === 'active_directory'
                                ? 'Bind password'
                                : connectorForm.type === 'entra'
                                  ? 'Application client secret'
                                  : 'Secret (optional)'
                        }
                        type="password"
                        value={connectorForm.secret}
                        onChange={(event) =>
                          setConnectorForm((current) => ({
                            ...current,
                            secret: event.target.value,
                          }))
                        }
                      />
                    </Field>
                  </>
                )}
                <div className="flex items-end">
                  <Button
                    onClick={() => void createConnector()}
                    disabled={
                      busy === 'connector' ||
                      (connectorForm.type === 'csv' && !csvFile) ||
                      (connectorForm.type === 'dhcp' &&
                        (!connectorForm.baseUrl ||
                          !connectorForm.username ||
                          !connectorForm.secret)) ||
                      (connectorForm.type === 'dns' &&
                        (!connectorForm.baseUrl ||
                          !connectorForm.dnsZones.trim() ||
                          (!connectorForm.allowUnsigned &&
                            (!connectorForm.tsigName || !connectorForm.secret)) ||
                          (Boolean(connectorForm.tsigName || connectorForm.secret) &&
                            (!connectorForm.tsigName || !connectorForm.secret)))) ||
                      (connectorForm.type === 'active_directory' &&
                        (!connectorForm.baseUrl ||
                          !connectorForm.username ||
                          !connectorForm.secret ||
                          !connectorForm.directoryBaseDn)) ||
                      (connectorForm.type === 'entra' &&
                        (!connectorForm.entraTenantId ||
                          !connectorForm.entraClientId ||
                          !connectorForm.secret))
                    }
                  >
                    <Plus size={14} /> Save source
                  </Button>
                </div>
              </CardBody>
            </Card>
          )}
          <DataTable columns={connectorColumns} rows={connectors} rowKey={(row) => row.id} />
        </div>
      )}

      {tab === 'reconciliation' && (
        <DataTable columns={candidateColumns} rows={candidates} rowKey={(row) => row.id} />
      )}

      {tab === 'reports' && (
        <div className="space-y-4">
          {canManageTemplates && (
            <Card>
              <CardHeader
                title="Create a report template"
                description="Templates retain filters, redaction, branding, and optional AES-256 PDF protection."
              />
              <CardBody className="grid gap-3 md:grid-cols-4">
                <Field label="Template name">
                  <Input
                    aria-label="Template name"
                    value={templateForm.name}
                    onChange={(event) =>
                      setTemplateForm((current) => ({ ...current, name: event.target.value }))
                    }
                  />
                </Field>
                <Field label="Site">
                  <Select
                    aria-label="Report site"
                    value={templateForm.siteId}
                    onChange={(event) =>
                      setTemplateForm((current) => ({ ...current, siteId: event.target.value }))
                    }
                  >
                    {sites.map((site) => (
                      <option key={site.id} value={site.id}>
                        {site.name}
                      </option>
                    ))}
                  </Select>
                </Field>
                <Field label="PDF password (optional)">
                  <Input
                    aria-label="PDF password (optional)"
                    type="password"
                    value={templateForm.password}
                    onChange={(event) =>
                      setTemplateForm((current) => ({ ...current, password: event.target.value }))
                    }
                  />
                </Field>
                <div className="flex items-end">
                  <Button onClick={() => void createTemplate()} disabled={busy === 'template'}>
                    <Plus size={14} /> Create
                  </Button>
                </div>
              </CardBody>
            </Card>
          )}
          <div className="grid gap-3 md:grid-cols-2">
            {templates.map((template) => (
              <Card key={template.id}>
                <CardHeader
                  title={template.name}
                  description={`Version ${template.version} · ${template.report_types_json.map(humanize).join(', ')}`}
                  actions={
                    <Badge tone={template.enabled ? 'ok' : 'neutral'}>
                      {template.enabled ? 'Enabled' : 'Disabled'}
                    </Badge>
                  }
                />
                <CardBody className="flex items-center justify-between text-xs text-muted">
                  <span>
                    {template.has_export_password ? 'Password-protected PDF' : 'No export password'}
                  </span>
                  {canManageTemplates && (
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() =>
                        token && void api.runReportTemplate(token, template.id).then(load)
                      }
                    >
                      <Play size={13} /> Generate
                    </Button>
                  )}
                </CardBody>
              </Card>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
