import { useCallback, useEffect, useMemo, useState } from 'react';
import { CheckCircle2, Clock3, Plus, RefreshCw, TicketCheck } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { DataTable, type ColumnDef } from '../components/app/data-table';
import { PageHeader } from '../components/app/page-header';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card, CardBody, CardHeader } from '../components/ui/card';
import { Field, Input, Select } from '../components/ui/input';
import { InlineError } from '../components/ui/states';
import { Tabs } from '../components/ui/tabs';
import { useToast } from '../lib/toast';
import { humanize } from '../lib/utils';
import type {
  SlaMetrics,
  SlaPolicy,
  TicketConnector,
  TicketConnectorType,
  TicketSync,
} from '../types/sla-ticketing';

const PROVIDERS: TicketConnectorType[] = ['github', 'gitlab', 'glpi', 'jira', 'generic'];

export function SlaTicketingPage() {
  const { token, user } = useAuth();
  const { toast } = useToast();
  const [tab, setTab] = useState('sla');
  const [policies, setPolicies] = useState<SlaPolicy[]>([]);
  const [metrics, setMetrics] = useState<SlaMetrics | null>(null);
  const [connectors, setConnectors] = useState<TicketConnector[]>([]);
  const [syncs, setSyncs] = useState<TicketSync[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const canManageSla = user?.permissions?.includes('sla.manage') ?? user?.role === 'administrator';
  const canManageConnectors =
    user?.permissions?.includes('ticketing.manage') ?? user?.role === 'administrator';
  const canSync = user?.permissions?.includes('ticketing.sync') ?? user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [nextPolicies, nextMetrics, nextConnectors, nextSyncs] = await Promise.all([
        api.listSlaPolicies(token),
        api.slaMetrics(token),
        api.listTicketConnectors(token),
        api.listTicketSyncs(token),
      ]);
      setPolicies(nextPolicies);
      setMetrics(nextMetrics);
      setConnectors(nextConnectors);
      setSyncs(nextSyncs);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Remediation operations could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const testConnector = useCallback(
    async (connector: TicketConnector) => {
      if (!token) return;
      setBusy(connector.id);
      try {
        const result = await api.testTicketConnector(token, connector.id);
        if (!result.succeeded) throw new Error(result.error ?? 'Connector test failed.');
        toast('success', 'Connector test passed. It may now be enabled.');
        await load();
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Connector test failed.');
      } finally {
        setBusy(null);
      }
    },
    [load, toast, token],
  );

  const toggleConnector = useCallback(
    async (connector: TicketConnector) => {
      if (!token) return;
      setBusy(connector.id);
      try {
        await api.updateTicketConnector(token, connector.id, { enabled: !connector.enabled });
        toast('success', connector.enabled ? 'Connector disabled.' : 'Connector enabled.');
        await load();
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Connector state could not be changed.');
      } finally {
        setBusy(null);
      }
    },
    [load, toast, token],
  );

  const policyColumns: ColumnDef<SlaPolicy>[] = useMemo(
    () => [
      {
        id: 'priority',
        header: 'Priority',
        cell: (row) => row.priority,
        sortValue: (row) => row.priority,
      },
      {
        id: 'name',
        header: 'Policy',
        cell: (row) => <span className="font-medium text-text">{row.name}</span>,
        sortValue: (row) => row.name,
      },
      {
        id: 'match',
        header: 'First-match criteria',
        cell: (row) => (
          <span className="text-xs text-muted">
            {Object.keys(row.match_json).length ? JSON.stringify(row.match_json) : 'All findings'}
          </span>
        ),
      },
      {
        id: 'critical',
        header: 'Critical due',
        cell: (row) => `${row.due_days_json.critical ?? '—'} days`,
        sortValue: (row) => row.due_days_json.critical ?? 0,
      },
      {
        id: 'pause',
        header: 'Risk acceptance',
        cell: (row) => (
          <Badge tone={row.pause_on_risk_acceptance ? 'warn' : 'neutral'}>
            {row.pause_on_risk_acceptance ? 'Pauses SLA' : 'Time continues'}
          </Badge>
        ),
      },
      {
        id: 'status',
        header: 'Status',
        cell: (row) => (
          <Badge tone={row.enabled ? 'ok' : 'neutral'}>{row.enabled ? 'On' : 'Off'}</Badge>
        ),
      },
    ],
    [],
  );

  const connectorColumns: ColumnDef<TicketConnector>[] = useMemo(
    () => [
      {
        id: 'name',
        header: 'Connector',
        cell: (row) => (
          <div>
            <p className="font-medium text-text">{row.name}</p>
            <p className="text-xs text-muted">{row.project_key}</p>
          </div>
        ),
        sortValue: (row) => row.name,
      },
      {
        id: 'type',
        header: 'Provider',
        cell: (row) => <Badge>{humanize(row.connector_type)}</Badge>,
        sortValue: (row) => row.connector_type,
      },
      {
        id: 'test',
        header: 'Test',
        cell: (row) => (
          <Badge tone={row.successful_test_at ? 'ok' : row.last_test_error ? 'bad' : 'neutral'}>
            {row.successful_test_at ? 'Passed' : row.last_test_error ? 'Failed' : 'Required'}
          </Badge>
        ),
      },
      {
        id: 'status',
        header: 'Status',
        cell: (row) => (
          <Badge tone={row.enabled ? 'ok' : 'neutral'}>{row.enabled ? 'On' : 'Off'}</Badge>
        ),
      },
      {
        id: 'actions',
        header: 'Actions',
        cell: (row) =>
          canManageConnectors ? (
            <div className="flex gap-1">
              <Button
                size="sm"
                variant="outline"
                disabled={busy === row.id}
                onClick={() => void testConnector(row)}
              >
                <RefreshCw size={12} aria-hidden /> Test
              </Button>
              <Button
                size="sm"
                variant={row.enabled ? 'destructive' : 'outline'}
                disabled={busy === row.id || (!row.enabled && !row.successful_test_at)}
                onClick={() => void toggleConnector(row)}
              >
                {row.enabled ? 'Disable' : 'Enable'}
              </Button>
            </div>
          ) : null,
      },
    ],
    [busy, canManageConnectors, testConnector, toggleConnector],
  );

  const syncColumns: ColumnDef<TicketSync>[] = useMemo(
    () => [
      {
        id: 'finding',
        header: 'Finding',
        cell: (row) => <code className="text-xs">{row.finding_id}</code>,
        sortValue: (row) => row.finding_id,
      },
      {
        id: 'connector',
        header: 'Connector',
        cell: (row) =>
          connectors.find((item) => item.id === row.connector_id)?.name ?? row.connector_id,
        sortValue: (row) => connectors.find((item) => item.id === row.connector_id)?.name ?? '',
      },
      {
        id: 'action',
        header: 'Action',
        cell: (row) => humanize(row.last_action),
        sortValue: (row) => row.last_action,
      },
      {
        id: 'status',
        header: 'Status',
        cell: (row) => (
          <Badge
            tone={row.status === 'succeeded' ? 'ok' : row.status === 'failed' ? 'bad' : 'warn'}
          >
            {humanize(row.status)}
          </Badge>
        ),
        sortValue: (row) => row.status,
      },
      {
        id: 'ticket',
        header: 'External ticket',
        cell: (row) =>
          row.external_ticket_url ? (
            <a
              href={row.external_ticket_url}
              target="_blank"
              rel="noreferrer"
              className="text-accent-strong hover:underline"
            >
              {row.external_ticket_id ?? 'Open'}
            </a>
          ) : (
            (row.external_ticket_id ?? '—')
          ),
      },
    ],
    [connectors],
  );

  return (
    <div>
      <PageHeader
        title="SLAs & ticketing"
        description="Explainable deadlines, governed exceptions, remediation guidance, and non-blocking ticket synchronization."
        actions={
          <Button size="sm" variant="outline" onClick={() => void load()} loading={loading}>
            <RefreshCw size={13} aria-hidden /> Refresh
          </Button>
        }
      />
      {error && <InlineError message={error} />}
      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          { id: 'sla', label: 'SLA policies', count: policies.length },
          { id: 'connectors', label: 'Connectors', count: connectors.length },
          { id: 'syncs', label: 'Ticket sync', count: syncs.length },
        ]}
      />

      {tab === 'sla' && (
        <div className="mt-4 space-y-4">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <MetricCard icon={Clock3} label="Open with SLA" value={metrics?.open ?? 0} />
            <MetricCard icon={Clock3} label="Overdue" value={metrics?.overdue ?? 0} tone="bad" />
            <MetricCard
              icon={TicketCheck}
              label="Due in 7 days"
              value={metrics?.due_within_7_days ?? 0}
              tone="warn"
            />
            <MetricCard
              icon={CheckCircle2}
              label="On-time completion"
              value={metrics?.on_time_percentage == null ? '—' : `${metrics.on_time_percentage}%`}
              tone="ok"
            />
          </div>
          {canManageSla && <NewPolicyCard token={token} onCreated={load} />}
          <DataTable
            rows={policies}
            columns={policyColumns}
            rowKey={(row) => row.id}
            loading={loading}
            searchText={(row) => `${row.name} ${row.description ?? ''}`}
            emptyTitle="No SLA policies"
            emptyDescription="Severity fallback deadlines remain active until an ordered policy matches."
            storageKey="sla-policies"
          />
        </div>
      )}

      {tab === 'connectors' && (
        <div className="mt-4 space-y-4">
          {canManageConnectors && <NewConnectorCard token={token} onCreated={load} />}
          <DataTable
            rows={connectors}
            columns={connectorColumns}
            rowKey={(row) => row.id}
            loading={loading}
            searchText={(row) => `${row.name} ${row.connector_type} ${row.project_key}`}
            emptyTitle="No ticket connectors"
            emptyDescription="Connectors are disabled until a successful test. Secret values are never returned."
            storageKey="ticket-connectors"
          />
        </div>
      )}

      {tab === 'syncs' && (
        <div className="mt-4 space-y-4">
          {canSync && <QueueSyncCard token={token} connectors={connectors} onQueued={load} />}
          <DataTable
            rows={syncs}
            columns={syncColumns}
            rowKey={(row) => row.id}
            loading={loading}
            searchText={(row) => `${row.finding_id} ${row.external_ticket_id ?? ''} ${row.status}`}
            emptyTitle="No ticket synchronization"
            emptyDescription="A connector outage never blocks finding persistence; failed attempts stay inspectable."
            storageKey="ticket-syncs"
          />
        </div>
      )}
    </div>
  );
}

function MetricCard({
  icon: Icon,
  label,
  value,
  tone = 'neutral',
}: {
  icon: typeof Clock3;
  label: string;
  value: string | number;
  tone?: 'neutral' | 'ok' | 'warn' | 'bad';
}) {
  return (
    <Card>
      <CardBody className="flex items-center gap-3 pt-4">
        <Icon
          size={18}
          className={tone === 'bad' ? 'text-bad' : tone === 'ok' ? 'text-ok' : 'text-accent'}
        />
        <div>
          <p className="text-lg font-bold text-text">{value}</p>
          <p className="text-xs text-muted">{label}</p>
        </div>
      </CardBody>
    </Card>
  );
}

function NewPolicyCard({
  token,
  onCreated,
}: {
  token: string | null;
  onCreated: () => Promise<void>;
}) {
  const [name, setName] = useState('');
  const [priority, setPriority] = useState('100');
  const [severity, setSeverity] = useState('critical');
  const [days, setDays] = useState('7');
  const [pause, setPause] = useState(false);
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    if (!token || !name.trim()) return;
    setBusy(true);
    try {
      await api.createSlaPolicy(token, {
        name: name.trim(),
        priority: Number(priority),
        match: { severities: [severity] },
        due_days: { [severity]: Number(days) },
        pause_on_risk_acceptance: pause,
      });
      setName('');
      await onCreated();
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card>
      <CardHeader
        title="Add ordered policy"
        description="Lower priority numbers match first. Ties are rejected."
      />
      <CardBody className="grid gap-3 md:grid-cols-5">
        <Field label="Name" htmlFor="sla-policy-name">
          <Input
            id="sla-policy-name"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
        </Field>
        <Field label="Priority" htmlFor="sla-policy-priority">
          <Input
            id="sla-policy-priority"
            type="number"
            min={1}
            value={priority}
            onChange={(event) => setPriority(event.target.value)}
          />
        </Field>
        <Field label="Severity" htmlFor="sla-policy-severity">
          <Select
            id="sla-policy-severity"
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
          >
            {['critical', 'high', 'medium', 'low', 'info'].map((item) => (
              <option key={item} value={item}>
                {humanize(item)}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Due days" htmlFor="sla-policy-days">
          <Input
            id="sla-policy-days"
            type="number"
            min={1}
            value={days}
            onChange={(event) => setDays(event.target.value)}
          />
        </Field>
        <div className="flex items-end gap-3">
          <label className="mb-2 flex items-center gap-2 text-xs text-muted">
            <input
              type="checkbox"
              checked={pause}
              onChange={(event) => setPause(event.target.checked)}
            />
            Pause on accepted risk
          </label>
          <Button variant="primary" loading={busy} onClick={() => void submit()}>
            <Plus size={13} /> Add
          </Button>
        </div>
      </CardBody>
    </Card>
  );
}

function NewConnectorCard({
  token,
  onCreated,
}: {
  token: string | null;
  onCreated: () => Promise<void>;
}) {
  const [name, setName] = useState('');
  const [provider, setProvider] = useState<TicketConnectorType>('github');
  const [baseUrl, setBaseUrl] = useState('https://');
  const [project, setProject] = useState('');
  const [secret, setSecret] = useState('');
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    if (!token || !name.trim() || !project.trim() || !secret) return;
    setBusy(true);
    try {
      await api.createTicketConnector(token, {
        name: name.trim(),
        connector_type: provider,
        base_url: baseUrl,
        project_key: project.trim(),
        secret,
        config: {},
      });
      setSecret('');
      setName('');
      await onCreated();
    } finally {
      setSecret('');
      setBusy(false);
    }
  };
  return (
    <Card>
      <CardHeader
        title="Add connector"
        description="Created disabled. The secret is encrypted and cleared after submission."
      />
      <CardBody className="grid gap-3 md:grid-cols-5">
        <Field label="Name" htmlFor="ticket-connector-name">
          <Input
            id="ticket-connector-name"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
        </Field>
        <Field label="Provider" htmlFor="ticket-connector-provider">
          <Select
            id="ticket-connector-provider"
            value={provider}
            onChange={(event) => setProvider(event.target.value as TicketConnectorType)}
          >
            {PROVIDERS.map((item) => (
              <option key={item} value={item}>
                {humanize(item)}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="HTTPS API URL" htmlFor="ticket-connector-url">
          <Input
            id="ticket-connector-url"
            type="url"
            value={baseUrl}
            onChange={(event) => setBaseUrl(event.target.value)}
          />
        </Field>
        <Field label="Project / queue" htmlFor="ticket-connector-project">
          <Input
            id="ticket-connector-project"
            value={project}
            onChange={(event) => setProject(event.target.value)}
          />
        </Field>
        <Field label="Token / secret" htmlFor="ticket-connector-secret">
          <div className="flex gap-2">
            <Input
              id="ticket-connector-secret"
              type="password"
              value={secret}
              autoComplete="new-password"
              onChange={(event) => setSecret(event.target.value)}
            />
            <Button variant="primary" loading={busy} onClick={() => void submit()}>
              <Plus size={13} /> Add
            </Button>
          </div>
        </Field>
      </CardBody>
    </Card>
  );
}

function QueueSyncCard({
  token,
  connectors,
  onQueued,
}: {
  token: string | null;
  connectors: TicketConnector[];
  onQueued: () => Promise<void>;
}) {
  const [findingId, setFindingId] = useState('');
  const [connectorId, setConnectorId] = useState('');
  const [action, setAction] = useState<'upsert' | 'close'>('upsert');
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    if (!token || !findingId || !connectorId) return;
    setBusy(true);
    try {
      await api.queueTicketSync(token, findingId, connectorId, action);
      setFindingId('');
      await onQueued();
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card>
      <CardHeader
        title="Queue ticket synchronization"
        description="The worker runs this after core finding persistence completes."
      />
      <CardBody className="grid gap-3 md:grid-cols-4">
        <Field label="Finding ID" htmlFor="ticket-sync-finding">
          <Input
            id="ticket-sync-finding"
            value={findingId}
            onChange={(event) => setFindingId(event.target.value)}
          />
        </Field>
        <Field label="Connector" htmlFor="ticket-sync-connector">
          <Select
            id="ticket-sync-connector"
            value={connectorId}
            onChange={(event) => setConnectorId(event.target.value)}
          >
            <option value="">Select…</option>
            {connectors
              .filter((item) => item.enabled)
              .map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name}
                </option>
              ))}
          </Select>
        </Field>
        <Field label="Action" htmlFor="ticket-sync-action">
          <Select
            id="ticket-sync-action"
            value={action}
            onChange={(event) => setAction(event.target.value as 'upsert' | 'close')}
          >
            <option value="upsert">Create or update</option>
            <option value="close">Close after verification</option>
          </Select>
        </Field>
        <div className="flex items-end">
          <Button variant="primary" loading={busy} onClick={() => void submit()}>
            <TicketCheck size={13} /> Queue
          </Button>
        </div>
      </CardBody>
    </Card>
  );
}
