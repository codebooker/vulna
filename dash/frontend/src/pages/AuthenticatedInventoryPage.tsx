import { useCallback, useEffect, useMemo, useState } from 'react';
import { KeyRound, PlayCircle, Plus, RefreshCw, ShieldCheck, Trash2 } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { DataTable, type ColumnDef } from '../components/app/data-table';
import { PageHeader } from '../components/app/page-header';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card, CardBody, CardHeader } from '../components/ui/card';
import { Field, Input, Select, Textarea } from '../components/ui/input';
import { InlineError } from '../components/ui/states';
import { Tabs } from '../components/ui/tabs';
import { useToast } from '../lib/toast';
import { humanize } from '../lib/utils';
import type {
  Credential,
  CredentialAssignment,
  CredentialAuthType,
  CredentialProtocol,
  CredentialResolution,
  CredentialTargetType,
  CredentialUsage,
  SoftwareItem,
} from '../types/credentials';
import type { Asset } from '../types/inventory';
import type { ProbeSummary } from '../types/onboarding';

const TARGET_TYPES: CredentialTargetType[] = ['asset', 'group', 'tag', 'network', 'site', 'preset'];

export function AuthenticatedInventoryPage() {
  const { token, user } = useAuth();
  const { toast } = useToast();
  const [tab, setTab] = useState('vault');
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [assignments, setAssignments] = useState<CredentialAssignment[]>([]);
  const [software, setSoftware] = useState<SoftwareItem[]>([]);
  const [usage, setUsage] = useState<CredentialUsage[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [probes, setProbes] = useState<ProbeSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [resolution, setResolution] = useState<CredentialResolution[]>([]);
  const canManage =
    user?.permissions?.includes('credentials.manage') ?? user?.role === 'administrator';
  const canManageScouts =
    user?.permissions?.includes('scouts.manage') ?? user?.role === 'administrator';
  const canManageSoftware =
    user?.permissions?.includes('software.manage') ?? user?.role === 'administrator';
  const canRun = user?.permissions?.includes('jobs.create') ?? user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [vault, assignmentPage, softwarePage, usagePage, assetPage, probePage] =
        await Promise.all([
          api.listCredentials(token),
          api.listCredentialAssignments(token),
          api.listSoftware(token),
          api.credentialUsage(token),
          api.listAllAssets(token),
          api.listProbes(token),
        ]);
      setCredentials(vault.items);
      setAssignments(assignmentPage.items);
      setSoftware(softwarePage.items);
      setUsage(usagePage.items);
      setAssets(assetPage.items);
      setProbes(probePage.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authenticated inventory could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const rotate = useCallback(
    async (credential: Credential) => {
      if (!token) return;
      const secret = window.prompt(
        `Enter a new secret for “${credential.name}”. It will not be shown again.`,
      );
      if (!secret) return;
      setBusy(credential.id);
      try {
        await api.rotateCredential(token, credential.id, secret);
        toast(
          'success',
          'Credential rotated. Existing job envelopes remain immutable and audited.',
        );
        await load();
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Credential rotation failed.');
      } finally {
        setBusy(null);
      }
    },
    [load, toast, token],
  );

  const setActive = useCallback(
    async (credential: Credential, isActive: boolean) => {
      if (!token) return;
      if (
        !isActive &&
        !window.confirm(`Deactivate “${credential.name}”? New jobs cannot resolve it.`)
      )
        return;
      setBusy(credential.id);
      try {
        await api.updateCredential(token, credential.id, { is_active: isActive });
        toast('success', isActive ? 'Credential activated.' : 'Credential deactivated.');
        await load();
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Credential status could not be changed.');
      } finally {
        setBusy(null);
      }
    },
    [load, toast, token],
  );

  const overrideEol = useCallback(
    async (item: SoftwareItem) => {
      if (!token) return;
      const status = window.prompt(
        'Override status: supported, extended_support, end_of_life, or unknown',
        item.eol.status,
      );
      if (
        !status ||
        !['supported', 'extended_support', 'end_of_life', 'unknown'].includes(status)
      ) {
        return;
      }
      const reason = window.prompt(
        'Document the evidence or support agreement (at least 8 chars).',
      );
      if (!reason || reason.trim().length < 8) return;
      setBusy(item.id);
      try {
        await api.createEolOverride(token, item.id, { status, reason: reason.trim() });
        toast('success', 'EOL override recorded with audit history.');
        await load();
      } catch (err) {
        setError(err instanceof Error ? err.message : 'EOL override could not be recorded.');
      } finally {
        setBusy(null);
      }
    },
    [load, toast, token],
  );

  const credentialColumns: ColumnDef<Credential>[] = useMemo(
    () => [
      {
        id: 'name',
        header: 'Credential',
        cell: (row) => (
          <div>
            <p className="font-medium text-text">{row.name}</p>
            <p className="text-xs text-muted">{row.username}</p>
          </div>
        ),
        sortValue: (row) => row.name,
      },
      {
        id: 'protocol',
        header: 'Protocol',
        cell: (row) => <Badge>{row.protocol.toUpperCase()}</Badge>,
        sortValue: (row) => row.protocol,
      },
      {
        id: 'secret',
        header: 'Secret',
        cell: (row) => (
          <span className="text-xs text-muted">
            {row.has_secret ? `Stored · version ${row.current_version}` : 'Missing'}
          </span>
        ),
        sortValue: (row) => row.current_version,
      },
      {
        id: 'status',
        header: 'Status',
        cell: (row) => (
          <Badge tone={row.is_active ? 'ok' : 'neutral'}>
            {row.is_active ? 'Active' : 'Inactive'}
          </Badge>
        ),
        sortValue: (row) => (row.is_active ? 1 : 0),
      },
      {
        id: 'actions',
        header: 'Actions',
        cell: (row) =>
          canManage ? (
            <div className="flex gap-1">
              <Button size="sm" variant="outline" onClick={() => void rotate(row)}>
                <RefreshCw size={12} aria-hidden /> Rotate
              </Button>
              <Button
                size="sm"
                variant={row.is_active ? 'destructive' : 'outline'}
                onClick={() => void setActive(row, !row.is_active)}
              >
                {row.is_active ? 'Deactivate' : 'Activate'}
              </Button>
            </div>
          ) : null,
      },
    ],
    [canManage, rotate, setActive],
  );

  const softwareColumns: ColumnDef<SoftwareItem>[] = useMemo(
    () => [
      {
        id: 'name',
        header: 'Software',
        cell: (row) => <span className="font-medium text-text">{row.name}</span>,
        sortValue: (row) => row.name,
      },
      {
        id: 'asset',
        header: 'Asset',
        cell: (row) =>
          assets.find((asset) => asset.id === row.asset_id)?.canonical_name ?? row.asset_id,
        sortValue: (row) => assets.find((asset) => asset.id === row.asset_id)?.canonical_name ?? '',
      },
      {
        id: 'version',
        header: 'Version',
        cell: (row) => row.version,
        sortValue: (row) => row.version,
      },
      {
        id: 'source',
        header: 'Source',
        cell: (row) => row.source.toUpperCase(),
        sortValue: (row) => row.source,
      },
      {
        id: 'eol',
        header: 'Lifecycle',
        cell: (row) => (
          <Badge
            tone={
              row.eol.status === 'end_of_life'
                ? 'bad'
                : row.eol.status === 'supported'
                  ? 'ok'
                  : 'neutral'
            }
          >
            {humanize(row.eol.status)}
            {row.eol.overridden ? ' · override' : ''}
          </Badge>
        ),
        sortValue: (row) => row.eol.status,
      },
      {
        id: 'actions',
        header: 'Actions',
        cell: (row) =>
          canManageSoftware ? (
            <Button
              size="sm"
              variant="outline"
              disabled={busy === row.id}
              onClick={() => void overrideEol(row)}
            >
              Override
            </Button>
          ) : null,
      },
    ],
    [assets, busy, canManageSoftware, overrideEol],
  );

  const usageColumns: ColumnDef<CredentialUsage>[] = useMemo(
    () => [
      {
        id: 'when',
        header: 'When',
        cell: (row) => new Date(row.created_at).toLocaleString(),
        sortValue: (row) => row.created_at,
      },
      {
        id: 'credential',
        header: 'Credential',
        cell: (row) =>
          credentials.find((value) => value.id === row.credential_id)?.name ?? row.credential_id,
        sortValue: (row) => credentials.find((value) => value.id === row.credential_id)?.name ?? '',
      },
      {
        id: 'protocol',
        header: 'Protocol',
        cell: (row) => row.protocol.toUpperCase(),
        sortValue: (row) => row.protocol,
      },
      {
        id: 'status',
        header: 'Status',
        cell: (row) => (
          <Badge
            tone={row.status === 'succeeded' ? 'ok' : row.status === 'failed' ? 'bad' : 'neutral'}
          >
            {humanize(row.status)}
          </Badge>
        ),
        sortValue: (row) => row.status,
      },
      { id: 'detail', header: 'Detail', cell: (row) => row.detail ?? '—' },
    ],
    [credentials],
  );

  return (
    <div aria-label="Authenticated inventory">
      <PageHeader
        crumbs={[{ label: 'Management' }, { label: 'Authenticated inventory' }]}
        title="Authenticated inventory"
        description="Collect read-only Linux and Windows software inventory through Scout-encrypted, purpose-bound credentials."
      />
      {error && <InlineError className="mb-3" message={error} />}
      <div className="mb-4 rounded-lg border border-accent/25 bg-[var(--accent-tint)] px-3 py-2 text-xs text-muted">
        <ShieldCheck size={14} className="mr-1 inline text-accent" aria-hidden />
        Secrets are accepted once, encrypted at rest, and delivered only inside a signed envelope
        encrypted to one opted-in Scout. They are never returned by this page.
      </div>
      <Tabs
        className="mb-4"
        value={tab}
        onChange={setTab}
        tabs={[
          { id: 'run', label: 'Run inventory' },
          { id: 'vault', label: 'Vault', count: credentials.length },
          { id: 'assignments', label: 'Assignments', count: assignments.length },
          { id: 'scouts', label: 'Scout opt-in', count: probes.length },
          { id: 'software', label: 'Software', count: software.length },
          { id: 'usage', label: 'Usage', count: usage.length },
        ]}
      />

      {tab === 'run' && (
        <RunInventoryPanel
          assets={assets}
          probes={probes}
          canRun={canRun}
          busy={busy === 'run-inventory'}
          onRun={async (assetId, probeId, protocols) => {
            if (!token) return;
            setBusy('run-inventory');
            setError(null);
            try {
              const asset = await api.getAsset(token, assetId);
              const target =
                asset.identifiers.find((item) => item.identifier_type === 'ip_address')
                  ?.identifier_value ??
                asset.identifiers.find((item) =>
                  ['fqdn', 'hostname'].includes(item.identifier_type),
                )?.identifier_value;
              if (!target) {
                throw new Error(
                  'This asset has no IP address or hostname that a Scout can target.',
                );
              }
              const job = await api.createAuthenticatedJob(token, {
                probe_id: probeId,
                asset_id: assetId,
                targets: [target],
                authenticated_protocols: protocols,
              });
              toast('success', `Authenticated inventory job ${job.id.slice(0, 8)} queued.`);
            } catch (err) {
              setError(err instanceof Error ? err.message : 'Inventory job could not be created.');
            } finally {
              setBusy(null);
            }
          }}
        />
      )}

      {tab === 'vault' && (
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
          <DataTable
            rows={credentials}
            columns={credentialColumns}
            rowKey={(row) => row.id}
            searchText={(row) => `${row.name} ${row.username} ${row.protocol}`}
            loading={loading}
            storageKey="vulnadash.credentials"
            emptyTitle="No vault credentials"
            emptyDescription="Add a read-only SSH or WinRM credential. The secret can only be replaced, never read back."
          />
          {canManage && (
            <CreateCredentialCard
              busy={busy === 'create'}
              onCreate={async (payload) => {
                if (!token) return;
                setBusy('create');
                try {
                  await api.createCredential(token, payload);
                  toast('success', 'Credential encrypted. The secret cannot be retrieved.');
                  await load();
                } catch (err) {
                  setError(err instanceof Error ? err.message : 'Credential could not be created.');
                } finally {
                  setBusy(null);
                }
              }}
            />
          )}
        </div>
      )}

      {tab === 'assignments' && (
        <AssignmentsPanel
          credentials={credentials}
          assignments={assignments}
          assets={assets}
          resolutions={resolution}
          canManage={canManage}
          busy={busy}
          onAssign={async (credentialId, targetType, targetId) => {
            if (!token) return;
            setBusy('assignment');
            try {
              await api.createCredentialAssignment(token, credentialId, targetType, targetId);
              toast('success', 'Credential assignment created.');
              await load();
            } catch (err) {
              setError(err instanceof Error ? err.message : 'Assignment could not be created.');
            } finally {
              setBusy(null);
            }
          }}
          onDelete={async (id) => {
            if (!token) return;
            setBusy(id);
            try {
              await api.deleteCredentialAssignment(token, id);
              toast('success', 'Credential assignment removed.');
              await load();
            } catch (err) {
              setError(err instanceof Error ? err.message : 'Assignment could not be removed.');
            } finally {
              setBusy(null);
            }
          }}
          onPreview={async (assetId) => {
            if (!token) return;
            try {
              setResolution(await api.resolveCredentials(token, assetId, ['ssh', 'winrm']));
            } catch (err) {
              setError(err instanceof Error ? err.message : 'Resolution preview failed.');
            }
          }}
        />
      )}

      {tab === 'scouts' && (
        <div className="grid gap-3 lg:grid-cols-2">
          {probes.map((probe) => (
            <Card key={probe.id}>
              <CardHeader
                title={probe.name}
                description={
                  probe.has_encryption_key
                    ? 'Scout encryption key enrolled'
                    : 'Re-enrollment required for credential delivery'
                }
                actions={
                  <Badge tone={probe.credentialed_scans_enabled ? 'ok' : 'neutral'}>
                    {probe.credentialed_scans_enabled ? 'Opted in' : 'Opted out'}
                  </Badge>
                }
              />
              <CardBody className="flex items-center justify-between gap-3 text-xs text-muted">
                <span>Credentialed scanning is disabled by default per Scout.</span>
                {canManageScouts && (
                  <Button
                    size="sm"
                    variant={probe.credentialed_scans_enabled ? 'destructive' : 'primary'}
                    disabled={
                      busy === probe.id ||
                      (!probe.has_encryption_key && !probe.credentialed_scans_enabled)
                    }
                    onClick={async () => {
                      if (!token) return;
                      setBusy(probe.id);
                      try {
                        await api.setProbeCredentialedScanning(
                          token,
                          probe.id,
                          !probe.credentialed_scans_enabled,
                        );
                        toast(
                          'success',
                          probe.credentialed_scans_enabled
                            ? 'Credentialed scanning disabled.'
                            : 'Credentialed scanning enabled for this Scout.',
                        );
                        await load();
                      } catch (err) {
                        setError(err instanceof Error ? err.message : 'Scout opt-in failed.');
                      } finally {
                        setBusy(null);
                      }
                    }}
                  >
                    {probe.credentialed_scans_enabled ? 'Disable' : 'Enable'}
                  </Button>
                )}
              </CardBody>
            </Card>
          ))}
        </div>
      )}

      {tab === 'software' && (
        <DataTable
          rows={software}
          columns={softwareColumns}
          rowKey={(row) => row.id}
          searchText={(row) => `${row.name} ${row.version} ${row.publisher ?? ''}`}
          loading={loading}
          storageKey="vulnadash.software-inventory"
          exportName="software-inventory"
          emptyTitle="No authenticated software inventory"
          emptyDescription="Inventory appears after an opted-in Scout completes an SSH or WinRM collection."
        />
      )}

      {tab === 'usage' && (
        <DataTable
          rows={usage}
          columns={usageColumns}
          rowKey={(row) => row.id}
          searchText={(row) => `${row.protocol} ${row.status} ${row.detail ?? ''}`}
          loading={loading}
          storageKey="vulnadash.credential-usage"
          emptyTitle="No credential usage"
          emptyDescription="Every delivery and collector outcome is recorded without command output or secrets."
        />
      )}
    </div>
  );
}

function RunInventoryPanel({
  assets,
  probes,
  canRun,
  busy,
  onRun,
}: {
  assets: Asset[];
  probes: ProbeSummary[];
  canRun: boolean;
  busy: boolean;
  onRun: (assetId: string, probeId: string, protocols: CredentialProtocol[]) => Promise<void>;
}) {
  const [assetId, setAssetId] = useState('');
  const [probeId, setProbeId] = useState('');
  const [protocols, setProtocols] = useState<CredentialProtocol[]>(['ssh']);
  const asset = assets.find((item) => item.id === assetId);
  const eligibleProbes = probes.filter(
    (probe) =>
      probe.site_id === asset?.site_id &&
      probe.status === 'enrolled' &&
      probe.credentialed_scans_enabled &&
      probe.has_encryption_key,
  );

  useEffect(() => {
    if (!eligibleProbes.some((probe) => probe.id === probeId)) {
      setProbeId(eligibleProbes[0]?.id ?? '');
    }
  }, [eligibleProbes, probeId]);

  return (
    <Card className="max-w-2xl">
      <CardHeader
        title="Run authenticated inventory"
        description="Select an asset and an opted-in Scout at the same site. Vulna resolves the narrowest matching credentials and queues a signed, encrypted collection job."
      />
      <CardBody className="flex flex-col gap-3">
        <Field label="Asset" htmlFor="inventory-asset">
          <Select
            id="inventory-asset"
            value={assetId}
            onChange={(event) => {
              setAssetId(event.target.value);
              setProbeId('');
            }}
          >
            <option value="">Select asset…</option>
            {assets.map((item) => (
              <option key={item.id} value={item.id}>
                {item.canonical_name}
              </option>
            ))}
          </Select>
        </Field>
        <Field
          label="Scout"
          htmlFor="inventory-probe"
          hint={
            assetId && eligibleProbes.length === 0
              ? 'No enrolled Scout at this site is opted in for credentialed scanning.'
              : 'Only enrolled, encryption-capable Scouts that explicitly opted in are listed.'
          }
        >
          <Select
            id="inventory-probe"
            value={probeId}
            disabled={!assetId || eligibleProbes.length === 0}
            onChange={(event) => setProbeId(event.target.value)}
          >
            <option value="">Select Scout…</option>
            {eligibleProbes.map((probe) => (
              <option key={probe.id} value={probe.id}>
                {probe.name}
              </option>
            ))}
          </Select>
        </Field>
        <fieldset className="flex gap-4">
          <legend className="mb-1 text-xs font-medium text-text">Protocols</legend>
          {(['ssh', 'winrm'] as const).map((protocol) => (
            <label key={protocol} className="flex items-center gap-1.5 text-xs text-muted">
              <input
                type="checkbox"
                checked={protocols.includes(protocol)}
                onChange={(event) =>
                  setProtocols((current) =>
                    event.target.checked
                      ? [...new Set([...current, protocol])]
                      : current.filter((value) => value !== protocol),
                  )
                }
              />
              {protocol.toUpperCase()}
            </label>
          ))}
        </fieldset>
        {!canRun && (
          <p className="text-xs text-muted">Your role can view inventory but cannot create jobs.</p>
        )}
        <Button
          variant="primary"
          className="self-start"
          loading={busy}
          disabled={!canRun || !assetId || !probeId || protocols.length === 0}
          onClick={() => void onRun(assetId, probeId, protocols)}
        >
          <PlayCircle size={14} aria-hidden /> Run inventory
        </Button>
      </CardBody>
    </Card>
  );
}

function CreateCredentialCard({
  busy,
  onCreate,
}: {
  busy: boolean;
  onCreate: (payload: {
    name: string;
    description?: string;
    protocol: CredentialProtocol;
    auth_type: CredentialAuthType;
    username: string;
    secret: string;
    metadata: Record<string, unknown>;
  }) => Promise<void>;
}) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [protocol, setProtocol] = useState<CredentialProtocol>('ssh');
  const [authType, setAuthType] = useState<CredentialAuthType>('password');
  const [username, setUsername] = useState('');
  const [secret, setSecret] = useState('');
  const [verification, setVerification] = useState('');
  return (
    <Card>
      <CardHeader
        title="Add credential"
        description="The secret is write-only and cleared after submission."
      />
      <CardBody className="flex flex-col gap-3">
        <Field label="Name" htmlFor="credential-name">
          <Input
            id="credential-name"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
        </Field>
        <Field label="Description" htmlFor="credential-description">
          <Textarea
            id="credential-description"
            value={description}
            onChange={(event) => setDescription(event.target.value)}
          />
        </Field>
        <div className="grid grid-cols-2 gap-2">
          <Field label="Protocol" htmlFor="credential-protocol">
            <Select
              id="credential-protocol"
              value={protocol}
              onChange={(event) => {
                setProtocol(event.target.value as CredentialProtocol);
                setAuthType('password');
                setVerification('');
              }}
            >
              <option value="ssh">SSH</option>
              <option value="winrm">WinRM</option>
            </Select>
          </Field>
          <Field label="Authentication" htmlFor="credential-auth">
            <Select
              id="credential-auth"
              value={authType}
              onChange={(event) => setAuthType(event.target.value as CredentialAuthType)}
            >
              <option value="password">Password</option>
              {protocol === 'ssh' && <option value="ssh_private_key">Private key</option>}
            </Select>
          </Field>
        </div>
        <Field label="Username" htmlFor="credential-username">
          <Input
            id="credential-username"
            autoComplete="off"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
          />
        </Field>
        <Field
          label={authType === 'ssh_private_key' ? 'Private key' : 'Password'}
          htmlFor="credential-secret"
          hint="This value is never returned by the API."
        >
          {authType === 'ssh_private_key' ? (
            <Textarea
              id="credential-secret"
              value={secret}
              onChange={(event) => setSecret(event.target.value)}
            />
          ) : (
            <Input
              id="credential-secret"
              type="password"
              autoComplete="new-password"
              value={secret}
              onChange={(event) => setSecret(event.target.value)}
            />
          )}
        </Field>
        <Field
          label={protocol === 'ssh' ? 'Host-key fingerprint' : 'TLS server name'}
          htmlFor="credential-verification"
          hint={
            protocol === 'ssh'
              ? 'Required SHA256: fingerprint; verification cannot be disabled.'
              : 'WinRM always uses HTTPS with certificate verification.'
          }
        >
          <Input
            id="credential-verification"
            placeholder={protocol === 'ssh' ? 'SHA256:…' : 'server.example.internal'}
            value={verification}
            onChange={(event) => setVerification(event.target.value)}
          />
        </Field>
        <Button
          variant="primary"
          loading={busy}
          disabled={!name.trim() || !username.trim() || !secret || !verification.trim()}
          onClick={async () => {
            await onCreate({
              name: name.trim(),
              description: description.trim() || undefined,
              protocol,
              auth_type: authType,
              username: username.trim(),
              secret,
              metadata:
                protocol === 'ssh'
                  ? { host_key_fingerprint: verification.trim(), port: 22 }
                  : {
                      https: true,
                      tls_server_name: verification.trim(),
                      authentication: 'ntlm',
                      port: 5986,
                    },
            });
            setSecret('');
          }}
        >
          <Plus size={14} aria-hidden /> Encrypt credential
        </Button>
      </CardBody>
    </Card>
  );
}

function AssignmentsPanel({
  credentials,
  assignments,
  assets,
  resolutions,
  canManage,
  busy,
  onAssign,
  onDelete,
  onPreview,
}: {
  credentials: Credential[];
  assignments: CredentialAssignment[];
  assets: Asset[];
  resolutions: CredentialResolution[];
  canManage: boolean;
  busy: string | null;
  onAssign: (credentialId: string, type: CredentialTargetType, targetId: string) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
  onPreview: (assetId: string) => Promise<void>;
}) {
  const [credentialId, setCredentialId] = useState('');
  const [targetType, setTargetType] = useState<CredentialTargetType>('asset');
  const [targetId, setTargetId] = useState('');
  const [previewAsset, setPreviewAsset] = useState('');
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
      <Card>
        <CardHeader
          title="Deterministic assignments"
          description="Resolution order is asset → group → tag → network → site → preset. Same-level conflicts block a job."
        />
        <CardBody className="flex flex-col gap-2">
          {assignments.length === 0 && (
            <p className="py-6 text-center text-sm text-muted">No credential assignments.</p>
          )}
          {assignments.map((assignment) => (
            <div
              key={assignment.id}
              className="flex items-center justify-between gap-3 rounded-lg border border-border px-3 py-2"
            >
              <div className="min-w-0">
                <p className="text-sm font-medium text-text">{assignment.credential_name}</p>
                <p className="truncate text-xs text-muted">
                  {humanize(assignment.target_type)} · {assignment.target_id}
                </p>
              </div>
              {canManage && (
                <Button
                  aria-label="Delete assignment"
                  size="icon-sm"
                  variant="ghost"
                  disabled={busy === assignment.id}
                  onClick={() => void onDelete(assignment.id)}
                >
                  <Trash2 size={13} aria-hidden />
                </Button>
              )}
            </div>
          ))}
        </CardBody>
      </Card>
      <div className="flex flex-col gap-4">
        {canManage && (
          <Card>
            <CardHeader title="Add assignment" />
            <CardBody className="flex flex-col gap-3">
              <Field label="Credential" htmlFor="assignment-credential">
                <Select
                  id="assignment-credential"
                  value={credentialId}
                  onChange={(event) => setCredentialId(event.target.value)}
                >
                  <option value="">Select…</option>
                  {credentials
                    .filter((value) => value.is_active)
                    .map((value) => (
                      <option key={value.id} value={value.id}>
                        {value.name}
                      </option>
                    ))}
                </Select>
              </Field>
              <Field label="Precedence level" htmlFor="assignment-type">
                <Select
                  id="assignment-type"
                  value={targetType}
                  onChange={(event) => {
                    setTargetType(event.target.value as CredentialTargetType);
                    setTargetId('');
                  }}
                >
                  {TARGET_TYPES.map((value) => (
                    <option key={value} value={value}>
                      {humanize(value)}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field
                label="Target"
                htmlFor="assignment-target"
                hint="IDs are validated against this organization before assignment."
              >
                {targetType === 'asset' ? (
                  <Select
                    id="assignment-target"
                    value={targetId}
                    onChange={(event) => setTargetId(event.target.value)}
                  >
                    <option value="">Select asset…</option>
                    {assets.map((asset) => (
                      <option key={asset.id} value={asset.id}>
                        {asset.canonical_name}
                      </option>
                    ))}
                  </Select>
                ) : (
                  <Input
                    id="assignment-target"
                    value={targetId}
                    placeholder={targetType === 'preset' ? 'preset key' : `${targetType} UUID`}
                    onChange={(event) => setTargetId(event.target.value)}
                  />
                )}
              </Field>
              <Button
                variant="primary"
                loading={busy === 'assignment'}
                disabled={!credentialId || !targetId}
                onClick={() => void onAssign(credentialId, targetType, targetId)}
              >
                <KeyRound size={14} aria-hidden /> Assign
              </Button>
            </CardBody>
          </Card>
        )}
        <Card>
          <CardHeader
            title="Resolution preview"
            description="Preview both protocols without decrypting a secret."
          />
          <CardBody className="flex flex-col gap-3">
            <Select
              value={previewAsset}
              onChange={(event) => {
                setPreviewAsset(event.target.value);
                if (event.target.value) void onPreview(event.target.value);
              }}
            >
              <option value="">Select asset…</option>
              {assets.map((asset) => (
                <option key={asset.id} value={asset.id}>
                  {asset.canonical_name}
                </option>
              ))}
            </Select>
            {resolutions.map((item) => (
              <div key={item.protocol} className="rounded-lg border border-border px-3 py-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-text">
                    {item.protocol.toUpperCase()}
                  </span>
                  <Badge tone={item.conflict ? 'bad' : item.credential_id ? 'ok' : 'neutral'}>
                    {item.conflict ? 'Blocked' : item.credential_id ? 'Resolved' : 'Unavailable'}
                  </Badge>
                </div>
                <p className="mt-1 text-xs text-muted">{item.message}</p>
              </div>
            ))}
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
