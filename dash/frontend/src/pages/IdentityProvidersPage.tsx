import { useCallback, useEffect, useState } from 'react';
import { KeyRound, Pencil, Plus, ShieldCheck, Trash2, UsersRound } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { PageHeader, SectionHeader } from '../components/app/page-header';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card, CardBody, CardHeader } from '../components/ui/card';
import { Field, Input, Select, Textarea } from '../components/ui/input';
import { CardSkeleton, EmptyState, InlineError } from '../components/ui/states';
import { useToast } from '../lib/toast';
import type { Role, UserSummary } from '../types/auth';
import type { Site } from '../types/inventory';
import type {
  GroupMapping,
  IdentityProtocol,
  IdentityProvider,
  SsoPolicy,
  SsoPolicyMode,
} from '../types/sso';

const ROLES: Role[] = [
  'administrator',
  'security_operator',
  'pentest_approver',
  'remediation_owner',
  'auditor',
  'viewer',
];

function roleLabel(role: Role) {
  return role.replaceAll('_', ' ').replace(/\b\w/g, (value) => value.toUpperCase());
}

function dateLabel(value: string | null) {
  return value ? new Date(value).toLocaleString() : 'Not completed';
}

export function IdentityProvidersPage() {
  const { token } = useAuth();
  const { toast } = useToast();
  const [providers, setProviders] = useState<IdentityProvider[]>([]);
  const [policy, setPolicy] = useState<SsoPolicy | null>(null);
  const [users, setUsers] = useState<UserSummary[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [editingProvider, setEditingProvider] = useState<IdentityProvider | null>(null);
  const [metadataProvider, setMetadataProvider] = useState<string | null>(null);
  const [metadataXml, setMetadataXml] = useState('');
  const [mappingProvider, setMappingProvider] = useState<string | null>(null);
  const [mappings, setMappings] = useState<GroupMapping[]>([]);
  const [externalGroup, setExternalGroup] = useState('');
  const [mappingRole, setMappingRole] = useState<Role | ''>('viewer');
  const [mappingSiteIds, setMappingSiteIds] = useState<string[]>([]);
  const [editingMappingId, setEditingMappingId] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [providerRows, policyValue, userPage, sitePage] = await Promise.all([
        api.listIdentityProviders(token),
        api.ssoPolicy(token),
        api.listUsers(token),
        api.listAllSites(token),
      ]);
      setProviders(providerRows);
      setPolicy(policyValue);
      setUsers(userPage.items);
      setSites(sitePage.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Identity settings could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const run = async (provider: IdentityProvider, action: 'validate' | 'test' | 'enabled') => {
    if (!token) return;
    setBusyId(provider.id);
    setError(null);
    try {
      if (action === 'validate') {
        await api.validateIdentityProvider(token, provider.id);
        toast('success', 'OIDC discovery validated.');
      } else if (action === 'test') {
        const start = await api.testIdentityProvider(token, provider.id);
        window.location.assign(start.authorization_url);
        return;
      } else {
        await api.enableIdentityProvider(token, provider.id, !provider.enabled);
        toast(
          'success',
          provider.enabled ? 'Identity provider disabled.' : 'Identity provider enabled.',
        );
      }
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Identity-provider action failed.');
    } finally {
      setBusyId(null);
    }
  };

  const importMetadata = async () => {
    if (!token || !metadataProvider || !metadataXml.trim()) return;
    setBusyId(metadataProvider);
    setError(null);
    try {
      await api.importSamlMetadata(token, metadataProvider, metadataXml);
      setMetadataProvider(null);
      setMetadataXml('');
      toast('success', 'SAML metadata validated and imported.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'SAML metadata import failed.');
    } finally {
      setBusyId(null);
    }
  };

  const openMappings = async (providerId: string) => {
    if (!token) return;
    setMappingProvider(providerId);
    setError(null);
    setEditingMappingId(null);
    setExternalGroup('');
    setMappingRole('viewer');
    setMappingSiteIds([]);
    try {
      setMappings(await api.identityGroupMappings(token, providerId));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Group mappings could not be loaded.');
    }
  };

  const saveMapping = async () => {
    if (!token || !mappingProvider || !externalGroup.trim()) return;
    const value = {
      external_group: externalGroup.trim(),
      role: mappingRole || null,
      site_ids: mappingSiteIds,
    };
    const next = editingMappingId
      ? mappings.map((mapping) =>
          mapping.id === editingMappingId
            ? value
            : {
                external_group: mapping.external_group,
                role: mapping.role,
                site_ids: mapping.site_ids,
              },
        )
      : [
          ...mappings.map(({ external_group, role, site_ids }) => ({
            external_group,
            role,
            site_ids,
          })),
          value,
        ];
    setBusyId(mappingProvider);
    try {
      setMappings(await api.replaceIdentityGroupMappings(token, mappingProvider, next));
      setExternalGroup('');
      setMappingRole('viewer');
      setMappingSiteIds([]);
      setEditingMappingId(null);
      toast('success', 'Group mappings updated. Re-test the provider before enabling it.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Group mapping could not be saved.');
    } finally {
      setBusyId(null);
    }
  };

  const editMapping = (mapping: GroupMapping) => {
    setEditingMappingId(mapping.id);
    setExternalGroup(mapping.external_group);
    setMappingRole(mapping.role ?? '');
    setMappingSiteIds(mapping.site_ids);
  };

  const removeMapping = async (mappingId: string) => {
    if (!token || !mappingProvider) return;
    const next = mappings
      .filter((mapping) => mapping.id !== mappingId)
      .map(({ external_group, role, site_ids }) => ({
        external_group,
        role,
        site_ids,
      }));
    setBusyId(mappingProvider);
    try {
      setMappings(await api.replaceIdentityGroupMappings(token, mappingProvider, next));
      if (editingMappingId === mappingId) {
        setEditingMappingId(null);
        setExternalGroup('');
        setMappingRole('viewer');
        setMappingSiteIds([]);
      }
      toast('success', 'Group mapping removed. Re-test the provider before enabling it.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Group mapping could not be removed.');
    } finally {
      setBusyId(null);
    }
  };

  const savePolicy = async (mode: SsoPolicyMode, providerId: string | null) => {
    if (!token) return;
    setBusyId('policy');
    setError(null);
    try {
      setPolicy(await api.updateSsoPolicy(token, mode, providerId));
      toast('success', 'SSO policy updated.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'SSO policy could not be updated.');
    } finally {
      setBusyId(null);
    }
  };

  const toggleBreakGlass = async (user: UserSummary) => {
    if (!token) return;
    setBusyId(user.id);
    setError(null);
    try {
      setPolicy(await api.setBreakGlass(token, user.id, !user.is_break_glass));
      setUsers((current) =>
        current.map((item) =>
          item.id === user.id ? { ...item, is_break_glass: !item.is_break_glass } : item,
        ),
      );
      toast('success', 'Break-glass protection updated. Existing sessions were revoked.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Break-glass protection could not be updated.');
    } finally {
      setBusyId(null);
    }
  };

  const deleteProvider = async (provider: IdentityProvider) => {
    if (!token || !window.confirm(`Delete identity provider “${provider.name}”?`)) return;
    setBusyId(provider.id);
    setError(null);
    try {
      await api.deleteIdentityProvider(token, provider.id);
      toast('success', 'Identity provider deleted.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Identity provider could not be deleted.');
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div aria-label="Identity and SSO">
      <PageHeader
        crumbs={[{ label: 'Administration' }, { label: 'Identity & SSO' }]}
        title="Identity & SSO"
        description="Connect OIDC or SAML identity providers without surrendering local, strong-MFA break-glass access. Secrets and certificates are write-only."
        actions={
          <Button variant="primary" onClick={() => setShowCreate((value) => !value)}>
            <Plus size={14} aria-hidden /> Add provider
          </Button>
        }
      />

      {error && <InlineError message={error} className="mb-3" />}
      {showCreate && (
        <CreateProviderCard
          onCancel={() => setShowCreate(false)}
          onCreated={() => {
            setShowCreate(false);
            void load();
          }}
        />
      )}
      {editingProvider && (
        <EditProviderCard
          provider={editingProvider}
          onCancel={() => setEditingProvider(null)}
          onSaved={() => {
            setEditingProvider(null);
            void load();
          }}
        />
      )}

      <SectionHeader title="Identity providers" />
      {loading ? (
        <Card className="mb-4 p-4">
          <CardSkeleton lines={3} />
        </Card>
      ) : providers.length === 0 ? (
        <Card className="mb-4 p-4">
          <EmptyState
            compact
            icon={KeyRound}
            title="No identity providers configured"
            description="Add OIDC discovery or signed SAML metadata, then validate and test it before enabling sign-in."
          />
        </Card>
      ) : (
        <div className="mb-4 grid gap-3 lg:grid-cols-2">
          {providers.map((provider) => (
            <Card key={provider.id}>
              <CardHeader
                title={provider.name}
                description={`${provider.protocol.toUpperCase()} · ${provider.slug}`}
                actions={
                  <Badge tone={provider.enabled ? 'ok' : 'neutral'} dot>
                    {provider.enabled ? 'Enabled' : 'Disabled'}
                  </Badge>
                }
              />
              <CardBody>
                <dl className="grid grid-cols-2 gap-x-3 gap-y-2 text-xs">
                  <div>
                    <dt className="text-faint">Configuration validated</dt>
                    <dd className="mt-0.5 text-text">{dateLabel(provider.validated_at)}</dd>
                  </div>
                  <div>
                    <dt className="text-faint">Administrator test</dt>
                    <dd className="mt-0.5 text-text">
                      {dateLabel(provider.last_test_succeeded_at)}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-faint">Provisioning</dt>
                    <dd className="mt-0.5 text-text">
                      {provider.jit_provisioning
                        ? `JIT as ${roleLabel(provider.default_role)}`
                        : 'Link only'}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-faint">Secret material</dt>
                    <dd className="mt-0.5 text-text">
                      {provider.protocol === 'oidc'
                        ? provider.has_client_secret
                          ? 'Client secret stored'
                          : 'Client secret missing'
                        : provider.has_idp_certificate
                          ? 'Signing certificate stored'
                          : 'Metadata missing'}
                    </dd>
                  </div>
                </dl>
                <div className="mt-3 flex flex-wrap gap-2">
                  {provider.protocol === 'oidc' ? (
                    <Button
                      size="sm"
                      variant="outline"
                      loading={busyId === provider.id}
                      onClick={() => void run(provider, 'validate')}
                    >
                      Validate discovery
                    </Button>
                  ) : (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setMetadataProvider(provider.id)}
                    >
                      Import metadata
                    </Button>
                  )}
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={!provider.validated_at}
                    onClick={() => void run(provider, 'test')}
                  >
                    Test sign-in
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => void openMappings(provider.id)}>
                    Group mappings
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => setEditingProvider(provider)}>
                    <Pencil size={12} aria-hidden /> Edit
                  </Button>
                  <Button
                    size="sm"
                    variant={provider.enabled ? 'destructive' : 'primary'}
                    disabled={!provider.enabled && !provider.last_test_succeeded_at}
                    loading={busyId === provider.id}
                    onClick={() => void run(provider, 'enabled')}
                  >
                    {provider.enabled ? 'Disable' : 'Enable'}
                  </Button>
                  <Button
                    size="icon-sm"
                    variant="ghost"
                    aria-label={`Delete ${provider.name}`}
                    disabled={provider.enabled}
                    loading={busyId === provider.id}
                    onClick={() => void deleteProvider(provider)}
                  >
                    <Trash2 size={13} aria-hidden />
                  </Button>
                </div>
              </CardBody>
            </Card>
          ))}
        </div>
      )}

      {metadataProvider && (
        <Card className="mb-4 border-accent/30">
          <CardHeader
            title="Import SAML metadata"
            description="Only signed assertions are accepted. DTDs and XML entities are rejected. Importing new metadata disables the provider until it is re-tested."
          />
          <CardBody>
            <Field label="Identity-provider metadata XML" htmlFor="saml-metadata">
              <Textarea
                id="saml-metadata"
                rows={8}
                value={metadataXml}
                onChange={(event) => setMetadataXml(event.target.value)}
              />
            </Field>
            <div className="mt-3 flex gap-2">
              <Button
                variant="primary"
                loading={busyId === metadataProvider}
                disabled={!metadataXml.trim()}
                onClick={() => void importMetadata()}
              >
                Validate and import
              </Button>
              <Button variant="ghost" onClick={() => setMetadataProvider(null)}>
                Cancel
              </Button>
            </div>
          </CardBody>
        </Card>
      )}

      {mappingProvider && (
        <Card className="mb-4 border-accent/30">
          <CardHeader
            title="Exact group mappings"
            description="Mappings apply only after a signed identity response. Conflicting role mappings fail the sign-in instead of guessing."
          />
          <CardBody>
            <div className="mb-3 flex flex-wrap gap-1.5">
              {mappings.length === 0 ? (
                <Badge>No mappings</Badge>
              ) : (
                mappings.map((mapping) => (
                  <div
                    key={mapping.id}
                    className="flex items-center gap-1 rounded-lg border border-border bg-surface-2 p-1"
                  >
                    <Badge tone="accent">
                      {mapping.external_group} →{' '}
                      {mapping.role ? roleLabel(mapping.role) : 'sites only'}
                      {mapping.site_ids.length > 0 && ` · ${mapping.site_ids.length} site(s)`}
                    </Badge>
                    <Button
                      size="icon-sm"
                      variant="ghost"
                      aria-label={`Edit ${mapping.external_group}`}
                      onClick={() => editMapping(mapping)}
                    >
                      <Pencil size={13} />
                    </Button>
                    <Button
                      size="icon-sm"
                      variant="destructive"
                      aria-label={`Remove ${mapping.external_group}`}
                      loading={busyId === mappingProvider}
                      onClick={() => void removeMapping(mapping.id)}
                    >
                      <Trash2 size={13} />
                    </Button>
                  </div>
                ))
              )}
            </div>
            <div className="grid gap-3 sm:grid-cols-[1fr_220px_auto] sm:items-end">
              <Field label="Exact external group" htmlFor="external-group">
                <Input
                  id="external-group"
                  value={externalGroup}
                  onChange={(event) => setExternalGroup(event.target.value)}
                />
              </Field>
              <Field label="Compatibility role" htmlFor="mapping-role">
                <Select
                  id="mapping-role"
                  value={mappingRole}
                  onChange={(event) => setMappingRole(event.target.value as Role | '')}
                >
                  <option value="">No role change (sites only)</option>
                  {ROLES.map((role) => (
                    <option key={role} value={role}>
                      {roleLabel(role)}
                    </option>
                  ))}
                </Select>
              </Field>
              <Button
                variant="primary"
                disabled={!externalGroup.trim()}
                loading={busyId === mappingProvider}
                onClick={() => void saveMapping()}
              >
                {editingMappingId ? 'Update mapping' : 'Add mapping'}
              </Button>
            </div>
            <div className="mt-3 rounded-lg border border-border p-3">
              <p className="mb-2 text-xs font-semibold text-text">Site access</p>
              <p className="mb-2 text-xs text-muted">
                No selected sites grants all-site access. Select sites to restrict this group.
              </p>
              <div className="flex flex-wrap gap-3">
                {sites.map((site) => (
                  <label key={site.id} className="flex items-center gap-2 text-xs text-text">
                    <input
                      type="checkbox"
                      checked={mappingSiteIds.includes(site.id)}
                      onChange={() =>
                        setMappingSiteIds((current) =>
                          current.includes(site.id)
                            ? current.filter((value) => value !== site.id)
                            : [...current, site.id],
                        )
                      }
                    />
                    {site.name}
                  </label>
                ))}
                {sites.length === 0 && (
                  <span className="text-xs text-muted">No sites available.</span>
                )}
              </div>
            </div>
            {editingMappingId && (
              <Button
                className="mt-3"
                variant="ghost"
                onClick={() => {
                  setEditingMappingId(null);
                  setExternalGroup('');
                  setMappingRole('viewer');
                  setMappingSiteIds([]);
                }}
              >
                Cancel edit
              </Button>
            )}
            <Button className="mt-3" variant="ghost" onClick={() => setMappingProvider(null)}>
              Done
            </Button>
          </CardBody>
        </Card>
      )}

      <div className="grid gap-4 xl:grid-cols-2">
        <PolicyCard
          providers={providers}
          policy={policy}
          busy={busyId === 'policy'}
          onSave={savePolicy}
        />
        <BreakGlassCard
          users={users}
          busyId={busyId}
          onToggle={(user) => void toggleBreakGlass(user)}
        />
      </div>
    </div>
  );
}

function EditProviderCard({
  provider,
  onCancel,
  onSaved,
}: {
  provider: IdentityProvider;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const { token } = useAuth();
  const { toast } = useToast();
  const [name, setName] = useState(provider.name);
  const [issuer, setIssuer] = useState(provider.issuer ?? '');
  const [clientId, setClientId] = useState(provider.client_id ?? '');
  const [clientSecret, setClientSecret] = useState('');
  const [jit, setJit] = useState(provider.jit_provisioning);
  const [allowPrivate, setAllowPrivate] = useState(provider.allow_private_network);
  const [encryptedAssertions, setEncryptedAssertions] = useState(
    provider.want_assertions_encrypted,
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const save = async () => {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await api.updateIdentityProvider(token, provider.id, {
        name: name.trim(),
        jit_provisioning: jit,
        allow_private_network: allowPrivate,
        want_assertions_encrypted: encryptedAssertions,
        ...(provider.protocol === 'oidc'
          ? {
              issuer,
              client_id: clientId,
              ...(clientSecret ? { client_secret: clientSecret } : {}),
            }
          : {}),
      });
      toast('success', 'Identity provider updated. Validate and test it again before enabling.');
      onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Identity provider could not be updated.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="mb-4 border-accent/30">
      <CardHeader
        title={`Edit ${provider.name}`}
        description="Configuration changes invalidate the prior validation and sign-in test. Leave the secret blank to keep it unchanged."
      />
      <CardBody className="flex flex-col gap-3">
        {error && <InlineError message={error} />}
        <Field label="Display name" htmlFor="edit-idp-name">
          <Input
            id="edit-idp-name"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
        </Field>
        {provider.protocol === 'oidc' && (
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Exact issuer URL" htmlFor="edit-idp-issuer">
              <Input
                id="edit-idp-issuer"
                value={issuer}
                onChange={(event) => setIssuer(event.target.value)}
              />
            </Field>
            <Field label="Client ID" htmlFor="edit-idp-client">
              <Input
                id="edit-idp-client"
                value={clientId}
                onChange={(event) => setClientId(event.target.value)}
              />
            </Field>
            <Field label="New client secret (optional)" htmlFor="edit-idp-secret">
              <Input
                id="edit-idp-secret"
                type="password"
                autoComplete="new-password"
                value={clientSecret}
                onChange={(event) => setClientSecret(event.target.value)}
              />
            </Field>
          </div>
        )}
        <div className="flex flex-wrap gap-4 text-xs text-muted">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={jit}
              onChange={(event) => setJit(event.target.checked)}
            />
            Just-in-time provisioning
          </label>
          {provider.protocol === 'oidc' ? (
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={allowPrivate}
                onChange={(event) => setAllowPrivate(event.target.checked)}
              />
              Allow trusted private-network IdP
            </label>
          ) : (
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={encryptedAssertions}
                onChange={(event) => setEncryptedAssertions(event.target.checked)}
              />
              Require encrypted assertions
            </label>
          )}
        </div>
        <div className="flex gap-2">
          <Button
            variant="primary"
            loading={busy}
            disabled={!name.trim()}
            onClick={() => void save()}
          >
            Save provider
          </Button>
          <Button variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
        </div>
      </CardBody>
    </Card>
  );
}

function CreateProviderCard({
  onCancel,
  onCreated,
}: {
  onCancel: () => void;
  onCreated: () => void;
}) {
  const { token } = useAuth();
  const { toast } = useToast();
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const [protocol, setProtocol] = useState<IdentityProtocol>('oidc');
  const [preset, setPreset] = useState<'generic' | 'entra' | 'google' | 'okta' | 'keycloak'>(
    'generic',
  );
  const [issuer, setIssuer] = useState('');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [jit, setJit] = useState(false);
  const [defaultRole, setDefaultRole] = useState<Role>('viewer');
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [encryptedAssertions, setEncryptedAssertions] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const create = async () => {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await api.createIdentityProvider(token, {
        name,
        slug,
        protocol,
        preset,
        jit_provisioning: jit,
        default_role: defaultRole,
        allow_private_network: allowPrivate,
        issuer: protocol === 'oidc' ? issuer : undefined,
        client_id: protocol === 'oidc' ? clientId : undefined,
        client_secret: protocol === 'oidc' ? clientSecret : undefined,
        want_assertions_encrypted: protocol === 'saml' ? encryptedAssertions : false,
      });
      toast('success', 'Identity provider created. Validate and test it before enabling sign-in.');
      onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Identity provider could not be created.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="mb-4 border-accent/30">
      <CardHeader
        title="Add an identity provider"
        description="The client secret is accepted once and returned only as a has-secret indicator."
      />
      <CardBody>
        {error && <InlineError message={error} className="mb-3" />}
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Display name" htmlFor="idp-name">
            <Input
              id="idp-name"
              value={name}
              onChange={(event) => {
                setName(event.target.value);
                if (!slug) {
                  setSlug(
                    event.target.value
                      .toLowerCase()
                      .replace(/[^a-z0-9]+/g, '-')
                      .replace(/(^-|-$)/g, ''),
                  );
                }
              }}
            />
          </Field>
          <Field label="Stable slug" htmlFor="idp-slug">
            <Input id="idp-slug" value={slug} onChange={(event) => setSlug(event.target.value)} />
          </Field>
          <Field label="Protocol" htmlFor="idp-protocol">
            <Select
              id="idp-protocol"
              value={protocol}
              onChange={(event) => setProtocol(event.target.value as IdentityProtocol)}
            >
              <option value="oidc">OpenID Connect</option>
              <option value="saml">SAML 2.0</option>
            </Select>
          </Field>
          {protocol === 'oidc' && (
            <Field label="Provider preset" htmlFor="idp-preset">
              <Select
                id="idp-preset"
                value={preset}
                onChange={(event) => setPreset(event.target.value as typeof preset)}
              >
                <option value="generic">Generic</option>
                <option value="entra">Microsoft Entra</option>
                <option value="google">Google</option>
                <option value="okta">Okta</option>
                <option value="keycloak">Keycloak</option>
              </Select>
            </Field>
          )}
          {protocol === 'oidc' && (
            <>
              <Field label="Exact issuer URL" htmlFor="idp-issuer">
                <Input
                  id="idp-issuer"
                  type="url"
                  placeholder="https://idp.example/"
                  value={issuer}
                  onChange={(event) => setIssuer(event.target.value)}
                />
              </Field>
              <Field label="Client ID" htmlFor="idp-client-id">
                <Input
                  id="idp-client-id"
                  value={clientId}
                  onChange={(event) => setClientId(event.target.value)}
                />
              </Field>
              <Field label="Client secret (write-only)" htmlFor="idp-client-secret">
                <Input
                  id="idp-client-secret"
                  type="password"
                  autoComplete="new-password"
                  value={clientSecret}
                  onChange={(event) => setClientSecret(event.target.value)}
                />
              </Field>
            </>
          )}
          <Field label="Default JIT role" htmlFor="idp-default-role">
            <Select
              id="idp-default-role"
              value={defaultRole}
              disabled={!jit}
              onChange={(event) => setDefaultRole(event.target.value as Role)}
            >
              <option value="viewer">{roleLabel('viewer')}</option>
            </Select>
          </Field>
          <p className="self-end pb-2 text-xs text-muted">
            Higher roles require an explicit identity-provider group mapping.
          </p>
        </div>
        <div className="mt-3 grid gap-2 text-xs text-muted sm:grid-cols-2">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={jit}
              onChange={(event) => setJit(event.target.checked)}
            />
            Create verified users just in time
          </label>
          {protocol === 'oidc' && (
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={allowPrivate}
                onChange={(event) => setAllowPrivate(event.target.checked)}
              />
              Allow a trusted private-network IdP
            </label>
          )}
          {protocol === 'saml' && (
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={encryptedAssertions}
                onChange={(event) => setEncryptedAssertions(event.target.checked)}
              />
              Require encrypted assertions
            </label>
          )}
        </div>
        <div className="mt-4 flex gap-2">
          <Button
            variant="primary"
            loading={busy}
            disabled={
              !name || !slug || (protocol === 'oidc' && (!issuer || !clientId || !clientSecret))
            }
            onClick={() => void create()}
          >
            Create disabled provider
          </Button>
          <Button variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
        </div>
      </CardBody>
    </Card>
  );
}

function PolicyCard({
  providers,
  policy,
  busy,
  onSave,
}: {
  providers: IdentityProvider[];
  policy: SsoPolicy | null;
  busy: boolean;
  onSave: (mode: SsoPolicyMode, providerId: string | null) => Promise<void>;
}) {
  const [mode, setMode] = useState<SsoPolicyMode>('disabled');
  const [providerId, setProviderId] = useState('');

  useEffect(() => {
    if (!policy) return;
    setMode(policy.mode);
    setProviderId(policy.identity_provider_id ?? '');
  }, [policy]);

  return (
    <Card>
      <CardHeader
        title="Sign-in policy"
        description="Enforcement stays unavailable until provider validation, an administrator test, enablement, and strong-MFA break-glass checks all pass."
        actions={<ShieldCheck size={17} className="text-accent" aria-hidden />}
      />
      <CardBody>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Mode" htmlFor="sso-policy-mode">
            <Select
              id="sso-policy-mode"
              value={mode}
              onChange={(event) => setMode(event.target.value as SsoPolicyMode)}
            >
              <option value="disabled">Local sign-in only</option>
              <option value="optional">Local or SSO</option>
              <option value="enforced">SSO enforced + break-glass</option>
            </Select>
          </Field>
          <Field label="Enforced provider" htmlFor="sso-policy-provider">
            <Select
              id="sso-policy-provider"
              value={providerId}
              onChange={(event) => setProviderId(event.target.value)}
            >
              <option value="">Select a provider</option>
              {providers.map((provider) => (
                <option key={provider.id} value={provider.id}>
                  {provider.name}
                </option>
              ))}
            </Select>
          </Field>
        </div>
        {policy && (
          <div className="mt-3 rounded-lg border border-border bg-surface-2 p-3 text-xs">
            <Badge tone={policy.enforcement_ready ? 'ok' : 'warn'} dot>
              {policy.enforcement_ready ? 'Enforcement ready' : 'Enforcement blocked'}
            </Badge>
            {policy.readiness_reasons.length > 0 && (
              <ul className="mt-2 list-disc space-y-1 pl-4 text-muted">
                {policy.readiness_reasons.map((reason) => (
                  <li key={reason}>{reason}</li>
                ))}
              </ul>
            )}
          </div>
        )}
        <Button
          className="mt-3"
          variant="primary"
          loading={busy}
          disabled={mode !== 'disabled' && !providerId}
          onClick={() => void onSave(mode, providerId || null)}
        >
          Save sign-in policy
        </Button>
      </CardBody>
    </Card>
  );
}

function BreakGlassCard({
  users,
  busyId,
  onToggle,
}: {
  users: UserSummary[];
  busyId: string | null;
  onToggle: (user: UserSummary) => void;
}) {
  const candidates = users.filter(
    (user) => user.role === 'administrator' && user.authentication_source === 'local',
  );
  return (
    <Card>
      <CardHeader
        title="Protected break-glass access"
        description="Only active local administrators with a password and enrolled TOTP or WebAuthn can be protected. Every use raises a critical security alert."
        actions={<UsersRound size={17} className="text-accent" aria-hidden />}
      />
      <CardBody className="flex flex-col gap-2">
        {candidates.length === 0 ? (
          <p className="text-xs text-muted">No eligible local administrators.</p>
        ) : (
          candidates.map((candidate) => {
            const eligible =
              candidate.account_status === 'active' && candidate.mfa_status === 'enrolled';
            return (
              <div
                key={candidate.id}
                className="flex flex-wrap items-center gap-2 rounded-lg border border-border px-3 py-2"
              >
                <div className="min-w-0 flex-1">
                  <p className="truncate text-[13px] font-medium text-text">{candidate.email}</p>
                  <p className="text-[11px] text-muted">
                    {candidate.mfa_status === 'enrolled'
                      ? 'Strong MFA enrolled'
                      : 'Strong MFA required'}
                  </p>
                </div>
                {candidate.is_break_glass && <Badge tone="ok">Protected</Badge>}
                <Button
                  size="sm"
                  variant={candidate.is_break_glass ? 'destructive' : 'outline'}
                  loading={busyId === candidate.id}
                  disabled={!candidate.is_break_glass && !eligible}
                  onClick={() => onToggle(candidate)}
                >
                  {candidate.is_break_glass ? 'Remove' : 'Protect'}
                </Button>
              </div>
            );
          })
        )}
      </CardBody>
    </Card>
  );
}
