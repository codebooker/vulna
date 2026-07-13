import { useCallback, useEffect, useMemo, useState } from 'react';
import { Bot, Copy, KeyRound, Plus, ShieldCheck, Trash2, UserRoundCog } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { PageHeader, SectionHeader } from '../components/app/page-header';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card, CardBody, CardHeader } from '../components/ui/card';
import { Field, Input, Select, Textarea } from '../components/ui/input';
import { CardSkeleton, EmptyState, InlineError } from '../components/ui/states';
import { useToast } from '../lib/toast';
import type {
  ApiTokenIssued,
  ApiTokenSummary,
  AuthorizationRole,
  GrantScopeType,
  PermissionDefinition,
  PrincipalType,
  ScopedGrant,
  ServiceAccount,
} from '../types/authorization';
import type { UserSummary } from '../types/auth';
import type { Site } from '../types/inventory';

function label(value: string) {
  return value.replaceAll('_', ' ').replace(/\b\w/g, (part) => part.toUpperCase());
}

function when(value: string | null) {
  return value ? new Date(value).toLocaleString() : 'Never';
}

export function AuthorizationPage() {
  const { token, user } = useAuth();
  const { toast } = useToast();
  const [permissions, setPermissions] = useState<PermissionDefinition[]>([]);
  const [roles, setRoles] = useState<AuthorizationRole[]>([]);
  const [grants, setGrants] = useState<ScopedGrant[]>([]);
  const [services, setServices] = useState<ServiceAccount[]>([]);
  const [personalTokens, setPersonalTokens] = useState<ApiTokenSummary[]>([]);
  const [serviceTokens, setServiceTokens] = useState<Record<string, ApiTokenSummary[]>>({});
  const [users, setUsers] = useState<UserSummary[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [issued, setIssued] = useState<ApiTokenIssued | null>(null);

  const [roleName, setRoleName] = useState('');
  const [roleDescription, setRoleDescription] = useState('');
  const [rolePermissions, setRolePermissions] = useState<string[]>([]);
  const [serviceName, setServiceName] = useState('');
  const [serviceDescription, setServiceDescription] = useState('');
  const [grantPrincipal, setGrantPrincipal] = useState('');
  const [grantRole, setGrantRole] = useState('');
  const [grantScope, setGrantScope] = useState<GrantScopeType>('organization');
  const [grantSite, setGrantSite] = useState('');
  const [tokenName, setTokenName] = useState('Automation token');
  const [tokenOwner, setTokenOwner] = useState('personal');
  const [tokenDays, setTokenDays] = useState(90);
  const [tokenIps, setTokenIps] = useState('');

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [permissionRows, roleRows, grantRows, serviceRows, ownTokens, userPage, sitePage] =
        await Promise.all([
          api.permissionCatalogue(token),
          api.listAuthorizationRoles(token),
          api.listScopedGrants(token),
          api.listServiceAccounts(token),
          api.listPersonalApiTokens(token),
          api.listUsers(token),
          api.listSites(token),
        ]);
      const serviceTokenRows = await Promise.all(
        serviceRows.map(
          async (account) =>
            [account.id, await api.listServiceApiTokens(token, account.id)] as const,
        ),
      );
      setPermissions(permissionRows);
      setRoles(roleRows);
      setGrants(grantRows);
      setServices(serviceRows);
      setPersonalTokens(ownTokens);
      setServiceTokens(Object.fromEntries(serviceTokenRows));
      setUsers(userPage.items);
      setSites(sitePage.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authorization settings could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const principals = useMemo(
    () => [
      ...users.map((value) => ({
        value: `user:${value.id}`,
        label: value.full_name ? `${value.full_name} (${value.email})` : value.email,
      })),
      ...services.map((value) => ({
        value: `service_account:${value.id}`,
        label: `${value.name} (service)`,
      })),
    ],
    [services, users],
  );

  const principalName = (grant: ScopedGrant) => {
    if (grant.principal_type === 'user') {
      const owner = users.find((value) => value.id === grant.principal_id);
      return owner?.full_name || owner?.email || grant.principal_id;
    }
    return services.find((value) => value.id === grant.principal_id)?.name || grant.principal_id;
  };

  const scopeName = (grant: ScopedGrant) =>
    grant.scope_type === 'organization'
      ? 'All sites'
      : sites.find((value) => value.id === grant.scope_id)?.name || grant.scope_id;

  const createRole = async () => {
    if (!token || !roleName.trim()) return;
    setBusy('role');
    setError(null);
    try {
      const key = roleName
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '_')
        .replace(/^_+|_+$/g, '');
      await api.createAuthorizationRole(token, {
        key,
        name: roleName.trim(),
        description: roleDescription.trim(),
        permission_keys: rolePermissions,
      });
      setRoleName('');
      setRoleDescription('');
      setRolePermissions([]);
      toast('success', 'Role created. It has no effect until you create a scoped grant.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Role could not be created.');
    } finally {
      setBusy(null);
    }
  };

  const createService = async () => {
    if (!token || !serviceName.trim()) return;
    setBusy('service');
    setError(null);
    try {
      await api.createServiceAccount(token, {
        name: serviceName.trim(),
        description: serviceDescription.trim(),
      });
      setServiceName('');
      setServiceDescription('');
      toast('success', 'Service account created without an interactive password.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Service account could not be created.');
    } finally {
      setBusy(null);
    }
  };

  const createGrant = async () => {
    if (!token || !grantPrincipal || !grantRole || !user) return;
    const [principalType, principalId] = grantPrincipal.split(':') as [PrincipalType, string];
    const scopeId = grantScope === 'organization' ? user.organization_id : grantSite;
    if (!scopeId) return;
    setBusy('grant');
    setError(null);
    try {
      await api.createScopedGrant(token, {
        principal_type: principalType,
        principal_id: principalId,
        role_id: grantRole,
        scope_type: grantScope,
        scope_id: scopeId,
      });
      toast('success', 'Grant applied. Existing credentials for that principal were invalidated.');
      setGrantPrincipal('');
      setGrantRole('');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Grant could not be created.');
    } finally {
      setBusy(null);
    }
  };

  const deleteGrant = async (grant: ScopedGrant) => {
    if (!token || !window.confirm(`Remove ${grant.role_name} from ${principalName(grant)}?`))
      return;
    setBusy(grant.id);
    setError(null);
    try {
      await api.deleteScopedGrant(token, grant.id);
      toast('success', 'Grant removed and credentials invalidated.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Grant could not be removed.');
    } finally {
      setBusy(null);
    }
  };

  const issueToken = async () => {
    if (!token || !tokenName.trim()) return;
    const payload = {
      name: tokenName.trim(),
      expires_in_days: tokenDays,
      ip_restrictions: tokenIps
        .split(/[\n,]/)
        .map((value) => value.trim())
        .filter(Boolean),
    };
    setBusy('token');
    setError(null);
    try {
      const value =
        tokenOwner === 'personal'
          ? await api.createPersonalApiToken(token, payload)
          : await api.createServiceApiToken(token, tokenOwner, payload);
      setIssued(value);
      toast('success', 'Token created. Copy the one-time value now.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Token could not be created.');
    } finally {
      setBusy(null);
    }
  };

  const revokeToken = async (value: ApiTokenSummary) => {
    if (!token || !window.confirm(`Revoke ${value.name}?`)) return;
    setBusy(value.id);
    try {
      if (value.principal_type === 'user') {
        await api.revokePersonalApiToken(token, value.id);
      } else {
        await api.revokeServiceApiToken(token, value.principal_id, value.id);
      }
      toast('success', 'Token revoked immediately.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Token could not be revoked.');
    } finally {
      setBusy(null);
    }
  };

  const suspendService = async (account: ServiceAccount) => {
    if (!token || !window.confirm(`Suspend ${account.name} and revoke all of its tokens?`)) return;
    setBusy(account.id);
    try {
      await api.suspendServiceAccount(token, account.id);
      toast('success', 'Service account suspended and its tokens revoked.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Service account could not be suspended.');
    } finally {
      setBusy(null);
    }
  };

  const allTokens = [
    ...personalTokens,
    ...Object.values(serviceTokens).flatMap((values) => values),
  ];

  return (
    <div aria-label="Authorization">
      <PageHeader
        crumbs={[{ label: 'Administration' }, { label: 'Authorization' }]}
        title="Authorization"
        description="Build roles from code-defined permissions, grant them at organization or site scope, and manage non-interactive service principals."
      />
      {error && <InlineError message={error} className="mb-4" />}

      {issued && (
        <Card className="mb-4 border-warn/40">
          <CardHeader
            title="Copy this API token now"
            description="Only its SHA-256 hash is stored. This value cannot be displayed again."
          />
          <CardBody>
            <div className="flex flex-col gap-2 md:flex-row">
              <Input value={issued.token} readOnly aria-label="One-time API token" />
              <Button
                variant="primary"
                onClick={() => void navigator.clipboard.writeText(issued.token)}
              >
                <Copy size={14} aria-hidden /> Copy token
              </Button>
              <Button variant="ghost" onClick={() => setIssued(null)}>
                I saved it
              </Button>
            </div>
          </CardBody>
        </Card>
      )}

      <div className="mb-5 grid gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader
            title="Create a role"
            description="A role selects stable permissions. Grants decide where it applies."
          />
          <CardBody className="space-y-3">
            <div className="grid gap-3 md:grid-cols-2">
              <Field label="Role name" htmlFor="role-name">
                <Input
                  id="role-name"
                  value={roleName}
                  onChange={(event) => setRoleName(event.target.value)}
                />
              </Field>
              <Field label="Description" htmlFor="role-description">
                <Input
                  id="role-description"
                  value={roleDescription}
                  onChange={(event) => setRoleDescription(event.target.value)}
                />
              </Field>
            </div>
            <Field
              label="Permissions"
              hint="Command-click or Control-click to select more than one."
            >
              <Select
                multiple
                size={8}
                className="h-44 py-1"
                value={rolePermissions}
                onChange={(event) =>
                  setRolePermissions(
                    Array.from(event.currentTarget.selectedOptions, (option) => option.value),
                  )
                }
              >
                {permissions.map((permission) => (
                  <option key={permission.key} value={permission.key}>
                    {permission.label} — {permission.key}
                    {permission.high_risk ? ' (step-up)' : ''}
                  </option>
                ))}
              </Select>
            </Field>
            <Button
              variant="primary"
              onClick={() => void createRole()}
              loading={busy === 'role'}
              disabled={!roleName.trim()}
            >
              <Plus size={14} aria-hidden /> Create role
            </Button>
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title="Create a service account"
            description="Service accounts cannot sign in interactively and receive no permanent secret."
          />
          <CardBody className="space-y-3">
            <Field label="Name" htmlFor="service-name">
              <Input
                id="service-name"
                value={serviceName}
                onChange={(event) => setServiceName(event.target.value)}
              />
            </Field>
            <Field label="Purpose" htmlFor="service-description">
              <Textarea
                id="service-description"
                value={serviceDescription}
                onChange={(event) => setServiceDescription(event.target.value)}
              />
            </Field>
            <Button
              variant="primary"
              onClick={() => void createService()}
              loading={busy === 'service'}
              disabled={!serviceName.trim()}
            >
              <Bot size={14} aria-hidden /> Create service account
            </Button>
          </CardBody>
        </Card>
      </div>

      <SectionHeader title="Roles" />
      <p className="-mt-1 mb-2 text-xs text-muted">
        Built-in compatibility roles remain code-defined and immutable.
      </p>
      <div className="mb-5 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {loading
          ? Array.from({ length: 3 }).map((_, index) => (
              <Card key={index}>
                <CardSkeleton />
              </Card>
            ))
          : roles.map((role) => (
              <Card key={role.id}>
                <CardHeader
                  title={
                    <span className="flex items-center gap-2">
                      <ShieldCheck size={15} className="text-accent" /> {role.name}
                    </span>
                  }
                  actions={
                    <Badge tone={role.is_system ? 'accent' : 'neutral'}>
                      {role.is_system ? 'Built in' : 'Custom'}
                    </Badge>
                  }
                />
                <CardBody>
                  <p className="text-xs text-muted">{role.description || 'No description'}</p>
                  <p className="mt-3 text-xs font-medium text-text">
                    {role.permission_keys.length} permissions
                  </p>
                  <p className="mt-1 line-clamp-3 text-[11px] text-faint">
                    {role.permission_keys.join(', ') || 'No permissions'}
                  </p>
                </CardBody>
              </Card>
            ))}
      </div>

      <SectionHeader title="Scoped grants" />
      <p className="-mt-1 mb-2 text-xs text-muted">
        Organization grants cover every site; site grants cover exactly one site.
      </p>
      <Card className="mb-5">
        <CardBody className="pt-4">
          <div className="mb-4 grid gap-3 lg:grid-cols-[1.4fr_1fr_0.8fr_1fr_auto] lg:items-end">
            <Field label="Principal">
              <Select
                value={grantPrincipal}
                onChange={(event) => setGrantPrincipal(event.target.value)}
              >
                <option value="">Choose a user or service</option>
                {principals.map((principal) => (
                  <option key={principal.value} value={principal.value}>
                    {principal.label}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Role">
              <Select value={grantRole} onChange={(event) => setGrantRole(event.target.value)}>
                <option value="">Choose a role</option>
                {roles.map((role) => (
                  <option key={role.id} value={role.id}>
                    {role.name}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Scope">
              <Select
                value={grantScope}
                onChange={(event) => setGrantScope(event.target.value as GrantScopeType)}
              >
                <option value="organization">Organization</option>
                <option value="site">Site</option>
              </Select>
            </Field>
            <Field label="Site">
              <Select
                disabled={grantScope === 'organization'}
                value={grantSite}
                onChange={(event) => setGrantSite(event.target.value)}
              >
                <option value="">Choose a site</option>
                {sites.map((site) => (
                  <option key={site.id} value={site.id}>
                    {site.name}
                  </option>
                ))}
              </Select>
            </Field>
            <Button
              variant="primary"
              onClick={() => void createGrant()}
              loading={busy === 'grant'}
              disabled={!grantPrincipal || !grantRole || (grantScope === 'site' && !grantSite)}
            >
              <Plus size={14} aria-hidden /> Grant
            </Button>
          </div>
          {grants.length === 0 && !loading ? (
            <EmptyState
              compact
              title="No scoped grants"
              description="Create a grant to give a principal access."
            />
          ) : (
            <div className="divide-y divide-border">
              {grants.map((grant) => (
                <div key={grant.id} className="flex flex-wrap items-center gap-3 py-2.5 text-xs">
                  {grant.principal_type === 'user' ? (
                    <UserRoundCog size={15} className="text-muted" />
                  ) : (
                    <Bot size={15} className="text-muted" />
                  )}
                  <span className="min-w-44 font-medium text-text">{principalName(grant)}</span>
                  <Badge tone="accent">{grant.role_name}</Badge>
                  <span className="text-muted">{scopeName(grant)}</span>
                  <Button
                    className="ml-auto"
                    size="icon-sm"
                    variant="ghost"
                    aria-label={`Remove ${grant.role_name}`}
                    loading={busy === grant.id}
                    onClick={() => void deleteGrant(grant)}
                  >
                    <Trash2 size={13} aria-hidden />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardBody>
      </Card>

      <SectionHeader title="API tokens" />
      <p className="-mt-1 mb-2 text-xs text-muted">
        All tokens expire, may be IP-restricted, and are displayed only once.
      </p>
      <Card className="mb-5">
        <CardBody className="pt-4">
          <div className="mb-4 grid gap-3 lg:grid-cols-[1fr_1fr_0.6fr_1fr_auto] lg:items-end">
            <Field label="Owner">
              <Select value={tokenOwner} onChange={(event) => setTokenOwner(event.target.value)}>
                <option value="personal">My account</option>
                {services
                  .filter((value) => value.status === 'active')
                  .map((account) => (
                    <option key={account.id} value={account.id}>
                      {account.name}
                    </option>
                  ))}
              </Select>
            </Field>
            <Field label="Token name">
              <Input value={tokenName} onChange={(event) => setTokenName(event.target.value)} />
            </Field>
            <Field label="Days">
              <Input
                type="number"
                min={1}
                max={365}
                value={tokenDays}
                onChange={(event) => setTokenDays(Number(event.target.value))}
              />
            </Field>
            <Field label="Allowed IPs" hint="Optional CIDRs, comma-separated">
              <Input
                value={tokenIps}
                onChange={(event) => setTokenIps(event.target.value)}
                placeholder="10.0.0.0/8"
              />
            </Field>
            <Button
              variant="primary"
              onClick={() => void issueToken()}
              loading={busy === 'token'}
              disabled={!tokenName.trim()}
            >
              <KeyRound size={14} aria-hidden /> Issue token
            </Button>
          </div>
          <div className="divide-y divide-border">
            {allTokens.map((value) => (
              <div key={value.id} className="flex flex-wrap items-center gap-3 py-2.5 text-xs">
                <KeyRound size={14} className="text-muted" />
                <span className="min-w-40 font-medium text-text">{value.name}</span>
                <code className="text-[11px] text-muted">{value.token_prefix}…</code>
                <Badge tone={value.revoked_at ? 'bad' : 'ok'}>
                  {value.revoked_at ? 'Revoked' : 'Active'}
                </Badge>
                <span className="text-muted">
                  Expires {new Date(value.expires_at).toLocaleDateString()}
                </span>
                <span className="text-faint">Last used {when(value.last_used_at)}</span>
                {!value.revoked_at && (
                  <Button
                    className="ml-auto"
                    size="sm"
                    variant="destructive"
                    loading={busy === value.id}
                    onClick={() => void revokeToken(value)}
                  >
                    Revoke
                  </Button>
                )}
              </div>
            ))}
            {!loading && allTokens.length === 0 && (
              <EmptyState
                compact
                title="No API tokens"
                description="Issue a short-lived token when automation needs access."
              />
            )}
          </div>
        </CardBody>
      </Card>

      <SectionHeader title="Service accounts" />
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {services.map((account) => (
          <Card key={account.id}>
            <CardHeader
              title={
                <span className="flex items-center gap-2">
                  <Bot size={15} className="text-accent" /> {account.name}
                </span>
              }
              actions={
                <Badge tone={account.status === 'active' ? 'ok' : 'bad'}>
                  {label(account.status)}
                </Badge>
              }
            />
            <CardBody>
              <p className="text-xs text-muted">{account.description || 'No purpose recorded'}</p>
              <p className="mt-3 text-[11px] text-faint">
                Primary role: {label(account.primary_role)} · Last used:{' '}
                {when(account.last_used_at)}
              </p>
              {account.status === 'active' && (
                <Button
                  className="mt-3"
                  size="sm"
                  variant="destructive"
                  loading={busy === account.id}
                  onClick={() => void suspendService(account)}
                >
                  Suspend and revoke
                </Button>
              )}
            </CardBody>
          </Card>
        ))}
      </div>
    </div>
  );
}
