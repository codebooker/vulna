import { useCallback, useEffect, useMemo, useState } from 'react';
import { Copy, KeyRound, RefreshCw, ShieldOff, UsersRound } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { PageHeader, SectionHeader } from '../components/app/page-header';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card, CardBody, CardHeader } from '../components/ui/card';
import { Field, Input, Select } from '../components/ui/input';
import { CardSkeleton, EmptyState, InlineError } from '../components/ui/states';
import { useToast } from '../lib/toast';
import type { Role } from '../types/auth';
import type { Site } from '../types/inventory';
import type {
  ScimGroupMapping,
  ScimMappingPayload,
  ScimMappingPreview,
  ScimProvisioningLog,
  ScimToken,
} from '../types/scim';

const ROLES: Array<Role | ''> = [
  '',
  'administrator',
  'security_operator',
  'pentest_approver',
  'remediation_owner',
  'auditor',
  'viewer',
];

function label(value: string) {
  return value.replaceAll('_', ' ').replace(/\b\w/g, (part) => part.toUpperCase());
}

function dateLabel(value: string | null) {
  return value ? new Date(value).toLocaleString() : 'Never';
}

function initialMapping(group: ScimGroupMapping): ScimMappingPayload {
  return {
    role: group.role,
    grants_all_sites: group.grants_all_sites,
    site_ids: group.site_ids,
  };
}

export function ScimProvisioningPage() {
  const { token } = useAuth();
  const { toast } = useToast();
  const [tokens, setTokens] = useState<ScimToken[]>([]);
  const [groups, setGroups] = useState<ScimGroupMapping[]>([]);
  const [logs, setLogs] = useState<ScimProvisioningLog[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tokenName, setTokenName] = useState('Primary directory');
  const [oneTimeToken, setOneTimeToken] = useState<string | null>(null);
  const [editingGroup, setEditingGroup] = useState<string | null>(null);
  const [mapping, setMapping] = useState<ScimMappingPayload>({
    role: null,
    grants_all_sites: false,
    site_ids: [],
  });
  const [preview, setPreview] = useState<ScimMappingPreview | null>(null);

  const scimBaseUrl = useMemo(() => `${window.location.origin}/scim/v2`, []);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [tokenRows, groupRows, logPage, sitePage] = await Promise.all([
        api.listScimTokens(token),
        api.listScimGroups(token),
        api.scimProvisioningLogs(token),
        api.listSites(token),
      ]);
      setTokens(tokenRows);
      setGroups(groupRows);
      setLogs(logPage.items);
      setSites(sitePage.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'SCIM settings could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const createToken = async () => {
    if (!token || !tokenName.trim()) return;
    setBusy('create-token');
    setError(null);
    try {
      const issued = await api.createScimToken(token, tokenName.trim());
      setOneTimeToken(issued.token);
      setTokenName('Primary directory');
      toast('success', 'SCIM token created. Copy it now; it will not be shown again.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'SCIM token could not be created.');
    } finally {
      setBusy(null);
    }
  };

  const rotateToken = async (value: ScimToken) => {
    if (!token) return;
    setBusy(value.id);
    setError(null);
    try {
      const issued = await api.rotateScimToken(token, value.id);
      setOneTimeToken(issued.token);
      toast('success', 'Token rotated. The previous token is already revoked.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'SCIM token could not be rotated.');
    } finally {
      setBusy(null);
    }
  };

  const revokeToken = async (value: ScimToken) => {
    if (!token) return;
    setBusy(value.id);
    setError(null);
    try {
      await api.revokeScimToken(token, value.id);
      toast('success', 'SCIM token revoked immediately.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'SCIM token could not be revoked.');
    } finally {
      setBusy(null);
    }
  };

  const openMapping = (group: ScimGroupMapping) => {
    setEditingGroup(group.id);
    setMapping(initialMapping(group));
    setPreview(null);
  };

  const previewMapping = async () => {
    if (!token || !editingGroup) return;
    setBusy(`preview-${editingGroup}`);
    setError(null);
    try {
      setPreview(await api.previewScimGroupMapping(token, editingGroup, mapping));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Mapping preview failed.');
    } finally {
      setBusy(null);
    }
  };

  const applyMapping = async () => {
    if (!token || !editingGroup || !preview) return;
    setBusy(`apply-${editingGroup}`);
    setError(null);
    try {
      await api.updateScimGroupMapping(token, editingGroup, mapping);
      setEditingGroup(null);
      setPreview(null);
      toast('success', 'SCIM access mapping applied and affected sessions revoked.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Mapping could not be applied.');
    } finally {
      setBusy(null);
    }
  };

  const toggleSite = (siteId: string) => {
    setPreview(null);
    setMapping((current) => ({
      ...current,
      site_ids: current.site_ids.includes(siteId)
        ? current.site_ids.filter((value) => value !== siteId)
        : [...current.site_ids, siteId],
    }));
  };

  return (
    <div aria-label="SCIM provisioning">
      <PageHeader
        crumbs={[{ label: 'Administration' }, { label: 'Provisioning' }]}
        title="SCIM provisioning"
        description="Provision users and groups through a standards-based, organization-isolated SCIM 2.0 endpoint. Tokens are hashed and shown only once."
      />

      {error && <InlineError message={error} className="mb-3" />}

      <Card className="mb-4">
        <CardHeader
          title="Service provider"
          description="Use these values in your identity provider."
        />
        <CardBody>
          <div className="grid gap-3 md:grid-cols-[1fr_auto] md:items-end">
            <Field label="Tenant URL">
              <Input value={scimBaseUrl} readOnly />
            </Field>
            <Button
              variant="secondary"
              onClick={() => void navigator.clipboard.writeText(scimBaseUrl)}
            >
              <Copy size={14} aria-hidden /> Copy URL
            </Button>
          </div>
          <p className="mt-2 text-xs text-muted">
            Users authenticate through SSO. SCIM passwords are never stored or accepted for local
            login.
          </p>
        </CardBody>
      </Card>

      {oneTimeToken && (
        <Card className="mb-4 border-warn/40">
          <CardHeader
            title="Copy this token now"
            description="Vulna stores only its hash. Closing this notice permanently hides the value."
          />
          <CardBody>
            <div className="flex flex-col gap-2 md:flex-row">
              <Input value={oneTimeToken} readOnly aria-label="One-time SCIM token" />
              <Button
                variant="primary"
                onClick={() => void navigator.clipboard.writeText(oneTimeToken)}
              >
                <Copy size={14} aria-hidden /> Copy token
              </Button>
              <Button variant="ghost" onClick={() => setOneTimeToken(null)}>
                I saved it
              </Button>
            </div>
          </CardBody>
        </Card>
      )}

      <SectionHeader title="Bearer tokens" />
      <Card className="mb-4">
        <CardBody>
          <div className="mb-4 grid gap-3 md:grid-cols-[1fr_auto] md:items-end">
            <Field label="Token name" htmlFor="scim-token-name">
              <Input
                id="scim-token-name"
                value={tokenName}
                maxLength={255}
                onChange={(event) => setTokenName(event.target.value)}
              />
            </Field>
            <Button
              variant="primary"
              disabled={busy === 'create-token' || !tokenName.trim()}
              onClick={() => void createToken()}
            >
              <KeyRound size={14} aria-hidden /> Create token
            </Button>
          </div>
          {loading ? (
            <CardSkeleton lines={3} />
          ) : tokens.length === 0 ? (
            <EmptyState
              compact
              icon={KeyRound}
              title="No SCIM tokens"
              description="Create a purpose-named token for your directory connector."
            />
          ) : (
            <div className="space-y-2">
              {tokens.map((value) => (
                <div
                  key={value.id}
                  className="flex flex-col justify-between gap-3 rounded-lg border border-border p-3 md:flex-row md:items-center"
                >
                  <div>
                    <div className="flex items-center gap-2 text-sm font-medium">
                      {value.name}
                      <Badge tone={value.revoked_at ? 'bad' : 'ok'} dot>
                        {value.revoked_at ? 'Revoked' : 'Active'}
                      </Badge>
                    </div>
                    <p className="mt-1 text-xs text-muted">
                      {value.token_prefix}… · expires {dateLabel(value.expires_at)} · last used{' '}
                      {dateLabel(value.last_used_at)}
                    </p>
                  </div>
                  {!value.revoked_at && (
                    <div className="flex gap-2">
                      <Button
                        variant="secondary"
                        size="sm"
                        disabled={busy === value.id}
                        onClick={() => void rotateToken(value)}
                      >
                        <RefreshCw size={13} aria-hidden /> Rotate
                      </Button>
                      <Button
                        variant="destructive"
                        size="sm"
                        disabled={busy === value.id}
                        onClick={() => void revokeToken(value)}
                      >
                        <ShieldOff size={13} aria-hidden /> Revoke
                      </Button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardBody>
      </Card>

      <SectionHeader title="Group access mappings" />
      <Card className="mb-4">
        <CardBody>
          {loading ? (
            <CardSkeleton lines={3} />
          ) : groups.length === 0 ? (
            <EmptyState
              compact
              icon={UsersRound}
              title="No provisioned groups"
              description="Groups appear here after your directory sends them to the SCIM Groups endpoint."
            />
          ) : (
            <div className="space-y-3">
              {groups.map((group) => (
                <div key={group.id} className="rounded-lg border border-border p-3">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-sm font-medium text-text">{group.display_name}</p>
                      <p className="mt-1 text-xs text-muted">
                        {group.member_count} members · role{' '}
                        {group.role ? label(group.role) : 'Viewer fallback'} ·{' '}
                        {group.grants_all_sites
                          ? 'all sites'
                          : `${group.site_ids.length} assigned sites`}
                      </p>
                    </div>
                    <Button variant="secondary" size="sm" onClick={() => openMapping(group)}>
                      Configure
                    </Button>
                  </div>

                  {editingGroup === group.id && (
                    <div className="mt-3 grid gap-3 border-t border-border pt-3">
                      <Field label="Compatibility role">
                        <Select
                          value={mapping.role ?? ''}
                          onChange={(event) => {
                            setPreview(null);
                            setMapping((current) => ({
                              ...current,
                              role: (event.target.value || null) as Role | null,
                            }));
                          }}
                        >
                          {ROLES.map((role) => (
                            <option key={role || 'none'} value={role}>
                              {role ? label(role) : 'No mapped role (Viewer fallback)'}
                            </option>
                          ))}
                        </Select>
                      </Field>
                      <label className="flex items-center gap-2 text-xs text-muted">
                        <input
                          type="checkbox"
                          checked={mapping.grants_all_sites}
                          onChange={(event) => {
                            setPreview(null);
                            setMapping((current) => ({
                              ...current,
                              grants_all_sites: event.target.checked,
                              site_ids: event.target.checked ? [] : current.site_ids,
                            }));
                          }}
                        />
                        Grant all sites
                      </label>
                      {!mapping.grants_all_sites && sites.length > 0 && (
                        <div className="grid gap-2 sm:grid-cols-2">
                          {sites.map((site) => (
                            <label
                              key={site.id}
                              className="flex items-center gap-2 text-xs text-muted"
                            >
                              <input
                                type="checkbox"
                                checked={mapping.site_ids.includes(site.id)}
                                onChange={() => toggleSite(site.id)}
                              />
                              {site.name}
                            </label>
                          ))}
                        </div>
                      )}
                      {preview && preview.group_id === group.id && (
                        <div className="rounded-lg bg-surface-2 p-3 text-xs text-muted">
                          Preview: {preview.affected_users} users will be recalculated. Existing
                          sessions are revoked when effective access changes. No policy is applied
                          until you confirm.
                        </div>
                      )}
                      <div className="flex flex-wrap gap-2">
                        <Button
                          variant="secondary"
                          size="sm"
                          disabled={busy === `preview-${group.id}`}
                          onClick={() => void previewMapping()}
                        >
                          Preview impact
                        </Button>
                        <Button
                          variant="primary"
                          size="sm"
                          disabled={!preview || busy === `apply-${group.id}`}
                          onClick={() => void applyMapping()}
                        >
                          Apply mapping
                        </Button>
                        <Button variant="ghost" size="sm" onClick={() => setEditingGroup(null)}>
                          Cancel
                        </Button>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardBody>
      </Card>

      <SectionHeader title="Provisioning history" />
      <Card>
        <CardBody>
          {logs.length === 0 ? (
            <p className="text-sm text-muted">No SCIM requests have been recorded.</p>
          ) : (
            <div className="space-y-2">
              {logs.map((value) => (
                <div
                  key={value.id}
                  className="flex items-center justify-between gap-3 border-b border-border py-2 last:border-0"
                >
                  <div>
                    <p className="text-sm text-text">
                      {value.operation.toUpperCase()} {value.resource_type ?? 'SCIM'}
                    </p>
                    <p className="text-xs text-muted">
                      {dateLabel(value.created_at)} · HTTP {value.status_code}
                      {value.detail ? ` · ${value.detail}` : ''}
                    </p>
                  </div>
                  <Badge tone={value.succeeded ? 'ok' : 'bad'} dot>
                    {value.succeeded ? 'Succeeded' : 'Failed'}
                  </Badge>
                </div>
              ))}
            </div>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
