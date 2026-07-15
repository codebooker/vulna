import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { Building2, LayoutGrid, Plus, Rows3 } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useToast } from '../lib/toast';
import { useNav } from '../lib/nav';
import { formatWhenFull } from '../lib/utils';
import { DataTable, type ColumnDef } from '../components/app/data-table';
import { PageHeader } from '../components/app/page-header';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { Field, Input, Select } from '../components/ui/input';
import { Code, DetailRow } from '../components/ui/misc';
import { ConfirmDialog, Drawer, Modal } from '../components/ui/overlay';
import { EmptyState, ErrorState, InlineError, TableSkeleton } from '../components/ui/states';
import { Segmented } from '../components/ui/tabs';
import type { NetworkScope, Site } from '../types/inventory';
import type { UserSummary } from '../types/auth';

/** Sites: the site list front and center, with table/card views and creation
 *  in a modal instead of a permanent inline form. */
export function SitesPage() {
  const { token, user, logout } = useAuth();
  const { current } = useNav();
  const [sites, setSites] = useState<Site[]>([]);
  const [scopes, setScopes] = useState<NetworkScope[]>([]);
  const [users, setUsers] = useState<UserSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<'table' | 'cards'>('table');
  const [createOpen, setCreateOpen] = useState(false);
  const [selected, setSelected] = useState<Site | null>(null);

  const isAdmin = user?.role === 'administrator';

  const loadSites = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [page, scopePage, userPage] = await Promise.all([
        api.listAllSites(token),
        api.listAllScopes(token).catch(() => null),
        isAdmin ? api.listUsers(token).catch(() => null) : Promise.resolve(null),
      ]);
      setSites(page.items);
      setScopes(scopePage?.items ?? []);
      setUsers(
        (userPage?.items ?? []).filter(
          (candidate) =>
            candidate.is_active !== false &&
            (!candidate.account_status || candidate.account_status === 'active'),
        ),
      );
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        logout();
        return;
      }
      setError(err instanceof Error ? err.message : 'Failed to load sites.');
    } finally {
      setLoading(false);
    }
  }, [token, logout, isAdmin]);

  useEffect(() => {
    void loadSites();
  }, [loadSites]);

  const handledSiteLink = useRef<string | null>(null);
  useEffect(() => {
    const siteId = current.params.site;
    if (!siteId || handledSiteLink.current === siteId) return;
    const match = sites.find((site) => site.id === siteId);
    if (match) {
      handledSiteLink.current = siteId;
      setSelected(match);
    }
  }, [current.params.site, sites]);

  const scopeCount = useCallback(
    (siteId: string) => scopes.filter((s) => s.site_id === siteId).length,
    [scopes],
  );

  const columns: ColumnDef<Site>[] = useMemo(
    () => [
      {
        id: 'name',
        header: 'Site name',
        cell: (s) => <span className="font-medium text-text">{s.name}</span>,
        sortValue: (s) => s.name,
        csvValue: (s) => s.name,
      },
      {
        id: 'code',
        header: 'Code',
        cell: (s) => <Code>{s.code}</Code>,
        sortValue: (s) => s.code,
        csvValue: (s) => s.code,
      },
      {
        id: 'location',
        header: 'Location',
        cell: (s) =>
          s.address ? (
            <span className="text-xs text-muted">{s.address}</span>
          ) : (
            <span className="text-faint">—</span>
          ),
        sortValue: (s) => s.address ?? '',
        csvValue: (s) => s.address ?? '',
      },
      {
        id: 'timezone',
        header: 'Timezone',
        cell: (s) => <span className="text-xs text-muted">{s.timezone}</span>,
        sortValue: (s) => s.timezone,
        csvValue: (s) => s.timezone,
      },
      {
        id: 'owner',
        header: 'Fallback owner',
        defaultHidden: true,
        cell: (s) => (
          <span className="text-xs text-muted">
            {users.find((candidate) => candidate.id === s.owner_user_id)?.full_name ?? '—'}
          </span>
        ),
        sortValue: (s) =>
          users.find((candidate) => candidate.id === s.owner_user_id)?.full_name ?? '',
        csvValue: (s) => users.find((candidate) => candidate.id === s.owner_user_id)?.email ?? '',
      },
      {
        id: 'scopes',
        header: 'Approved scopes',
        cell: (s) => {
          const n = scopeCount(s.id);
          return n > 0 ? (
            <Badge tone="accent">
              {n} scope{n === 1 ? '' : 's'}
            </Badge>
          ) : (
            <span className="text-faint">None</span>
          );
        },
        sortValue: (s) => scopeCount(s.id),
        csvValue: (s) => String(scopeCount(s.id)),
        align: 'right',
      },
      {
        id: 'tags',
        header: 'Tags',
        defaultHidden: true,
        cell: (s) =>
          s.tags.length > 0 ? (
            <span className="flex flex-wrap gap-1">
              {s.tags.map((t) => (
                <Badge key={t} tone="neutral">
                  {t}
                </Badge>
              ))}
            </span>
          ) : (
            <span className="text-faint">—</span>
          ),
        csvValue: (s) => s.tags.join(' '),
      },
      {
        id: 'updated',
        header: 'Last updated',
        cell: (s) => <span className="text-xs text-muted">{formatWhenFull(s.updated_at)}</span>,
        sortValue: (s) => s.updated_at,
        csvValue: (s) => s.updated_at,
      },
    ],
    [scopeCount, users],
  );

  return (
    <div aria-label="Sites">
      <PageHeader
        crumbs={[{ label: 'Operations' }, { label: 'Sites' }]}
        title="Sites"
        description="Locations and their approved network scopes."
        actions={
          <>
            <Segmented
              ariaLabel="View"
              options={[
                {
                  id: 'table',
                  label: <Rows3 size={14} aria-label="Table view" />,
                  title: 'Table view',
                },
                {
                  id: 'cards',
                  label: <LayoutGrid size={14} aria-label="Card view" />,
                  title: 'Card view',
                },
              ]}
              value={view}
              onChange={(v) => setView(v as 'table' | 'cards')}
            />
            {isAdmin && (
              <Button variant="primary" onClick={() => setCreateOpen(true)}>
                <Plus size={14} aria-hidden /> Add site
              </Button>
            )}
          </>
        }
      />

      {view === 'table' ? (
        <DataTable<Site>
          columns={columns}
          rows={sites}
          rowKey={(s) => s.id}
          searchText={(s) => `${s.name} ${s.code} ${s.address ?? ''} ${s.tags.join(' ')}`}
          searchPlaceholder="Search sites…"
          onRowClick={setSelected}
          loading={loading}
          error={error}
          onRetry={() => void loadSites()}
          emptyTitle="No sites yet"
          emptyDescription="Create your first site to organize networks and appliances by location."
          emptyAction={
            isAdmin ? (
              <Button variant="primary" size="sm" onClick={() => setCreateOpen(true)}>
                <Plus size={13} aria-hidden /> Add site
              </Button>
            ) : undefined
          }
          exportName="sites"
          storageKey="vulnadash.sites"
          defaultSort={{ id: 'name', dir: 'asc' }}
        />
      ) : loading ? (
        <Card>
          <TableSkeleton rows={3} cols={3} />
        </Card>
      ) : error ? (
        <Card>
          <ErrorState compact message={error} onRetry={() => void loadSites()} />
        </Card>
      ) : sites.length === 0 ? (
        <Card>
          <EmptyState
            icon={Building2}
            title="No sites yet"
            description="Create your first site to organize networks and appliances by location."
            action={
              isAdmin ? (
                <Button variant="primary" size="sm" onClick={() => setCreateOpen(true)}>
                  <Plus size={13} aria-hidden /> Add site
                </Button>
              ) : undefined
            }
          />
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {sites.map((s) => (
            <Card
              key={s.id}
              role="button"
              tabIndex={0}
              onClick={() => setSelected(s)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  setSelected(s);
                }
              }}
              className="cursor-pointer p-4 transition-colors hover:border-border-strong hover:bg-surface-2"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-[var(--accent-tint)] text-accent">
                    <Building2 size={15} aria-hidden />
                  </span>
                  <div>
                    <p className="text-[13px] font-semibold text-text">{s.name}</p>
                    <p className="text-[11px] text-muted">{s.address ?? s.timezone}</p>
                  </div>
                </div>
                <Code>{s.code}</Code>
              </div>
              <div className="mt-3 flex items-center gap-2 text-xs text-muted">
                <Badge tone={scopeCount(s.id) > 0 ? 'accent' : 'neutral'}>
                  {scopeCount(s.id)} scope{scopeCount(s.id) === 1 ? '' : 's'}
                </Badge>
                {s.tags.map((t) => (
                  <Badge key={t} tone="neutral">
                    {t}
                  </Badge>
                ))}
              </div>
            </Card>
          ))}
        </div>
      )}

      <SiteDrawer
        site={selected}
        scopes={scopes}
        users={users}
        isAdmin={isAdmin}
        onClose={() => setSelected(null)}
        onChanged={() => void loadSites()}
      />

      {isAdmin && (
        <CreateSiteModal
          open={createOpen}
          onClose={() => setCreateOpen(false)}
          onCreated={() => {
            setCreateOpen(false);
            void loadSites();
          }}
        />
      )}
    </div>
  );
}

function SiteDrawer({
  site,
  scopes,
  users,
  isAdmin,
  onClose,
  onChanged,
}: {
  site: Site | null;
  scopes: NetworkScope[];
  users: UserSummary[];
  isAdmin: boolean;
  onClose: () => void;
  onChanged: () => void;
}) {
  const { token } = useAuth();
  const { toast } = useToast();
  const [name, setName] = useState('');
  const [code, setCode] = useState('');
  const [address, setAddress] = useState('');
  const [ownerId, setOwnerId] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  useEffect(() => {
    if (site) {
      setName(site.name);
      setCode(site.code);
      setAddress(site.address ?? '');
      setOwnerId(site.owner_user_id ?? '');
      setError(null);
    }
  }, [site]);

  const dirty =
    site &&
    (name !== site.name ||
      code !== site.code ||
      (address.trim() || null) !== (site.address ?? null) ||
      (ownerId || null) !== site.owner_user_id);

  const save = async () => {
    if (!token || !site || !name.trim() || !code.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await api.updateSite(token, site.id, {
        name: name.trim(),
        code: code.trim(),
        address: address.trim() || null,
        owner_user_id: ownerId || null,
      });
      onChanged();
      toast('success', 'Site updated.');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to update site.');
    } finally {
      setBusy(false);
    }
  };

  const del = async () => {
    if (!token || !site) return;
    setBusy(true);
    setError(null);
    try {
      await api.deleteSite(token, site.id);
      onChanged();
      toast('success', 'Site deleted.');
      setConfirmDelete(false);
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete site.');
    } finally {
      setBusy(false);
    }
  };

  const siteScopes = site ? scopes.filter((sc) => sc.site_id === site.id) : [];

  return (
    <Drawer
      open={site !== null}
      onClose={onClose}
      title={site?.name ?? ''}
      description={site ? `Site code ${site.code}` : undefined}
    >
      {site && (
        <div className="flex flex-col gap-4">
          {error && <InlineError message={error} />}

          {isAdmin ? (
            <div className="flex flex-col gap-3 rounded-lg border border-border p-3">
              <div className="flex gap-2">
                <Field label="Name" htmlFor="edit-site-name" className="flex-1">
                  <Input
                    id="edit-site-name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                  />
                </Field>
                <Field label="Code" htmlFor="edit-site-code" className="w-28">
                  <Input
                    id="edit-site-code"
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                  />
                </Field>
              </div>
              <Field
                label="Fallback asset owner"
                hint="Used only when no finding, asset, or group owner matches."
              >
                <Select value={ownerId} onChange={(event) => setOwnerId(event.target.value)}>
                  <option value="">No site fallback owner</option>
                  {users.map((candidate) => (
                    <option key={candidate.id} value={candidate.id}>
                      {candidate.full_name || candidate.email}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Location" htmlFor="edit-site-address">
                <Input
                  id="edit-site-address"
                  value={address}
                  onChange={(e) => setAddress(e.target.value)}
                  placeholder="Optional"
                />
              </Field>
              <div className="flex justify-end">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={busy || !dirty || !name.trim() || !code.trim()}
                  onClick={() => void save()}
                >
                  Save changes
                </Button>
              </div>
            </div>
          ) : (
            <dl className="divide-y divide-border rounded-lg border border-border px-3">
              <DetailRow label="Code">
                <Code>{site.code}</Code>
              </DetailRow>
              <DetailRow label="Location">{site.address ?? '—'}</DetailRow>
            </dl>
          )}

          <dl className="divide-y divide-border rounded-lg border border-border px-3">
            <DetailRow label="Timezone">{site.timezone}</DetailRow>
            <DetailRow label="Business owner">{site.business_owner ?? '—'}</DetailRow>
            <DetailRow label="Technical owner">{site.technical_owner ?? '—'}</DetailRow>
            <DetailRow label="Created">{formatWhenFull(site.created_at)}</DetailRow>
            <DetailRow label="Updated">{formatWhenFull(site.updated_at)}</DetailRow>
          </dl>
          {site.description && (
            <p className="text-[13px] leading-relaxed text-muted">{site.description}</p>
          )}

          <section>
            <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
              Approved scopes
            </h3>
            {siteScopes.length === 0 ? (
              <p className="text-xs text-muted">No approved scopes for this site yet.</p>
            ) : (
              <ul className="flex flex-col gap-1.5">
                {siteScopes.map((sc) => (
                  <li
                    key={sc.id}
                    className="flex items-center justify-between rounded-lg border border-border px-3 py-2"
                  >
                    <span className="text-[13px] text-text">{sc.name}</span>
                    <span className="flex items-center gap-2">
                      <Code>{sc.cidr}</Code>
                      <Badge tone={sc.enabled ? 'ok' : 'neutral'}>
                        {sc.enabled ? 'Enabled' : 'Disabled'}
                      </Badge>
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>

          {isAdmin && (
            <div className="mt-2 flex justify-end border-t border-border pt-3">
              <Button
                variant="destructive"
                size="sm"
                disabled={busy}
                onClick={() => setConfirmDelete(true)}
              >
                Delete site
              </Button>
            </div>
          )}
        </div>
      )}

      <ConfirmDialog
        open={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        destructive
        busy={busy}
        title={`Delete site “${site?.name}”?`}
        body="The site and its approved scopes are deleted. Networks, appliances, and findings tied to it may be affected. This cannot be undone."
        confirmLabel="Delete site"
        onConfirm={() => void del()}
      />
    </Drawer>
  );
}

function CreateSiteModal({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}) {
  const { token, logout } = useAuth();
  const { toast } = useToast();
  const [name, setName] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!token) return;
    setError(null);
    setSubmitting(true);
    try {
      await api.createSite(token, { name, code });
      setName('');
      setCode('');
      toast('success', 'Site created.');
      onCreated();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        logout();
        return;
      }
      setError(err instanceof Error ? err.message : 'Failed to create site.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Add a site"
      description="A site groups networks, appliances, and findings by physical or logical location."
    >
      <form className="flex flex-col gap-3" onSubmit={handleSubmit}>
        <Field label="Name" htmlFor="site-name">
          <Input
            id="site-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Head Office"
            required
          />
        </Field>
        <Field label="Code" htmlFor="site-code" hint="Short unique identifier, e.g. HQ.">
          <Input
            id="site-code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="HQ"
            required
          />
        </Field>
        {error && <InlineError message={error} />}
        <div className="mt-1 flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" loading={submitting}>
            {submitting ? 'Creating…' : 'Create site'}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
