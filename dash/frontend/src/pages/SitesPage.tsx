import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { Building2, LayoutGrid, Plus, Rows3 } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useToast } from '../lib/toast';
import { formatWhenFull } from '../lib/utils';
import { DataTable, type ColumnDef } from '../components/app/data-table';
import { PageHeader } from '../components/app/page-header';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { Field, Input } from '../components/ui/input';
import { Code, DetailRow } from '../components/ui/misc';
import { Drawer, Modal } from '../components/ui/overlay';
import { EmptyState, ErrorState, InlineError, TableSkeleton } from '../components/ui/states';
import { Segmented } from '../components/ui/tabs';
import type { NetworkScope, Site } from '../types/inventory';

/** Sites: the site list front and center, with table/card views and creation
 *  in a modal instead of a permanent inline form. */
export function SitesPage() {
  const { token, user, logout } = useAuth();
  const [sites, setSites] = useState<Site[]>([]);
  const [scopes, setScopes] = useState<NetworkScope[]>([]);
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
      const [page, scopePage] = await Promise.all([
        api.listSites(token),
        api.listScopes(token).catch(() => null),
      ]);
      setSites(page.items);
      setScopes(scopePage?.items ?? []);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        logout();
        return;
      }
      setError(err instanceof Error ? err.message : 'Failed to load sites.');
    } finally {
      setLoading(false);
    }
  }, [token, logout]);

  useEffect(() => {
    void loadSites();
  }, [loadSites]);

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
    [scopeCount],
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

      {/* Detail drawer */}
      <Drawer
        open={selected !== null}
        onClose={() => setSelected(null)}
        title={selected?.name ?? ''}
        description={selected ? `Site code ${selected.code}` : undefined}
      >
        {selected && (
          <div className="flex flex-col gap-4">
            <dl className="divide-y divide-border rounded-lg border border-border px-3">
              <DetailRow label="Code">
                <Code>{selected.code}</Code>
              </DetailRow>
              <DetailRow label="Location">{selected.address ?? '—'}</DetailRow>
              <DetailRow label="Timezone">{selected.timezone}</DetailRow>
              <DetailRow label="Business owner">{selected.business_owner ?? '—'}</DetailRow>
              <DetailRow label="Technical owner">{selected.technical_owner ?? '—'}</DetailRow>
              <DetailRow label="Created">{formatWhenFull(selected.created_at)}</DetailRow>
              <DetailRow label="Updated">{formatWhenFull(selected.updated_at)}</DetailRow>
            </dl>
            {selected.description && (
              <p className="text-[13px] leading-relaxed text-muted">{selected.description}</p>
            )}
            <section>
              <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
                Approved scopes
              </h3>
              {scopes.filter((sc) => sc.site_id === selected.id).length === 0 ? (
                <p className="text-xs text-muted">No approved scopes for this site yet.</p>
              ) : (
                <ul className="flex flex-col gap-1.5">
                  {scopes
                    .filter((sc) => sc.site_id === selected.id)
                    .map((sc) => (
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
          </div>
        )}
      </Drawer>

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
