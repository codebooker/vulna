import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Network as NetworkIcon, Plus } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useToast } from '../lib/toast';
import { StatusBadge } from '../components/app/badges';
import { PageHeader } from '../components/app/page-header';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { Field, Input, Select } from '../components/ui/input';
import { Code } from '../components/ui/misc';
import { ConfirmDialog, Modal } from '../components/ui/overlay';
import { CardSkeleton, EmptyState, ErrorState, InlineError } from '../components/ui/states';
import type { Site } from '../types/inventory';
import type { Network } from '../types/network';
import type { ProbeSummary } from '../types/onboarding';

/** Networks: named groups of address ranges under a site, bound to Scouts. */
export function NetworksPage() {
  const { token, user, logout } = useAuth();
  const [networks, setNetworks] = useState<Network[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [probes, setProbes] = useState<ProbeSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [toDelete, setToDelete] = useState<Network | null>(null);
  const [busy, setBusy] = useState(false);

  const isAdmin = user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [nets, sitePage, probePage] = await Promise.all([
        api.listNetworks(token),
        api.listSites(token),
        api.listProbes(token),
      ]);
      setNetworks(nets);
      setSites(sitePage.items);
      setProbes(probePage.items);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        logout();
        return;
      }
      setError(err instanceof Error ? err.message : 'Failed to load networks.');
    } finally {
      setLoading(false);
    }
  }, [token, logout]);

  useEffect(() => {
    void load();
  }, [load]);

  const siteName = (id: string) => sites.find((s) => s.id === id)?.name ?? id.slice(0, 8);

  const deleteNetwork = async () => {
    if (!token || !toDelete) return;
    setBusy(true);
    try {
      await api.deleteNetwork(token, toDelete.id);
      setToDelete(null);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Delete failed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div aria-label="Networks">
      <PageHeader
        crumbs={[{ label: 'Management' }, { label: 'Networks' }]}
        title="Networks"
        description="Named groups of address ranges under a site, bound to one or more Scouts. Bind an extra Scout to reach another site's network across an SD-WAN/VPN."
        actions={
          isAdmin && (
            <Button variant="primary" onClick={() => setCreateOpen(true)}>
              <Plus size={14} aria-hidden /> Add network
            </Button>
          )
        }
      />

      {error && <InlineError message={error} className="mb-3" />}

      {loading ? (
        <Card>
          <CardSkeleton lines={5} />
        </Card>
      ) : networks.length === 0 && !error ? (
        <Card>
          <EmptyState
            icon={NetworkIcon}
            title="No networks yet"
            description="Create a network to define which ranges a location holds and which Scouts reach them."
            action={
              isAdmin ? (
                <Button variant="primary" size="sm" onClick={() => setCreateOpen(true)}>
                  <Plus size={13} aria-hidden /> Add network
                </Button>
              ) : undefined
            }
          />
        </Card>
      ) : loading === false && error ? (
        <Card>
          <ErrorState compact message={error} onRetry={() => void load()} />
        </Card>
      ) : (
        <div className="flex flex-col gap-3">
          {networks.map((net) => (
            <NetworkCard
              key={net.id}
              net={net}
              siteName={siteName(net.site_id)}
              probes={probes}
              isAdmin={isAdmin}
              onChanged={load}
              onDelete={() => setToDelete(net)}
            />
          ))}
        </div>
      )}

      {isAdmin && (
        <CreateNetworkModal
          open={createOpen}
          sites={sites}
          probes={probes}
          onClose={() => setCreateOpen(false)}
          onCreated={() => {
            setCreateOpen(false);
            void load();
          }}
        />
      )}

      <ConfirmDialog
        open={toDelete !== null}
        onClose={() => setToDelete(null)}
        destructive
        busy={busy}
        title={`Delete network “${toDelete?.name}”?`}
        body="Bound Scouts are released and schedules against this network stop working."
        confirmLabel="Delete network"
        onConfirm={() => void deleteNetwork()}
      />
    </div>
  );
}

function NetworkCard({
  net,
  siteName,
  probes,
  isAdmin,
  onChanged,
  onDelete,
}: {
  net: Network;
  siteName: string;
  probes: ProbeSummary[];
  isAdmin: boolean;
  onChanged: () => void;
  onDelete: () => void;
}) {
  const { token } = useAuth();
  const { toast } = useToast();
  const [cidr, setCidr] = useState('');
  const [scoutId, setScoutId] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [renaming, setRenaming] = useState(false);
  const [nameDraft, setNameDraft] = useState(net.name);

  const run = async (fn: () => Promise<unknown>, success?: string) => {
    if (!token) return;
    setError(null);
    try {
      await fn();
      onChanged();
      if (success) toast('success', success);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed.');
    }
  };

  const unbound = probes.filter((p) => !net.scouts.some((s) => s.probe_id === p.id));

  return (
    <Card className="p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-[var(--accent-tint)] text-accent">
          <NetworkIcon size={15} aria-hidden />
        </span>
        {renaming ? (
          <div className="flex min-w-0 flex-1 items-center gap-2">
            <Input
              value={nameDraft}
              onChange={(e) => setNameDraft(e.target.value)}
              className="max-w-xs"
              aria-label="Network name"
            />
            <Button
              size="sm"
              variant="outline"
              disabled={!nameDraft.trim() || nameDraft === net.name}
              onClick={() =>
                void run(
                  () => api.updateNetwork(token!, net.id, { name: nameDraft.trim() }),
                  'Network renamed.',
                ).then(() => setRenaming(false))
              }
            >
              Save
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setNameDraft(net.name);
                setRenaming(false);
              }}
            >
              Cancel
            </Button>
          </div>
        ) : (
          <>
            <div className="min-w-0 flex-1">
              <p className="text-[13px] font-semibold text-text">{net.name}</p>
              <p className="text-[11px] text-muted">{siteName}</p>
            </div>
            <StatusBadge status={net.enabled ? 'enabled' : 'disabled'} />
            {isAdmin && (
              <>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    setNameDraft(net.name);
                    setRenaming(true);
                  }}
                >
                  Rename
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() =>
                    void run(
                      () => api.updateNetwork(token!, net.id, { enabled: !net.enabled }),
                      net.enabled ? 'Network disabled.' : 'Network enabled.',
                    )
                  }
                >
                  {net.enabled ? 'Disable' : 'Enable'}
                </Button>
                <Button size="sm" variant="ghost" className="text-bad" onClick={onDelete}>
                  Delete
                </Button>
              </>
            )}
          </>
        )}
      </div>

      <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
        <div className="rounded-lg border border-border bg-surface-2/60 p-3">
          <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted">
            Ranges
          </p>
          {net.ranges.length === 0 ? (
            <p className="text-xs text-faint">No ranges yet.</p>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {net.ranges.map((r) => (
                <Code key={r.id}>{r.cidr}</Code>
              ))}
            </div>
          )}
        </div>
        <div className="rounded-lg border border-border bg-surface-2/60 p-3">
          <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted">
            Scouts
          </p>
          {net.scouts.length === 0 ? (
            <p className="text-xs text-warn">No bound scout — scans cannot run.</p>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {net.scouts.map((s) => (
                <Badge key={s.probe_id} tone={s.is_primary ? 'accent' : 'neutral'}>
                  {s.probe_name}
                  {s.is_primary && ' · primary'}
                </Badge>
              ))}
            </div>
          )}
        </div>
      </div>

      {error && <InlineError message={error} className="mt-3" />}

      {isAdmin && (
        <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-border pt-3">
          <Input
            aria-label="Add range (CIDR)"
            placeholder="10.2.0.0/16"
            className="w-40"
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
          />
          <Button
            size="sm"
            variant="outline"
            disabled={!cidr}
            onClick={() =>
              void run(() => api.addNetworkRange(token!, net.id, cidr), 'Range added.').then(() =>
                setCidr(''),
              )
            }
          >
            Add range
          </Button>
          <span className="mx-1 hidden h-5 w-px bg-border sm:block" aria-hidden />
          <Select
            aria-label="Bind scout"
            className="w-44"
            value={scoutId}
            onChange={(e) => setScoutId(e.target.value)}
          >
            <option value="">Bind a scout…</option>
            {unbound.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </Select>
          <Button
            size="sm"
            variant="outline"
            disabled={!scoutId}
            onClick={() =>
              void run(
                () => api.bindNetworkScout(token!, net.id, scoutId, net.scouts.length === 0),
                'Scout bound.',
              ).then(() => setScoutId(''))
            }
          >
            Bind scout
          </Button>
          {net.scouts.map((s) => (
            <Button
              key={s.probe_id}
              size="sm"
              variant="ghost"
              onClick={() =>
                void run(() => api.unbindNetworkScout(token!, net.id, s.probe_id), 'Scout unbound.')
              }
            >
              Unbind {s.probe_name}
            </Button>
          ))}
        </div>
      )}
    </Card>
  );
}

function CreateNetworkModal({
  open,
  sites,
  probes,
  onClose,
  onCreated,
}: {
  open: boolean;
  sites: Site[];
  probes: ProbeSummary[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const { token } = useAuth();
  const { toast } = useToast();
  const [siteId, setSiteId] = useState('');
  const [name, setName] = useState('');
  const [cidr, setCidr] = useState('');
  const [scoutId, setScoutId] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!token || !siteId || !name) return;
    setError(null);
    setSubmitting(true);
    try {
      await api.createNetwork(token, {
        site_id: siteId,
        name,
        ranges: cidr ? [{ cidr }] : [],
        scouts: scoutId ? [{ probe_id: scoutId, is_primary: true }] : [],
      });
      setName('');
      setCidr('');
      setScoutId('');
      toast('success', 'Network created.');
      onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create network.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Add a network"
      description="Define the ranges a location holds and which Scout reaches them."
    >
      <form className="flex flex-col gap-3" onSubmit={handleSubmit}>
        <Field label="Site" htmlFor="net-site">
          <Select id="net-site" value={siteId} onChange={(e) => setSiteId(e.target.value)} required>
            <option value="">Choose a site…</option>
            {sites.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Name" htmlFor="net-name">
          <Input
            id="net-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Office LAN"
            required
          />
        </Field>
        <Field label="First range (CIDR, optional)" htmlFor="net-cidr">
          <Input
            id="net-cidr"
            value={cidr}
            placeholder="10.2.0.0/16"
            onChange={(e) => setCidr(e.target.value)}
          />
        </Field>
        <Field label="Primary scout (optional)" htmlFor="net-scout">
          <Select id="net-scout" value={scoutId} onChange={(e) => setScoutId(e.target.value)}>
            <option value="">None</option>
            {probes.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </Select>
        </Field>
        {error && <InlineError message={error} />}
        <div className="mt-1 flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" loading={submitting}>
            {submitting ? 'Creating…' : 'Create network'}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
