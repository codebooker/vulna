import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import type { Site } from '../types/inventory';
import type { Network } from '../types/network';
import type { ProbeSummary } from '../types/onboarding';

/** Networks: named groups of address ranges under a site, bound to Scouts. An
 *  admin defines the ranges a location holds and which Scout(s) reach them —
 *  including a Scout that reaches another site's network across an SD-WAN/VPN. */
export function NetworksPage() {
  const { token, user, logout } = useAuth();
  const [networks, setNetworks] = useState<Network[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [probes, setProbes] = useState<ProbeSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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

  const siteName = (id: string) => sites.find((s) => s.id === id)?.name ?? id;

  return (
    <div className="card" aria-label="Networks">
      <h2>Networks</h2>
      <p className="detail">
        A network is a named group of address ranges under a site, bound to one or more Scouts. Bind
        an extra Scout to reach another site&apos;s network across an SD-WAN/VPN.
      </p>
      {loading && <p className="detail">Loading networks…</p>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}

      {!loading && networks.length === 0 && !error && <p className="detail">No networks yet.</p>}

      {networks.map((net) => (
        <NetworkCard
          key={net.id}
          net={net}
          siteName={siteName(net.site_id)}
          probes={probes}
          isAdmin={isAdmin}
          onChanged={load}
        />
      ))}

      {isAdmin && <CreateNetworkForm sites={sites} probes={probes} onCreated={load} />}
    </div>
  );
}

function NetworkCard({
  net,
  siteName,
  probes,
  isAdmin,
  onChanged,
}: {
  net: Network;
  siteName: string;
  probes: ProbeSummary[];
  isAdmin: boolean;
  onChanged: () => void;
}) {
  const { token } = useAuth();
  const [cidr, setCidr] = useState('');
  const [scoutId, setScoutId] = useState('');
  const [error, setError] = useState<string | null>(null);

  const run = async (fn: () => Promise<unknown>) => {
    if (!token) return;
    setError(null);
    try {
      await fn();
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed.');
    }
  };

  const unbound = probes.filter((p) => !net.scouts.some((s) => s.probe_id === p.id));

  return (
    <div className="preview" style={{ marginBottom: '1rem' }}>
      <h3>
        {net.name} <span className="detail">· {siteName}</span>
      </h3>
      <p className="detail">
        Ranges: {net.ranges.length === 0 ? '—' : net.ranges.map((r) => r.cidr).join(', ')}
      </p>
      <p className="detail">
        Scouts:{' '}
        {net.scouts.length === 0
          ? '— (no bound scout; scans cannot run)'
          : net.scouts.map((s) => `${s.probe_name}${s.is_primary ? ' (primary)' : ''}`).join(', ')}
      </p>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {isAdmin && (
        <div className="row">
          <input
            aria-label="Add range (CIDR)"
            placeholder="10.2.0.0/16"
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
          />
          <button
            type="button"
            className="btn ghost"
            disabled={!cidr}
            onClick={() => void run(() => api.addNetworkRange(token!, net.id, cidr))}
          >
            Add range
          </button>
          <select
            aria-label="Bind scout"
            value={scoutId}
            onChange={(e) => setScoutId(e.target.value)}
          >
            <option value="">Bind a scout…</option>
            {unbound.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
          <button
            type="button"
            className="btn ghost"
            disabled={!scoutId}
            onClick={() =>
              void run(() => api.bindNetworkScout(token!, net.id, scoutId, net.scouts.length === 0))
            }
          >
            Bind scout
          </button>
          {net.scouts.map((s) => (
            <button
              key={s.probe_id}
              type="button"
              className="btn ghost"
              onClick={() => void run(() => api.unbindNetworkScout(token!, net.id, s.probe_id))}
            >
              Unbind {s.probe_name}
            </button>
          ))}
          <button
            type="button"
            className="btn ghost"
            onClick={() => {
              if (window.confirm(`Delete network “${net.name}”?`))
                void run(() => api.deleteNetwork(token!, net.id));
            }}
          >
            Delete
          </button>
        </div>
      )}
    </div>
  );
}

function CreateNetworkForm({
  sites,
  probes,
  onCreated,
}: {
  sites: Site[];
  probes: ProbeSummary[];
  onCreated: () => void;
}) {
  const { token } = useAuth();
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
      onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create network.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="form inline" onSubmit={handleSubmit}>
      <h3>Add a network</h3>
      <div className="row">
        <label className="field">
          <span>Site</span>
          <select value={siteId} onChange={(e) => setSiteId(e.target.value)} required>
            <option value="">Choose a site…</option>
            {sites.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Name</span>
          <input value={name} onChange={(e) => setName(e.target.value)} required />
        </label>
        <label className="field">
          <span>First range (CIDR, optional)</span>
          <input value={cidr} placeholder="10.2.0.0/16" onChange={(e) => setCidr(e.target.value)} />
        </label>
        <label className="field">
          <span>Primary scout (optional)</span>
          <select value={scoutId} onChange={(e) => setScoutId(e.target.value)}>
            <option value="">None</option>
            {probes.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
      </div>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <button type="submit" className="btn" disabled={submitting}>
        {submitting ? 'Creating…' : 'Create network'}
      </button>
    </form>
  );
}
