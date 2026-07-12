import { useCallback, useEffect, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import type { Relay, RelayEnrollment } from '../types/relay';
import type { Site } from '../types/inventory';

/** VulnaRelay (advanced, opt-in): a thin-site tunnel with no scanners, where scope
 *  is enforced at the central egress. OFF by default; an admin turns it on here.
 *  The smart VulnaScout probe remains the recommended default. */
export function RelayPage() {
  const { token, user } = useAuth();
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [relays, setRelays] = useState<Relay[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [enrollment, setEnrollment] = useState<RelayEnrollment | null>(null);
  const [name, setName] = useState('');
  const [siteId, setSiteId] = useState('');
  const [scopeDrafts, setScopeDrafts] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);

  const isAdmin = user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    try {
      const on = (await api.relaySettings(token)).enabled;
      setEnabled(on);
      const loadedSites = (await api.listSites(token)).items;
      setSites(loadedSites);
      setSiteId((current) => current || loadedSites[0]?.id || '');
      if (on) setRelays((await api.listRelays(token)).relays);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load relay settings.');
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const toggle = async () => {
    if (!token || enabled === null) return;
    setError(null);
    try {
      setEnabled((await api.setRelayEnabled(token, !enabled)).enabled);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to change relay mode.');
    }
  };

  const enroll = async () => {
    if (!token || !name || !siteId) return;
    setError(null);
    try {
      setEnrollment(await api.relayEnrollmentCommand(token, name, siteId));
      setName('');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create enrollment command.');
    }
  };

  const saveScope = async (relay: Relay) => {
    if (!token) return;
    const text = scopeDrafts[relay.id] ?? relay.approved_cidrs.join(', ');
    const cidrs = text
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean);
    try {
      await api.setRelayScope(token, relay.id, cidrs);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update relay scope.');
    }
  };

  const resume = async (id: string) => {
    if (!token) return;
    try {
      await api.resumeRelay(token, id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Resume failed.');
    }
  };

  const kill = async (id: string) => {
    if (!token) return;
    if (!window.confirm('Engage the kill switch? This tears the tunnel and stops all scanning.'))
      return;
    try {
      await api.killRelay(token, id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Kill switch failed.');
    }
  };

  if (enabled === null) return null;

  return (
    <section className="card" aria-label="VulnaRelay">
      <h2>VulnaRelay (advanced)</h2>
      <p className="detail">
        A thin-site tunnel with no scanners; the central scanner reaches the site through it and
        scope is enforced at the central egress. This is an advanced, opt-in mode — the smart
        VulnaScout probe is the recommended default.
      </p>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}

      <p>
        Relay mode is <strong>{enabled ? 'on' : 'off'}</strong>.
        {isAdmin && (
          <button
            type="button"
            className="btn ghost"
            style={{ marginLeft: '0.75rem' }}
            onClick={() => void toggle()}
          >
            {enabled ? 'Disable relay mode' : 'Enable relay mode'}
          </button>
        )}
      </p>

      {enabled && (
        <>
          <h3>Relays</h3>
          {relays.length === 0 ? (
            <p className="detail">No relays enrolled yet.</p>
          ) : (
            <ul className="status-list">
              {relays.map((r) => (
                <li key={r.id}>
                  <span
                    className={
                      r.status === 'killed'
                        ? 'bad'
                        : r.status === 'enrolled' && r.tunnel_up
                          ? 'ok'
                          : 'pending'
                    }
                  >
                    {r.status}
                    {r.tunnel_up ? ' · up' : ''}
                  </span>{' '}
                  <strong>{r.name}</strong>{' '}
                  <span className="detail">
                    · {sites.find((site) => site.id === r.site_id)?.name ?? 'Unknown site'}
                  </span>{' '}
                  {isAdmin && r.status !== 'killed' && (
                    <button type="button" className="btn ghost" onClick={() => void kill(r.id)}>
                      Kill switch
                    </button>
                  )}
                  {isAdmin && r.status === 'killed' && (
                    <button type="button" className="btn ghost" onClick={() => void resume(r.id)}>
                      Resume
                    </button>
                  )}
                  {isAdmin && (
                    <div className="row">
                      <input
                        aria-label={`Approved CIDRs for ${r.name}`}
                        placeholder="Approved CIDRs, comma-separated"
                        value={scopeDrafts[r.id] ?? r.approved_cidrs.join(', ')}
                        onChange={(event) =>
                          setScopeDrafts((current) => ({ ...current, [r.id]: event.target.value }))
                        }
                      />
                      <button type="button" className="btn ghost" onClick={() => void saveScope(r)}>
                        Save scope
                      </button>
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}

          {isAdmin && (
            <div className="row">
              <input
                aria-label="Relay name"
                placeholder="Relay name (e.g. site-b)"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
              <select
                aria-label="Relay site"
                value={siteId}
                onChange={(event) => setSiteId(event.target.value)}
              >
                <option value="">Choose a site</option>
                {sites.map((site) => (
                  <option key={site.id} value={site.id}>
                    {site.name}
                  </option>
                ))}
              </select>
              <button
                type="button"
                className="btn ghost"
                disabled={!name || !siteId}
                onClick={() => void enroll()}
              >
                Add relay
              </button>
            </div>
          )}

          {enrollment && (
            <div className="preview">
              <p>Run this on the relay host (shown once):</p>
              <pre className="cmd">{enrollment.install.command}</pre>
              <p className="detail">{enrollment.install.note}</p>
            </div>
          )}
        </>
      )}
    </section>
  );
}
