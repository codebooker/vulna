import { useCallback, useEffect, useState } from 'react';
import { Plus, ShieldOff } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useToast } from '../lib/toast';
import { StatusBadge } from '../components/app/badges';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { Field, Input, Select } from '../components/ui/input';
import { CodeBlock } from '../components/ui/misc';
import { ConfirmDialog } from '../components/ui/overlay';
import { EmptyState, InlineError } from '../components/ui/states';
import type { Relay, RelayEnrollment } from '../types/relay';
import type { Site } from '../types/inventory';

/** VulnaRelay (advanced, opt-in): a thin-site tunnel with no scanners, where
 *  scope is enforced at the central egress. OFF by default. The smart
 *  VulnaScout probe remains the recommended default. */
export function RelayPage() {
  const { token, user } = useAuth();
  const { toast } = useToast();
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [relays, setRelays] = useState<Relay[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [enrollment, setEnrollment] = useState<RelayEnrollment | null>(null);
  const [name, setName] = useState('');
  const [siteId, setSiteId] = useState('');
  const [scopeDrafts, setScopeDrafts] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [killTarget, setKillTarget] = useState<Relay | null>(null);
  const [busy, setBusy] = useState(false);

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
      toast('success', 'Relay scope updated.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update relay scope.');
    }
  };

  const resume = async (id: string) => {
    if (!token) return;
    try {
      await api.resumeRelay(token, id);
      await load();
      toast('success', 'Relay resumed.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Resume failed.');
    }
  };

  const kill = async (relay: Relay) => {
    if (!token) return;
    setBusy(true);
    try {
      await api.killRelay(token, relay.id);
      await load();
      toast('warning', `Kill switch engaged for ${relay.name}.`);
      setKillTarget(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Kill switch failed.');
    } finally {
      setBusy(false);
    }
  };

  if (enabled === null) return null;

  return (
    <div aria-label="VulnaRelay">
      <Card className="mb-3 flex flex-wrap items-center justify-between gap-3 px-4 py-3">
        <div className="min-w-0">
          <p className="text-[13px] font-semibold text-text">Relay mode (advanced)</p>
          <p className="mt-0.5 max-w-xl text-xs leading-relaxed text-muted">
            A thin-site tunnel with no scanners; the central scanner reaches the site through it and
            scope is enforced at the central egress. Opt-in — the smart VulnaScout probe is the
            recommended default.
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <p className="text-xs text-muted">
            Relay mode is <strong className="text-text">{enabled ? 'on' : 'off'}</strong>.
          </p>
          {isAdmin && (
            <Button variant="outline" size="sm" onClick={() => void toggle()}>
              {enabled ? 'Disable relay mode' : 'Enable relay mode'}
            </Button>
          )}
        </div>
      </Card>

      {error && <InlineError message={error} className="mb-3" />}

      {enabled && (
        <>
          {relays.length === 0 ? (
            <Card className="mb-3">
              <EmptyState
                compact
                icon={ShieldOff}
                title="No relays enrolled yet"
                description="Add a relay below to tunnel a thin site through the central scanner."
              />
            </Card>
          ) : (
            <div className="mb-3 flex flex-col gap-2.5">
              {relays.map((r) => (
                <Card key={r.id} className="p-3.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[13px] font-semibold text-text">{r.name}</span>
                    <StatusBadge status={r.status} />
                    {r.tunnel_up && <Badge tone="ok">Tunnel up</Badge>}
                    <span className="text-xs text-muted">
                      {sites.find((site) => site.id === r.site_id)?.name ?? 'Unknown site'}
                    </span>
                    <span className="ml-auto flex items-center gap-1.5">
                      {isAdmin && r.status !== 'killed' && (
                        <Button size="sm" variant="destructive" onClick={() => setKillTarget(r)}>
                          Kill switch
                        </Button>
                      )}
                      {isAdmin && r.status === 'killed' && (
                        <Button size="sm" variant="outline" onClick={() => void resume(r.id)}>
                          Resume
                        </Button>
                      )}
                    </span>
                  </div>
                  {isAdmin && (
                    <div className="mt-2.5 flex flex-wrap items-center gap-2">
                      <Input
                        aria-label={`Approved CIDRs for ${r.name}`}
                        placeholder="Approved CIDRs, comma-separated"
                        className="max-w-md flex-1"
                        value={scopeDrafts[r.id] ?? r.approved_cidrs.join(', ')}
                        onChange={(event) =>
                          setScopeDrafts((current) => ({ ...current, [r.id]: event.target.value }))
                        }
                      />
                      <Button size="sm" variant="outline" onClick={() => void saveScope(r)}>
                        Save scope
                      </Button>
                    </div>
                  )}
                </Card>
              ))}
            </div>
          )}

          {isAdmin && (
            <Card className="p-3.5">
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
                Add a relay
              </p>
              <div className="flex flex-wrap items-end gap-2">
                <Field label="Relay name" htmlFor="relay-name" className="min-w-40 flex-1">
                  <Input
                    id="relay-name"
                    placeholder="e.g. site-b"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                  />
                </Field>
                <Field label="Site" htmlFor="relay-site" className="min-w-40 flex-1">
                  <Select
                    id="relay-site"
                    value={siteId}
                    onChange={(event) => setSiteId(event.target.value)}
                  >
                    <option value="">Choose a site</option>
                    {sites.map((site) => (
                      <option key={site.id} value={site.id}>
                        {site.name}
                      </option>
                    ))}
                  </Select>
                </Field>
                <Button variant="primary" disabled={!name || !siteId} onClick={() => void enroll()}>
                  <Plus size={14} aria-hidden /> Add relay
                </Button>
              </div>

              {enrollment && (
                <div className="mt-3 rounded-lg border border-border bg-surface-2 p-3">
                  <p className="mb-1.5 text-xs text-muted">
                    Run this on the relay host (shown once):
                  </p>
                  <CodeBlock>{enrollment.install.command}</CodeBlock>
                  <p className="mt-1.5 text-xs text-muted">{enrollment.install.note}</p>
                </div>
              )}
            </Card>
          )}
        </>
      )}

      <ConfirmDialog
        open={killTarget !== null}
        onClose={() => setKillTarget(null)}
        destructive
        busy={busy}
        title={`Engage kill switch for “${killTarget?.name}”?`}
        body="This tears the tunnel and stops all scanning through this relay immediately."
        confirmLabel="Engage kill switch"
        onConfirm={() => {
          if (killTarget) void kill(killTarget);
        }}
      />
    </div>
  );
}
