import { useCallback, useEffect, useState } from 'react';
import { Ban, Power, ShieldOff, Trash2 } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useToast } from '../lib/toast';
import { StatusBadge } from '../components/app/badges';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { ConfirmDialog } from '../components/ui/overlay';
import { Switch } from '../components/ui/misc';
import { EmptyState, InlineError } from '../components/ui/states';
import type { Relay } from '../types/relay';
import type { Site } from '../types/inventory';

/** VulnaRelay: scanner-free WireGuard endpoints that tunnel a thin site through
 *  the central scanner. Organization opt-in and per-Relay kill switches remain
 *  explicit. Adding one is done from the "Add relay" drawer (Appliances header). */
export function RelayPage({ refreshKey }: { refreshKey?: number }) {
  const { token, user } = useAuth();
  const { toast } = useToast();
  const [relays, setRelays] = useState<Relay[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [scopeDrafts, setScopeDrafts] = useState<
    Record<string, { approved: string; denied: string; allowPublic: boolean }>
  >({});
  const [relayEnabled, setRelayEnabled] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [killTarget, setKillTarget] = useState<Relay | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<Relay | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Relay | null>(null);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);

  const isAdmin = user?.permissions
    ? user.permissions.includes('relays.manage')
    : user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    try {
      const [sitePage, relayList, settings] = await Promise.all([
        api.listSites(token),
        api.listRelays(token),
        api.relaySettings(token),
      ]);
      setSites(sitePage.items);
      setRelays(relayList.relays);
      setRelayEnabled(settings.enabled);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load relays.');
    } finally {
      setLoaded(true);
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load, refreshKey]);

  const saveScope = async (relay: Relay) => {
    if (!token) return;
    const draft = scopeDrafts[relay.id] ?? {
      approved: relay.approved_cidrs.join(', '),
      denied: relay.denied_cidrs.join(', '),
      allowPublic: relay.allow_public_addresses,
    };
    const cidrs = draft.approved
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean);
    const denied = draft.denied
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean);
    try {
      await api.setRelayScope(token, relay.id, cidrs, denied, draft.allowPublic);
      await load();
      toast('success', 'Relay scope updated.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update relay scope.');
    }
  };

  const toggleRelayMode = async () => {
    if (!token) return;
    setBusy(true);
    try {
      const result = await api.setRelayEnabled(token, !relayEnabled);
      setRelayEnabled(result.enabled);
      toast(
        result.enabled ? 'success' : 'warning',
        result.enabled ? 'Relay mode enabled.' : 'Relay mode disabled; relay egress is blocked.',
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update relay mode.');
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (relay: Relay) => {
    if (!token) return;
    setBusy(true);
    try {
      await api.revokeRelay(token, relay.id);
      setRevokeTarget(null);
      await load();
      toast('success', `${relay.name} was revoked and its managed scope was removed.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Relay revocation failed.');
    } finally {
      setBusy(false);
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

  const deleteRelay = async (relay: Relay) => {
    if (!token) return;
    setBusy(true);
    try {
      await api.deleteRelay(token, relay.id);
      setDeleteTarget(null);
      await load();
      toast('success', `${relay.name} was permanently deleted.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Relay deletion failed.');
    } finally {
      setBusy(false);
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

  if (!loaded) return null;

  return (
    <div aria-label="VulnaRelay">
      {error && <InlineError message={error} className="mb-3" />}

      {isAdmin && (
        <Card className="mb-3 flex items-center gap-3 p-3.5">
          <Power className="h-4 w-4 text-muted" />
          <div className="min-w-0 flex-1">
            <div className="text-[13px] font-semibold text-text">Organization relay mode</div>
            <div className="text-xs text-muted">
              {relayEnabled
                ? 'Relay enrollment and central tunnel egress are enabled.'
                : 'All relay egress is blocked until this is enabled.'}
            </div>
          </div>
          <Switch
            checked={relayEnabled}
            disabled={busy}
            onChange={() => void toggleRelayMode()}
            ariaLabel="Organization relay mode"
          />
        </Card>
      )}

      {relays.length === 0 ? (
        <Card className="mb-3">
          <EmptyState
            compact
            icon={ShieldOff}
            title="No relays enrolled yet"
            description="Use “Add relay” to tunnel a thin site through the central scanner."
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
                  {isAdmin && r.status === 'enrolled' && (
                    <Button size="sm" variant="destructive" onClick={() => setKillTarget(r)}>
                      Kill switch
                    </Button>
                  )}
                  {isAdmin && r.status === 'killed' && (
                    <Button size="sm" variant="outline" onClick={() => void resume(r.id)}>
                      Resume
                    </Button>
                  )}
                  {isAdmin && (r.status === 'enrolled' || r.status === 'killed') && (
                    <Button
                      size="sm"
                      variant="ghost"
                      aria-label={`Revoke ${r.name}`}
                      onClick={() => setRevokeTarget(r)}
                    >
                      <Ban className="h-3.5 w-3.5" />
                      Revoke
                    </Button>
                  )}
                  {isAdmin && (r.status === 'pending_enrollment' || r.status === 'revoked') && (
                    <Button
                      size="sm"
                      variant="destructive"
                      aria-label={`Delete ${r.name}`}
                      onClick={() => setDeleteTarget(r)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                      Delete
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
                    value={scopeDrafts[r.id]?.approved ?? r.approved_cidrs.join(', ')}
                    onChange={(event) =>
                      setScopeDrafts((current) => ({
                        ...current,
                        [r.id]: {
                          approved: event.target.value,
                          denied: current[r.id]?.denied ?? r.denied_cidrs.join(', '),
                          allowPublic: current[r.id]?.allowPublic ?? r.allow_public_addresses,
                        },
                      }))
                    }
                  />
                  <Input
                    aria-label={`Denied CIDRs for ${r.name}`}
                    placeholder="Denied CIDRs, comma-separated"
                    className="max-w-md flex-1"
                    value={scopeDrafts[r.id]?.denied ?? r.denied_cidrs.join(', ')}
                    onChange={(event) =>
                      setScopeDrafts((current) => ({
                        ...current,
                        [r.id]: {
                          approved: current[r.id]?.approved ?? r.approved_cidrs.join(', '),
                          denied: event.target.value,
                          allowPublic: current[r.id]?.allowPublic ?? r.allow_public_addresses,
                        },
                      }))
                    }
                  />
                  <label className="flex items-center gap-1.5 text-xs text-muted">
                    <input
                      type="checkbox"
                      checked={scopeDrafts[r.id]?.allowPublic ?? r.allow_public_addresses}
                      onChange={(event) =>
                        setScopeDrafts((current) => ({
                          ...current,
                          [r.id]: {
                            approved: current[r.id]?.approved ?? r.approved_cidrs.join(', '),
                            denied: current[r.id]?.denied ?? r.denied_cidrs.join(', '),
                            allowPublic: event.target.checked,
                          },
                        }))
                      }
                    />
                    Allow public addresses
                  </label>
                  <Button size="sm" variant="outline" onClick={() => void saveScope(r)}>
                    Save scope
                  </Button>
                </div>
              )}
            </Card>
          ))}
        </div>
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
      <ConfirmDialog
        open={revokeTarget !== null}
        onClose={() => setRevokeTarget(null)}
        destructive
        busy={busy}
        title={`Revoke “${revokeTarget?.name}”?`}
        body="This permanently invalidates the relay certificate, tears down the tunnel, and removes its managed scan scope. Enrolling it again will require a new token."
        confirmLabel="Revoke relay"
        onConfirm={() => {
          if (revokeTarget) void revoke(revokeTarget);
        }}
      />
      <ConfirmDialog
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        destructive
        busy={busy}
        title={`Permanently delete “${deleteTarget?.name}”?`}
        body="This removes the Relay record from Vulna. This cannot be undone. Enrolled or killed Relays must be revoked first so their certificate, tunnel, and managed scope are invalidated safely."
        confirmLabel="Delete permanently"
        onConfirm={() => {
          if (deleteTarget) void deleteRelay(deleteTarget);
        }}
      />
    </div>
  );
}
