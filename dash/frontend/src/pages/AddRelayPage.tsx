import { useCallback, useEffect, useState } from 'react';
import { Plus, ShieldOff } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { Button } from '../components/ui/button';
import { Field, Input, Select } from '../components/ui/input';
import { CodeBlock } from '../components/ui/misc';
import { EmptyState, InlineError } from '../components/ui/states';
import type { RelayEnrollment } from '../types/relay';
import type { Site } from '../types/inventory';

/** Add-relay form, mirroring AddScoutPage: generates a one-time enrollment
 *  command for a scanner-free WireGuard relay endpoint. */
export function AddRelayPage({ onEnrolled }: { onEnrolled?: () => void }) {
  const { token } = useAuth();
  const [sites, setSites] = useState<Site[]>([]);
  const [name, setName] = useState('');
  const [siteId, setSiteId] = useState('');
  const [enrollment, setEnrollment] = useState<RelayEnrollment | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!token) return;
    try {
      const s = (await api.listSites(token)).items;
      setSites(s);
      setSiteId((cur) => cur || s[0]?.id || '');
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load sites.');
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const enroll = async () => {
    if (!token || !name || !siteId) return;
    setBusy(true);
    setError(null);
    try {
      setEnrollment(await api.relayEnrollmentCommand(token, name, siteId));
      setName('');
      onEnrolled?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create enrollment command.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs leading-relaxed text-muted">
        A relay is a scanner-free WireGuard endpoint that tunnels a thin site through the central
        scanner. It carries only approved-scope traffic and has its own kill switch. Run the
        generated command on the relay host as root.
      </p>
      {sites.length === 0 ? (
        <EmptyState
          compact
          icon={ShieldOff}
          title="No sites yet"
          description="Create a site first — a relay belongs to a site."
        />
      ) : (
        <>
          <div className="flex flex-wrap items-end gap-2">
            <Field label="Relay name" htmlFor="add-relay-name" className="min-w-40 flex-1">
              <Input
                id="add-relay-name"
                placeholder="e.g. site-b"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </Field>
            <Field label="Site" htmlFor="add-relay-site" className="min-w-40 flex-1">
              <Select
                id="add-relay-site"
                value={siteId}
                onChange={(e) => setSiteId(e.target.value)}
              >
                <option value="">Choose a site</option>
                {sites.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </Select>
            </Field>
            <Button
              variant="primary"
              disabled={busy || !name || !siteId}
              onClick={() => void enroll()}
            >
              <Plus size={14} aria-hidden /> Add relay
            </Button>
          </div>
          {error && <InlineError message={error} />}
          {enrollment && (
            <div className="rounded-lg border border-border bg-surface-2 p-3">
              <p className="mb-1.5 text-xs text-muted">Run this on the relay host (shown once):</p>
              <CodeBlock>{enrollment.install.command}</CodeBlock>
              <p className="mt-1.5 text-xs text-muted">{enrollment.install.note}</p>
            </div>
          )}
        </>
      )}
    </div>
  );
}
