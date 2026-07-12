import { useCallback, useEffect, useState } from 'react';
import { Plus, Send, Webhook } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useToast } from '../lib/toast';
import { StatusBadge } from '../components/app/badges';
import { PageHeader, SectionHeader } from '../components/app/page-header';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { Field, Input } from '../components/ui/input';
import { Drawer } from '../components/ui/overlay';
import { CardSkeleton, EmptyState, InlineError } from '../components/ui/states';
import type {
  NotificationChannel,
  NotificationDelivery,
  NotificationEventDef,
} from '../types/notifications';

/** Integrations & notifications: email or signed-webhook channels, configured
 *  without editing env files. Credentials are write-only; webhook URLs are
 *  SSRF-validated by the API. */
export function NotificationsPage() {
  const { token, user } = useAuth();
  const { toast } = useToast();
  const [events, setEvents] = useState<NotificationEventDef[]>([]);
  const [channels, setChannels] = useState<NotificationChannel[]>([]);
  const [deliveries, setDeliveries] = useState<NotificationDelivery[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [addOpen, setAddOpen] = useState(false);

  const isAdmin = user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      setEvents((await api.notificationEvents(token)).events);
      setChannels((await api.listChannels(token)).channels);
      setDeliveries((await api.listDeliveries(token)).deliveries);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load notifications.');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const test = async (id: string) => {
    if (!token) return;
    setError(null);
    setNotice(null);
    try {
      await api.testChannel(token, id);
      setNotice('Test notification sent.');
      toast('success', 'Test notification sent.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Test failed.');
    }
  };

  return (
    <div aria-label="Notifications">
      <PageHeader
        crumbs={[{ label: 'Administration' }, { label: 'Integrations' }]}
        title="Integrations &amp; notifications"
        description="Get notified by email or webhook. Credentials are stored encrypted and never shown again; webhook URLs are validated to prevent request forgery."
        actions={
          isAdmin && (
            <Button variant="primary" onClick={() => setAddOpen(true)}>
              <Plus size={14} aria-hidden /> Add webhook
            </Button>
          )
        }
      />

      {error && <InlineError message={error} className="mb-3" />}
      {notice && (
        <p
          className="mb-3 rounded-lg border border-ok/30 bg-ok/10 px-3 py-2 text-xs text-ok"
          role="status"
        >
          {notice}
        </p>
      )}

      <SectionHeader title="Channels" />
      {loading ? (
        <Card className="mb-4">
          <CardSkeleton lines={2} />
        </Card>
      ) : channels.length === 0 ? (
        <Card className="mb-4">
          <EmptyState
            compact
            icon={Webhook}
            title="No channels configured yet"
            description="Add a webhook to push scan results, findings, and health alerts into your tooling."
            action={
              isAdmin ? (
                <Button variant="primary" size="sm" onClick={() => setAddOpen(true)}>
                  <Plus size={13} aria-hidden /> Add webhook
                </Button>
              ) : undefined
            }
          />
        </Card>
      ) : (
        <div className="mb-4 flex flex-col gap-2">
          {channels.map((c) => (
            <Card key={c.id} className="flex flex-wrap items-center gap-2.5 px-3.5 py-2.5">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-[var(--accent-tint)] text-accent">
                <Webhook size={15} aria-hidden />
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-[13px] font-semibold text-text">{c.name}</p>
                <p className="text-[11px] text-muted">
                  {c.channel_type} · {c.events.length} event{c.events.length === 1 ? '' : 's'} ·{' '}
                  {c.policy}
                </p>
              </div>
              <StatusBadge status={c.enabled ? 'enabled' : 'disabled'} />
              {isAdmin && (
                <Button size="sm" variant="outline" onClick={() => void test(c.id)}>
                  <Send size={12} aria-hidden /> Send test
                </Button>
              )}
            </Card>
          ))}
        </div>
      )}

      <SectionHeader title="Delivery history" />
      {loading ? (
        <Card>
          <CardSkeleton lines={3} />
        </Card>
      ) : deliveries.length === 0 ? (
        <Card>
          <EmptyState
            compact
            title="No deliveries yet"
            description="Sent notifications appear here with their status."
          />
        </Card>
      ) : (
        <Card className="divide-y divide-border">
          {deliveries.slice(0, 10).map((d) => (
            <div key={d.id} className="flex flex-wrap items-center gap-2.5 px-3.5 py-2.5">
              <StatusBadge status={d.status} />
              <span className="min-w-0 flex-1">
                <span className="block truncate text-[13px] text-text">{d.title}</span>
                <span className="block text-[11px] text-muted">{d.event_type}</span>
              </span>
              {d.last_error && (
                <span className="max-w-64 truncate text-[11px] text-bad" title={d.last_error}>
                  {d.last_error}
                </span>
              )}
            </div>
          ))}
        </Card>
      )}

      {isAdmin && (
        <AddWebhookDrawer
          open={addOpen}
          events={events}
          onClose={() => setAddOpen(false)}
          onCreated={() => {
            setAddOpen(false);
            void load();
          }}
        />
      )}
    </div>
  );
}

function AddWebhookDrawer({
  open,
  events,
  onClose,
  onCreated,
}: {
  open: boolean;
  events: NotificationEventDef[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const { token } = useAuth();
  const { toast } = useToast();
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [secret, setSecret] = useState('');
  const [selected, setSelected] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const toggleEvent = (type: string) =>
    setSelected((cur) => (cur.includes(type) ? cur.filter((t) => t !== type) : [...cur, type]));

  const createWebhook = async () => {
    if (!token) return;
    setError(null);
    setSubmitting(true);
    try {
      await api.createChannel(token, {
        name,
        channel_type: 'webhook',
        config: { url },
        secret: secret || undefined,
        events: selected,
        policy: 'immediate',
      });
      setName('');
      setUrl('');
      setSecret('');
      setSelected([]);
      toast('success', 'Channel created.');
      onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create channel.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title="Add a webhook"
      description="Signed webhook deliveries; the secret is write-only."
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            loading={submitting}
            disabled={!name || !url || selected.length === 0}
            onClick={() => void createWebhook()}
          >
            Create channel
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <Field label="Channel name" htmlFor="wh-name">
          <Input
            id="wh-name"
            placeholder="e.g. ops-webhook"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </Field>
        <Field label="Webhook URL" htmlFor="wh-url">
          <Input
            id="wh-url"
            placeholder="https://…"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
        </Field>
        <Field
          label="Signing secret"
          htmlFor="wh-secret"
          hint="Optional. Stored encrypted, never shown again."
        >
          <Input
            id="wh-secret"
            type="password"
            placeholder="Signing secret"
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
          />
        </Field>
        <fieldset className="rounded-lg border border-border p-3">
          <legend className="px-1 text-xs font-semibold text-muted">Events</legend>
          <div className="flex flex-col gap-1">
            {events.map((ev) => (
              <label
                key={ev.type}
                className="flex cursor-pointer items-center gap-2.5 rounded-md px-1.5 py-1 text-[13px] text-text hover:bg-surface-2"
              >
                <input
                  type="checkbox"
                  checked={selected.includes(ev.type)}
                  onChange={() => toggleEvent(ev.type)}
                  className="accent-[var(--brand)]"
                />
                {ev.label}
              </label>
            ))}
          </div>
        </fieldset>
        {selected.length > 0 && (
          <p className="text-xs text-muted">
            <Badge tone="accent">{selected.length}</Badge> event{selected.length === 1 ? '' : 's'}{' '}
            selected
          </p>
        )}
        {error && <InlineError message={error} />}
      </div>
    </Drawer>
  );
}
