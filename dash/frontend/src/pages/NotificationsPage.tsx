import { useCallback, useEffect, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import type {
  NotificationChannel,
  NotificationDelivery,
  NotificationEventDef,
} from '../types/notifications';

/** Notifications: configure and test email or webhook channels without editing
 *  env files. Credentials are write-only (never returned); webhook destinations
 *  are SSRF-validated by the API. */
export function NotificationsPage() {
  const { token, user } = useAuth();
  const [events, setEvents] = useState<NotificationEventDef[]>([]);
  const [channels, setChannels] = useState<NotificationChannel[]>([]);
  const [deliveries, setDeliveries] = useState<NotificationDelivery[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // New-channel form.
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [secret, setSecret] = useState('');
  const [selected, setSelected] = useState<string[]>([]);

  const isAdmin = user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    try {
      setEvents((await api.notificationEvents(token)).events);
      setChannels((await api.listChannels(token)).channels);
      setDeliveries((await api.listDeliveries(token)).deliveries);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load notifications.');
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const toggleEvent = (type: string) =>
    setSelected((cur) => (cur.includes(type) ? cur.filter((t) => t !== type) : [...cur, type]));

  const createWebhook = async () => {
    if (!token) return;
    setError(null);
    setNotice(null);
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
      setNotice('Channel created.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create channel.');
    }
  };

  const test = async (id: string) => {
    if (!token) return;
    setError(null);
    setNotice(null);
    try {
      await api.testChannel(token, id);
      setNotice('Test notification sent.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Test failed.');
    }
  };

  return (
    <section className="card" aria-label="Notifications">
      <h2>Notifications</h2>
      <p className="detail">
        Get notified by email or webhook. Credentials are stored encrypted and never shown again;
        webhook URLs are validated to prevent request forgery.
      </p>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {notice && <p className="detail">{notice}</p>}

      <h3>Channels</h3>
      {channels.length === 0 ? (
        <p className="detail">No channels configured yet.</p>
      ) : (
        <ul className="status-list">
          {channels.map((c) => (
            <li key={c.id}>
              <span className={c.enabled ? 'ok' : 'pending'}>{c.channel_type}</span>{' '}
              <strong>{c.name}</strong> — {c.events.length} event(s), {c.policy}
              {isAdmin && (
                <button
                  type="button"
                  className="btn ghost"
                  style={{ marginLeft: '0.75rem' }}
                  onClick={() => void test(c.id)}
                >
                  Send test
                </button>
              )}
            </li>
          ))}
        </ul>
      )}

      {isAdmin && (
        <>
          <h3>Add a webhook</h3>
          <div className="stack">
            <input
              aria-label="Channel name"
              placeholder="Name (e.g. ops-webhook)"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <input
              aria-label="Webhook URL"
              placeholder="https://…"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
            <input
              aria-label="Signing secret"
              placeholder="Signing secret"
              type="password"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
            />
            <fieldset>
              <legend>Events</legend>
              {events.map((ev) => (
                <label key={ev.type} style={{ display: 'block' }}>
                  <input
                    type="checkbox"
                    checked={selected.includes(ev.type)}
                    onChange={() => toggleEvent(ev.type)}
                  />{' '}
                  {ev.label}
                </label>
              ))}
            </fieldset>
            <button
              type="button"
              className="btn"
              disabled={!name || !url || selected.length === 0}
              onClick={() => void createWebhook()}
            >
              Create channel
            </button>
          </div>
        </>
      )}

      <h3>Delivery history</h3>
      {deliveries.length === 0 ? (
        <p className="detail">No deliveries yet.</p>
      ) : (
        <ul className="status-list">
          {deliveries.slice(0, 8).map((d) => (
            <li key={d.id}>
              <span
                className={d.status === 'sent' ? 'ok' : d.status === 'failed' ? 'bad' : 'pending'}
              >
                {d.status}
              </span>{' '}
              {d.event_type} — {d.title}
              {d.last_error && <div className="detail">Error: {d.last_error}</div>}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
