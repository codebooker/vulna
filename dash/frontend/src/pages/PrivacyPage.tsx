import { useCallback, useEffect, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import type {
  OutboundConnection,
  PrivacySettings,
  SecretItem,
  TelemetryPreview,
} from '../types/privacy';

/** Privacy & data ownership: what can leave the deployment, what secrets are
 *  configured (never their values), opt-in telemetry with a field-level preview,
 *  and a data export. */
export function PrivacyPage() {
  const { token, user } = useAuth();
  const [outbound, setOutbound] = useState<OutboundConnection[]>([]);
  const [secrets, setSecrets] = useState<SecretItem[]>([]);
  const [settings, setSettings] = useState<PrivacySettings | null>(null);
  const [preview, setPreview] = useState<TelemetryPreview | null>(null);
  const [error, setError] = useState<string | null>(null);

  const isAdmin = user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    try {
      setOutbound((await api.privacyOutbound(token)).connections);
      setSettings((await api.privacySettings(token)).settings);
      setPreview(await api.telemetryPreview(token));
      if (isAdmin) setSecrets((await api.privacySecrets(token)).secrets);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load privacy.');
    }
  }, [token, isAdmin]);

  useEffect(() => {
    void load();
  }, [load]);

  const toggle = async (key: keyof PrivacySettings) => {
    if (!token || !settings) return;
    setError(null);
    try {
      const next = await api.updatePrivacySettings(token, { [key]: !settings[key] });
      setSettings(next.settings);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update settings.');
    }
  };

  const download = async () => {
    if (!token) return;
    setError(null);
    try {
      const bundle = await api.exportData(token);
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'vulna-export.json';
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Export failed.');
    }
  };

  return (
    <section className="card" aria-label="Privacy">
      <h2>Privacy &amp; data ownership</h2>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}

      <h3>What can leave this deployment</h3>
      <ul className="status-list">
        {outbound.map((c) => (
          <li key={c.name}>
            <span className={c.enabled ? 'pending' : 'ok'}>{c.enabled ? 'active' : 'off'}</span>{' '}
            <strong>{c.name}</strong>
            {c.destination ? ` → ${c.destination}` : ''}
            <div className="detail">{c.purpose}</div>
          </li>
        ))}
      </ul>

      {settings && (
        <>
          <h3>Privacy settings</h3>
          <ul className="status-list">
            {(Object.keys(settings) as (keyof PrivacySettings)[]).map((key) => (
              <li key={key}>
                <span className={settings[key] ? 'ok' : 'pending'}>
                  {settings[key] ? 'on' : 'off'}
                </span>{' '}
                {key.replace(/_/g, ' ')}
                {isAdmin && (
                  <button
                    type="button"
                    className="btn ghost"
                    style={{ marginLeft: '0.75rem' }}
                    onClick={() => void toggle(key)}
                  >
                    Toggle
                  </button>
                )}
              </li>
            ))}
          </ul>
          {preview && !settings.telemetry_enabled && (
            <p className="detail">
              Telemetry is off. If enabled, it would send only these anonymous counts:{' '}
              {Object.keys(preview.counts).join(', ')} (no IPs, hostnames, usernames, findings, or
              CVEs).
            </p>
          )}
        </>
      )}

      {isAdmin && secrets.length > 0 && (
        <>
          <h3>Secret inventory</h3>
          <ul className="status-list">
            {secrets.map((s) => (
              <li key={s.name}>
                <span className={s.present ? 'ok' : 'bad'}>{s.present ? 'set' : 'missing'}</span>{' '}
                {s.name}
              </li>
            ))}
          </ul>
        </>
      )}

      {isAdmin && (
        <>
          <h3>Take your data with you</h3>
          <button type="button" className="btn ghost" onClick={() => void download()}>
            Download data export (JSON)
          </button>
        </>
      )}
    </section>
  );
}
