import { useCallback, useEffect, useState } from 'react';
import { DownloadCloud } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useToast } from '../lib/toast';
import { humanize } from '../lib/utils';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { Switch } from '../components/ui/misc';
import { InlineError } from '../components/ui/states';
import type {
  OutboundConnection,
  PrivacySettings,
  SecretItem,
  TelemetryPreview,
} from '../types/privacy';

/** Privacy & data ownership: what can leave the deployment, configured secrets
 *  (never values), opt-in telemetry with a field-level preview, and export. */
export function PrivacyPage() {
  const { token, user } = useAuth();
  const { toast } = useToast();
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
      toast('success', 'Privacy settings updated.');
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
      toast('success', 'Export downloaded.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Export failed.');
    }
  };

  return (
    <div aria-label="Privacy">
      <h2 className="mb-4 text-[15px] font-semibold text-text">Privacy &amp; data ownership</h2>
      {error && <InlineError message={error} className="mb-3" />}

      <Card className="mb-3 p-4">
        <h3 className="mb-2 text-[13px] font-semibold text-text">What can leave this deployment</h3>
        <ul className="flex flex-col gap-2">
          {outbound.map((c) => (
            <li key={c.name} className="flex items-start justify-between gap-3">
              <span className="min-w-0">
                <span className="block text-[13px] font-medium text-text">
                  {c.name}
                  {c.destination && <span className="text-muted"> → {c.destination}</span>}
                </span>
                <span className="block text-xs text-muted">{c.purpose}</span>
              </span>
              <Badge tone={c.enabled ? 'warn' : 'ok'}>{c.enabled ? 'active' : 'off'}</Badge>
            </li>
          ))}
        </ul>
      </Card>

      {settings && (
        <Card className="mb-3 p-4">
          <h3 className="mb-2 text-[13px] font-semibold text-text">Privacy settings</h3>
          <ul className="flex flex-col gap-2.5">
            {(Object.keys(settings) as (keyof PrivacySettings)[]).map((key) => (
              <li key={key} className="flex items-center justify-between gap-3">
                <span className="text-[13px] text-text">{humanize(key)}</span>
                {isAdmin ? (
                  <Switch
                    checked={!!settings[key]}
                    onChange={() => void toggle(key)}
                    ariaLabel={humanize(key)}
                  />
                ) : (
                  <Badge tone={settings[key] ? 'ok' : 'neutral'}>
                    {settings[key] ? 'on' : 'off'}
                  </Badge>
                )}
              </li>
            ))}
          </ul>
          {preview && !settings.telemetry_enabled && (
            <p className="mt-3 border-t border-border pt-2.5 text-xs text-muted">
              Telemetry is off. If enabled, it would send only these anonymous counts:{' '}
              {Object.keys(preview.counts).join(', ')} (no IPs, hostnames, usernames, findings, or
              CVEs).
            </p>
          )}
        </Card>
      )}

      {isAdmin && secrets.length > 0 && (
        <Card className="mb-3 p-4">
          <h3 className="mb-2 text-[13px] font-semibold text-text">Secret inventory</h3>
          <ul className="flex flex-col gap-1.5">
            {secrets.map((s) => (
              <li key={s.name} className="flex items-center justify-between gap-2 text-[13px]">
                <span className="font-mono text-xs text-text">{s.name}</span>
                <Badge tone={s.present ? 'ok' : 'bad'}>{s.present ? 'set' : 'missing'}</Badge>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {isAdmin && (
        <Card className="flex flex-wrap items-center justify-between gap-3 p-4">
          <div>
            <h3 className="text-[13px] font-semibold text-text">Take your data with you</h3>
            <p className="text-xs text-muted">Full JSON export of your deployment's data.</p>
          </div>
          <Button variant="outline" onClick={() => void download()}>
            <DownloadCloud size={14} aria-hidden /> Download data export (JSON)
          </Button>
        </Card>
      )}
    </div>
  );
}
