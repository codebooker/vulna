import { useCallback, useEffect, useState } from 'react';
import { Globe, MonitorCheck } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { Field, Input, Select } from '../components/ui/input';
import { CodeBlock } from '../components/ui/misc';
import { InlineError } from '../components/ui/states';
import type { BrowserTest, NetworkStatus, ValidateResult } from '../types/networking';

const MODE_LABEL: Record<string, string> = {
  localhost: 'Local host only',
  lan: 'Private LAN (IP / local name)',
  public_dns: 'Public DNS name with automatic TLS',
  existing_proxy: 'Behind my existing reverse proxy',
  manual_cert: 'Manually supplied certificate',
};

/** Networking / URL / TLS assistant. Application TLS is kept separate from
 *  VulnaScout mutual TLS. Admins only. */
export function NetworkingPage() {
  const { token, user } = useAuth();
  const [status, setStatus] = useState<NetworkStatus | null>(null);
  const [mode, setMode] = useState('public_dns');
  const [hostname, setHostname] = useState('vulna.example.com');
  const [scheme, setScheme] = useState('https');
  const [result, setResult] = useState<ValidateResult | null>(null);
  const [browser, setBrowser] = useState<BrowserTest | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [validating, setValidating] = useState(false);

  const isAdmin = user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    try {
      setStatus(await api.networkingStatus(token));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load networking status.');
    }
  }, [token]);

  useEffect(() => {
    if (isAdmin) void load();
  }, [isAdmin, load]);

  if (!isAdmin) return null;

  const validate = async () => {
    if (!token) return;
    setError(null);
    setValidating(true);
    try {
      setResult(await api.validateNetworking(token, { mode, hostname, scheme }));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Validation failed.');
    } finally {
      setValidating(false);
    }
  };

  const testThisBrowser = async () => {
    if (!token) return;
    setError(null);
    try {
      setBrowser(await api.testBrowser(token));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Test failed.');
    }
  };

  return (
    <div aria-label="Networking assistant">
      <h2 className="mb-1 text-[15px] font-semibold text-text">Networking &amp; access</h2>
      <p className="mb-4 max-w-2xl text-[13px] text-muted">
        Reach VulnaDash securely from the intended network. Application TLS is separate from
        VulnaScout mutual TLS — changing one never affects the other.
      </p>

      {error && <InlineError message={error} className="mb-3" />}

      <Card className="mb-3 p-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Field label="Access mode" htmlFor="net-mode">
            <Select id="net-mode" value={mode} onChange={(e) => setMode(e.target.value)}>
              {(status?.access_modes ?? Object.keys(MODE_LABEL)).map((m) => (
                <option key={m} value={m}>
                  {MODE_LABEL[m] ?? m}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Hostname" htmlFor="net-host">
            <Input id="net-host" value={hostname} onChange={(e) => setHostname(e.target.value)} />
          </Field>
          <Field label="Scheme" htmlFor="net-scheme">
            <Select id="net-scheme" value={scheme} onChange={(e) => setScheme(e.target.value)}>
              <option value="https">https</option>
              <option value="http">http</option>
            </Select>
          </Field>
        </div>
        <div className="mt-3 flex gap-2">
          <Button variant="primary" loading={validating} onClick={() => void validate()}>
            <Globe size={14} aria-hidden /> Validate
          </Button>
          <Button variant="outline" onClick={() => void testThisBrowser()}>
            <MonitorCheck size={14} aria-hidden /> Test from this browser
          </Button>
        </div>
      </Card>

      {result && (
        <Card className="mb-3 p-4">
          <p className="mb-2 text-[13px] font-semibold">
            {result.valid ? (
              <span className="text-ok">No problems detected.</span>
            ) : (
              <span className="text-bad">{result.issues.length} issue(s) found.</span>
            )}
          </p>
          {result.issues.map((i) => (
            <div
              key={i.code}
              className="mb-2 rounded-lg border border-warn/30 bg-warn/10 px-3 py-2"
            >
              <p className="text-xs font-medium text-warn">⚠ {i.problem}</p>
              <p className="mt-0.5 text-xs text-muted">→ {i.action}</p>
            </div>
          ))}
          {result.settings.warnings.map((w) => (
            <p key={w} className="text-xs text-muted">
              {w}
            </p>
          ))}
          {mode === 'existing_proxy' && (
            <details className="mt-2">
              <summary className="cursor-pointer text-xs font-medium text-accent-strong">
                Reverse-proxy snippet (nginx)
              </summary>
              <CodeBlock className="mt-2">{result.proxy_snippet}</CodeBlock>
            </details>
          )}
        </Card>
      )}

      {browser && (
        <Card className="p-4">
          <h3 className="mb-2 text-[13px] font-semibold text-text">
            What the server sees from this browser
          </h3>
          <ul className="flex flex-col gap-1.5 text-[13px] text-text">
            <li className="flex items-center justify-between">
              <span className="text-muted">Reachable</span>
              <Badge tone={browser.reachable ? 'ok' : 'bad'}>
                {browser.reachable ? 'yes' : 'no'}
              </Badge>
            </li>
            <li className="flex items-center justify-between">
              <span className="text-muted">Peer</span>
              <span>{browser.peer ?? '—'}</span>
            </li>
            <li className="flex items-center justify-between">
              <span className="text-muted">Peer is a trusted proxy</span>
              <Badge tone={browser.peer_is_trusted_proxy ? 'ok' : 'neutral'}>
                {browser.peer_is_trusted_proxy ? 'yes' : 'no'}
              </Badge>
            </li>
            <li className="flex items-center justify-between">
              <span className="text-muted">Forwarded proto</span>
              <span>{browser.forwarded_proto ?? '—'}</span>
            </li>
          </ul>
          <p className="mt-2 text-xs text-muted">{browser.note}</p>
        </Card>
      )}
    </div>
  );
}
