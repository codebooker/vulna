import { useCallback, useEffect, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import type { Site } from '../types/inventory';
import type { EnrollmentCommand } from '../types/remote';

/** Per-site "Add VulnaScout": generates a short-lived, single-use install command
 *  for a remote Scout. The command routes through the signature-verifying
 *  bootstrap; enrolling does not authorize any target. Admins only. */
export function AddScoutPage() {
  const { token, user } = useAuth();
  const [sites, setSites] = useState<Site[]>([]);
  const [siteId, setSiteId] = useState('');
  const [cmd, setCmd] = useState<EnrollmentCommand | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const isAdmin = user?.role === 'administrator';

  const loadSites = useCallback(async () => {
    if (!token) return;
    try {
      const page = await api.listSites(token);
      setSites(page.items);
      if (page.items.length > 0) setSiteId((prev) => prev || page.items[0].id);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load sites.');
    }
  }, [token]);

  useEffect(() => {
    if (isAdmin) void loadSites();
  }, [isAdmin, loadSites]);

  if (!isAdmin) return null;

  const generate = async () => {
    if (!token || !siteId) return;
    setError(null);
    setCopied(false);
    try {
      setCmd(await api.addScout(token, siteId));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not generate the command.');
    }
  };

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="card">
      <h2>Add a remote VulnaScout</h2>
      <p className="detail">
        Generate a one-time install command for another host. It expires, works once, and needs no
        inbound port on the remote site. Enrolling never authorizes a target — approve a scope
        afterward.
      </p>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <div className="row">
        <label className="field">
          Site
          <select value={siteId} onChange={(e) => setSiteId(e.target.value)}>
            {sites.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name} ({s.code})
              </option>
            ))}
          </select>
        </label>
        <button type="button" className="btn" disabled={!siteId} onClick={() => void generate()}>
          Generate install command
        </button>
      </div>

      {cmd && (
        <div className="preview">
          <p className="detail">
            Run this on the remote Linux host (amd64/arm64). It downloads a signed release, verifies
            its signature, installs, and enrolls:
          </p>
          <pre className="cmd">{cmd.commands.universal}</pre>
          <div className="row">
            <button
              type="button"
              className="btn ghost"
              onClick={() => void copy(cmd.commands.universal)}
            >
              {copied ? 'Copied' : 'Copy command'}
            </button>
            <span className="detail">
              Verify code <code>{cmd.short_code}</code> · expires{' '}
              {new Date(cmd.expires_at).toLocaleString()}
            </span>
          </div>
          <p className="warn">
            The token is shown once. Its enrollment status appears in the Scouts list once the host
            connects.
          </p>
        </div>
      )}
    </div>
  );
}
