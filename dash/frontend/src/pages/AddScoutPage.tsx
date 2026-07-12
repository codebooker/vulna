import { useCallback, useEffect, useState } from 'react';
import { Copy, TerminalSquare } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useToast } from '../lib/toast';
import { formatWhenFull } from '../lib/utils';
import { Button } from '../components/ui/button';
import { Field, Select } from '../components/ui/input';
import { Code, CodeBlock } from '../components/ui/misc';
import { InlineError } from '../components/ui/states';
import type { Site } from '../types/inventory';
import type { EnrollmentCommand } from '../types/remote';

/** Per-site "Add VulnaScout": generates a short-lived, single-use install
 *  command for a remote Scout. Enrolling never authorizes a target. Admins
 *  only. Rendered inside the Appliances page (drawer) and standalone in tests. */
export function AddScoutPage() {
  const { token, user } = useAuth();
  const { toast } = useToast();
  const [sites, setSites] = useState<Site[]>([]);
  const [siteId, setSiteId] = useState('');
  const [cmd, setCmd] = useState<EnrollmentCommand | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [generating, setGenerating] = useState(false);

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
    setGenerating(true);
    try {
      setCmd(await api.addScout(token, siteId));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not generate the command.');
    } finally {
      setGenerating(false);
    }
  };

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      toast('success', 'Command copied to clipboard.');
    } catch {
      setCopied(false);
    }
  };

  return (
    <div aria-label="Add a remote VulnaScout">
      <p className="mb-3 text-[13px] leading-relaxed text-muted">
        Generate a one-time install command for another host. It expires, works once, and needs no
        inbound port on the remote site. Enrolling never authorizes a target — approve a scope
        afterward.
      </p>
      {error && <InlineError message={error} className="mb-3" />}

      <div className="flex flex-wrap items-end gap-2">
        <Field label="Site" htmlFor="scout-site" className="min-w-48 flex-1">
          <Select id="scout-site" value={siteId} onChange={(e) => setSiteId(e.target.value)}>
            {sites.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name} ({s.code})
              </option>
            ))}
          </Select>
        </Field>
        <Button
          variant="primary"
          disabled={!siteId}
          loading={generating}
          onClick={() => void generate()}
        >
          <TerminalSquare size={14} aria-hidden /> Generate install command
        </Button>
      </div>

      {cmd && (
        <div className="mt-4 rounded-lg border border-border bg-surface-2 p-3.5">
          <p className="mb-2 text-xs text-muted">
            Run this on the remote Linux host (amd64/arm64). It downloads a signed release, verifies
            its signature, installs, and enrolls:
          </p>
          <CodeBlock>{cmd.commands.universal}</CodeBlock>
          <div className="mt-2.5 flex flex-wrap items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => void copy(cmd.commands.universal)}>
              <Copy size={12} aria-hidden /> {copied ? 'Copied' : 'Copy command'}
            </Button>
            <span className="text-xs text-muted">
              Verify code <Code>{cmd.short_code}</Code> · expires {formatWhenFull(cmd.expires_at)}
            </span>
          </div>
          <p className="mt-2.5 text-xs text-warn">
            The token is shown once. Its enrollment status appears in the appliances list once the
            host connects.
          </p>
        </div>
      )}
    </div>
  );
}
