import { useEffect, useState } from 'react';
import { fetchHealth, fetchSystemInfo } from '../api/client';
import { cn } from '../lib/utils';
import { Code } from '../components/ui/misc';
import type { SystemInfoResponse } from '../types/system';

type ConnectionState = 'pending' | 'ok' | 'error';

/** Compact backend connectivity status (shown on the login screen). */
export function HealthPage() {
  const [state, setState] = useState<ConnectionState>('pending');
  const [info, setInfo] = useState<SystemInfoResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function check() {
      try {
        const health = await fetchHealth();
        if (health.status !== 'ok') {
          throw new Error(`Unexpected status: ${health.status}`);
        }
        const systemInfo = await fetchSystemInfo();
        if (!cancelled) {
          setInfo(systemInfo);
          setState('ok');
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : String(err));
          setState('error');
        }
      }
    }

    void check();
    return () => {
      cancelled = true;
    };
  }, []);

  const label =
    state === 'ok'
      ? 'Backend reachable'
      : state === 'error'
        ? 'Backend unreachable'
        : 'Checking backend…';

  return (
    <div>
      <div className="flex items-center gap-2 text-[13px] text-text">
        <span
          aria-hidden
          className={cn(
            'h-2 w-2 rounded-full',
            state === 'ok' ? 'bg-ok' : state === 'error' ? 'bg-bad' : 'bg-warn animate-pulse',
          )}
        />
        <span>{label}</span>
      </div>

      {state === 'ok' && info && (
        <p className="mt-1.5 text-xs text-muted">
          Service <Code>{info.service}</Code> version <Code>{info.version}</Code> · environment{' '}
          <Code>{info.environment}</Code> · API <Code>{info.api_version}</Code>
        </p>
      )}

      {state === 'error' && error && (
        <p className="mt-1.5 text-xs text-muted">
          Could not reach the VulnaDash API: <Code>{error}</Code>
        </p>
      )}
    </div>
  );
}
