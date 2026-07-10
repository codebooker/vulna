import { useEffect, useState } from 'react';
import { fetchHealth, fetchSystemInfo } from '../api/client';
import type { SystemInfoResponse } from '../types/system';

type ConnectionState = 'pending' | 'ok' | 'error';

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
    <div className="card">
      <h2>System health</h2>
      <div className="status-row">
        <span className={`dot ${state === 'ok' ? 'ok' : state === 'error' ? 'bad' : 'pending'}`} />
        <span>{label}</span>
      </div>

      {state === 'ok' && info && (
        <div className="detail">
          Service <code>{info.service}</code> version <code>{info.version}</code> · environment{' '}
          <code>{info.environment}</code> · API <code>{info.api_version}</code>
        </div>
      )}

      {state === 'error' && error && (
        <div className="detail">
          Could not reach the VulnaDash API: <code>{error}</code>
        </div>
      )}
    </div>
  );
}
