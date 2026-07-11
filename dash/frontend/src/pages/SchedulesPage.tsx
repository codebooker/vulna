import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import type { Network } from '../types/network';
import type { ScanSchedule } from '../types/schedule';

const PRESETS: { label: string; minutes: number }[] = [
  { label: 'Every 6 hours', minutes: 360 },
  { label: 'Daily', minutes: 1440 },
  { label: 'Weekly', minutes: 10080 },
];

function intervalLabel(minutes: number): string {
  const preset = PRESETS.find((p) => p.minutes === minutes);
  if (preset) return preset.label;
  if (minutes % 1440 === 0) return `Every ${minutes / 1440} days`;
  if (minutes % 60 === 0) return `Every ${minutes / 60} hours`;
  return `Every ${minutes} minutes`;
}

/** Scheduled scans: recurring, unattended vulnerability assessments of a network,
 *  run by the network's bound Scout. */
export function SchedulesPage() {
  const { token, user, logout } = useAuth();
  const [schedules, setSchedules] = useState<ScanSchedule[]>([]);
  const [networks, setNetworks] = useState<Network[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const isOperator = user?.role === 'administrator' || user?.role === 'security_operator';

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [scheds, nets] = await Promise.all([api.listSchedules(token), api.listNetworks(token)]);
      setSchedules(scheds);
      setNetworks(nets);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        logout();
        return;
      }
      setError(err instanceof Error ? err.message : 'Failed to load schedules.');
    } finally {
      setLoading(false);
    }
  }, [token, logout]);

  useEffect(() => {
    void load();
  }, [load]);

  const netName = (id: string) => networks.find((n) => n.id === id)?.name ?? id;

  const act = async (fn: () => Promise<unknown>) => {
    if (!token) return;
    setError(null);
    try {
      await fn();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed.');
    }
  };

  return (
    <div className="card" aria-label="Scheduled scans">
      <h2>Scheduled scans</h2>
      <p className="detail">
        Recurring, unattended vulnerability assessments of a network, run by its bound Scout.
        Intrusive/full-spectrum runs stay manual (they need approval).
      </p>
      {loading && <p className="detail">Loading schedules…</p>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}

      {!loading && schedules.length === 0 && !error && <p className="detail">No schedules yet.</p>}

      {schedules.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Network</th>
              <th>Cadence</th>
              <th>Next run</th>
              <th>Last run</th>
              {isOperator && <th>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {schedules.map((s) => (
              <tr key={s.id}>
                <td>{s.name}</td>
                <td>{netName(s.network_id)}</td>
                <td>
                  {intervalLabel(s.interval_minutes)}
                  {!s.enabled && <span className="detail"> · paused</span>}
                </td>
                <td>{s.enabled ? new Date(s.next_run_at).toLocaleString() : '—'}</td>
                <td>
                  {s.last_run_at ? new Date(s.last_run_at).toLocaleString() : '—'}
                  {s.last_error && (
                    <span className="error" title={s.last_error}>
                      {' '}
                      · error
                    </span>
                  )}
                </td>
                {isOperator && (
                  <td>
                    <button
                      type="button"
                      className="btn ghost"
                      onClick={() => void act(() => api.runSchedule(token!, s.id))}
                    >
                      Run now
                    </button>{' '}
                    <button
                      type="button"
                      className="btn ghost"
                      onClick={() =>
                        void act(() => api.updateSchedule(token!, s.id, { enabled: !s.enabled }))
                      }
                    >
                      {s.enabled ? 'Pause' : 'Resume'}
                    </button>{' '}
                    <button
                      type="button"
                      className="btn ghost"
                      onClick={() => {
                        if (window.confirm(`Delete schedule “${s.name}”?`))
                          void act(() => api.deleteSchedule(token!, s.id));
                      }}
                    >
                      Delete
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {isOperator && <CreateScheduleForm networks={networks} onCreated={load} />}
    </div>
  );
}

function CreateScheduleForm({
  networks,
  onCreated,
}: {
  networks: Network[];
  onCreated: () => void;
}) {
  const { token } = useAuth();
  const [networkId, setNetworkId] = useState('');
  const [name, setName] = useState('');
  const [minutes, setMinutes] = useState(1440);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!token || !networkId || !name) return;
    setError(null);
    setSubmitting(true);
    try {
      await api.createSchedule(token, { network_id: networkId, name, interval_minutes: minutes });
      setName('');
      setNetworkId('');
      onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create schedule.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="form inline" onSubmit={handleSubmit}>
      <h3>Add a schedule</h3>
      {networks.length === 0 && (
        <p className="detail">Create a network with a bound scout first.</p>
      )}
      <div className="row">
        <label className="field">
          <span>Network</span>
          <select value={networkId} onChange={(e) => setNetworkId(e.target.value)} required>
            <option value="">Choose a network…</option>
            {networks.map((n) => (
              <option key={n.id} value={n.id}>
                {n.name}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Name</span>
          <input value={name} onChange={(e) => setName(e.target.value)} required />
        </label>
        <label className="field">
          <span>Cadence</span>
          <select value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
            {PRESETS.map((p) => (
              <option key={p.minutes} value={p.minutes}>
                {p.label}
              </option>
            ))}
          </select>
        </label>
      </div>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <button type="submit" className="btn" disabled={submitting || networks.length === 0}>
        {submitting ? 'Creating…' : 'Create schedule'}
      </button>
    </form>
  );
}
