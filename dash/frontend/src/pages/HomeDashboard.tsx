import { useCallback, useEffect, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import type { DashboardSummary } from '../types/dashboard';

const PRIORITY_LABEL: Record<string, string> = {
  fix_now: 'Fix now',
  plan: 'Plan a fix',
  watch: 'Watch',
  informational: 'Informational',
};

/** Home dashboard: what needs attention, what changed, what wasn't assessed,
 *  whether Vulna is healthy, and the single next recommended action. */
export function HomeDashboard() {
  const { token } = useAuth();
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!token) return;
    try {
      setSummary(await api.dashboardSummary(token));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load the dashboard.');
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  if (error) {
    return (
      <section className="card" aria-label="Home">
        <h2>Home</h2>
        <p role="alert" className="error">
          {error}
        </p>
      </section>
    );
  }
  if (!summary) return null;

  const na = summary.needs_attention;

  return (
    <section className="card" aria-label="Home dashboard">
      <h2>Home</h2>

      <div className={`next-action ${summary.next_action.priority}`}>
        <strong>Next:</strong> {summary.next_action.message}
      </div>

      <div className="dash-grid">
        <div>
          <h3>Needs attention</h3>
          <ul className="priority-counts">
            {(['fix_now', 'plan', 'watch', 'informational'] as const).map((k) => (
              <li key={k} className={`pill ${k}`}>
                <span className="count">{na[k]}</span> {PRIORITY_LABEL[k]}
              </li>
            ))}
          </ul>
          {na.top.length > 0 && (
            <ul className="top-findings">
              {na.top.map((t) => (
                <li key={t.id}>
                  <span className={`tagpill ${t.priority}`}>{PRIORITY_LABEL[t.priority]}</span>{' '}
                  {t.title}
                  <span className="detail">
                    {' '}
                    — {t.severity}, {t.confidence_label} confidence. {t.rationale}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div>
          <h3>Recently changed</h3>
          <p className="detail">
            {summary.changed_recently.total} change(s) in the last{' '}
            {summary.changed_recently.window_days} days.
          </p>
          <ul className="status-list">
            {summary.changed_recently.recent.slice(0, 5).map((c, i) => (
              <li key={i}>
                <span className="pending">{c.event_type.replace(/_/g, ' ')}</span> {c.summary}
              </li>
            ))}
          </ul>
        </div>

        <div>
          <h3>Coverage</h3>
          <ul className="status-list">
            <li>{summary.unassessed.stale_assets} system(s) not assessed recently</li>
            <li>{summary.unassessed.approved_scopes} approved scope(s)</li>
            <li>{summary.unassessed.completed_scans} completed scan(s)</li>
          </ul>
        </div>

        <div>
          <h3>Vulna health</h3>
          <ul className="status-list">
            {Object.entries(summary.health).map(([k, v]) => (
              <li key={k}>
                <span className={v === 'ok' || v === 'connected' ? 'ok' : 'pending'}>{v}</span>{' '}
                {k.replace(/_/g, ' ')}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
