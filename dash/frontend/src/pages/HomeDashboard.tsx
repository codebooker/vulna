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

/** Overview: what needs attention, what changed, coverage, and whether Vulna
 *  itself is healthy, plus the single next recommended action. */
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
      <section className="card" aria-label="Overview">
        <p role="alert" className="error">
          {error}
        </p>
      </section>
    );
  }
  if (!summary) {
    return <p className="detail">Loading overview…</p>;
  }

  const na = summary.needs_attention;

  return (
    <div aria-label="Overview">
      <div className={`next-action ${summary.next_action.priority}`}>
        <span>
          <strong>Next</strong> · {summary.next_action.message}
        </span>
      </div>

      <div className="overview-grid">
        <section className="card span-2">
          <h3>Needs attention</h3>
          <ul className="priority-counts">
            {(['fix_now', 'plan', 'watch', 'informational'] as const).map((k) => (
              <li key={k} className={`pill ${k}`}>
                <span className="count">{na[k]}</span> {PRIORITY_LABEL[k]}
              </li>
            ))}
          </ul>
          {na.top.length > 0 ? (
            <ul className="top-findings">
              {na.top.map((t) => (
                <li key={t.id}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span className={`tagpill ${t.priority}`}>{PRIORITY_LABEL[t.priority]}</span>
                    <strong>{t.title}</strong>
                  </div>
                  <span className="detail">
                    {t.severity} severity · {t.confidence_label} confidence. {t.rationale}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="detail">Nothing needs attention right now.</p>
          )}
        </section>

        <section className="card">
          <h3>Vulna health</h3>
          <ul className="status-list">
            {Object.entries(summary.health).map(([k, v]) => {
              const good = v === 'ok' || v === 'connected';
              return (
                <li key={k}>
                  <span className={`dot ${good ? 'ok' : 'pending'}`} />
                  <span style={{ flex: 1 }}>{k.replace(/_/g, ' ')}</span>
                  <span className={good ? 'ok' : 'pending'}>{v}</span>
                </li>
              );
            })}
          </ul>
        </section>

        <section className="card">
          <h3>Recently changed</h3>
          <p className="detail" style={{ marginTop: '-0.3rem', marginBottom: '0.7rem' }}>
            {summary.changed_recently.total} change(s) in the last{' '}
            {summary.changed_recently.window_days} days.
          </p>
          <ul className="status-list">
            {summary.changed_recently.recent.slice(0, 5).map((c, i) => (
              <li key={i}>
                <span className="dot pending" />
                <span>
                  <span className="mono" style={{ color: 'var(--muted)' }}>
                    {c.event_type.replace(/_/g, ' ')}
                  </span>{' '}
                  {c.summary}
                </span>
              </li>
            ))}
            {summary.changed_recently.recent.length === 0 && (
              <li className="detail">No recent changes.</li>
            )}
          </ul>
        </section>

        <section className="card span-2">
          <h3>Coverage</h3>
          <div className="coverage-row">
            <div className="stat">
              <span className="stat-value">{summary.unassessed.stale_assets}</span>
              <span className="stat-label">systems not assessed recently</span>
            </div>
            <div className="stat">
              <span className="stat-value">{summary.unassessed.approved_scopes}</span>
              <span className="stat-label">approved scopes</span>
            </div>
            <div className="stat">
              <span className="stat-value">{summary.unassessed.completed_scans}</span>
              <span className="stat-label">completed scans</span>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
