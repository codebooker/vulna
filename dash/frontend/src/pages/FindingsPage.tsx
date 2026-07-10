import { useCallback, useEffect, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import type { Finding } from '../types/finding';

const PRIORITY_LABEL: Record<string, string> = {
  fix_now: 'Fix now',
  plan: 'Plan a fix',
  watch: 'Watch',
  informational: 'Informational',
};

/** Findings review: a prioritized list plus a consistent, plain-language detail
 *  layout with one-click workflows and expandable technical evidence. */
export function FindingsPage() {
  const { token, user } = useAuth();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!token) return;
    try {
      const page = await api.listFindings(token);
      setFindings(page.items);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load findings.');
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const act = async (fn: () => Promise<unknown>) => {
    if (!token || !selected) return;
    setBusy(true);
    setError(null);
    try {
      await fn();
      const fresh = await api.getFinding(token, selected.id);
      setSelected(fresh);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed.');
    } finally {
      setBusy(false);
    }
  };

  const markFixedAndVerify = () =>
    act(async () => {
      if (!token || !selected) return;
      await api.updateFinding(token, selected.id, { status: 'ready_for_verification' });
      await api.rescanFinding(token, selected.id);
    });

  const falsePositive = () =>
    act(async () => {
      if (!token || !selected) return;
      const reason = window.prompt('Why is this a false positive?') ?? '';
      await api.updateFinding(token, selected.id, {
        status: 'false_positive',
        false_positive_reason: reason,
      });
    });

  const assignToMe = () =>
    act(async () => {
      if (!token || !selected || !user) return;
      await api.updateFinding(token, selected.id, { status: 'assigned', owner_user_id: user.id });
    });

  return (
    <section className="card" aria-label="Findings">
      <h2>Findings</h2>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {findings.length === 0 && <p className="detail">No findings yet.</p>}

      <ul className="finding-list">
        {findings.map((f) => (
          <li key={f.id}>
            <button
              type="button"
              className={`finding-row${selected?.id === f.id ? ' active' : ''}`}
              onClick={() => setSelected(f)}
            >
              <span className={`tagpill ${f.priority}`}>
                {PRIORITY_LABEL[f.priority] ?? f.priority}
              </span>{' '}
              <span className="ftitle">{f.title}</span>
              <span className="detail">
                {' '}
                {f.severity} · {f.confidence_label} confidence · {f.status}
              </span>
            </button>
          </li>
        ))}
      </ul>

      {selected && (
        <article className="finding-detail" aria-label={`Finding: ${selected.title}`}>
          <h3>{selected.title}</h3>

          <section>
            <h4>1. What Vulna observed</h4>
            <p className="detail">{selected.description ?? selected.title}</p>
          </section>
          <section>
            <h4>2. Why it matters</h4>
            <p className="detail">
              Severity {selected.severity}
              {selected.cvss_score != null && <> · CVSS {selected.cvss_score}</>}
              {selected.known_exploited && <> · known exploited (KEV)</>}
              {selected.epss_score != null && <> · EPSS {Math.round(selected.epss_score * 100)}%</>}
              . Priority: <strong>{PRIORITY_LABEL[selected.priority] ?? selected.priority}</strong>.
            </p>
          </section>
          <section>
            <h4>3. How confident Vulna is</h4>
            <p className="detail">
              {selected.confidence_label} confidence ({selected.confidence}/100).{' '}
              {selected.priority_rationale}
            </p>
          </section>
          <section>
            <h4>4. Affected system and service</h4>
            <p className="detail">
              Asset: <code>{selected.asset_id ?? '—'}</code> · Service:{' '}
              <code>{selected.service_id ?? '—'}</code>
            </p>
          </section>
          <section>
            <h4>5. Practical remediation</h4>
            <p className="detail">{selected.remediation ?? 'No specific remediation recorded.'}</p>
          </section>
          <section>
            <h4>6. How to verify the fix</h4>
            <p className="detail">
              After remediating, use <em>Mark fixed &amp; verify</em>. Vulna re-checks and only
              closes the finding when the configured verification succeeds.
            </p>
            <div className="row">
              <button
                type="button"
                className="btn"
                disabled={busy}
                onClick={() => void markFixedAndVerify()}
              >
                Mark fixed &amp; verify
              </button>
              <button
                type="button"
                className="btn ghost"
                disabled={busy}
                onClick={() => void assignToMe()}
              >
                Assign to me
              </button>
              <button
                type="button"
                className="btn ghost"
                disabled={busy}
                onClick={() => void falsePositive()}
              >
                False positive
              </button>
            </div>
          </section>
          <section>
            <h4>7. References and evidence</h4>
            {selected.references_json.length > 0 && (
              <ul className="status-list">
                {selected.references_json.map((r) => (
                  <li key={r}>
                    <code>{r}</code>
                  </li>
                ))}
              </ul>
            )}
            <details>
              <summary>Raw evidence (technical)</summary>
              <pre className="cmd">{JSON.stringify(selected.evidence_json, null, 2)}</pre>
            </details>
          </section>
        </article>
      )}
    </section>
  );
}
