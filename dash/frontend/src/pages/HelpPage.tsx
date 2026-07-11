import { useCallback, useEffect, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import type { DemoStatus, HelpTopic } from '../types/help';

/** Help & demo: contextual documentation links, the exposure checklist, and a
 *  safe demo mode (sample data, no scanning) that admins can toggle. */
export function HelpPage() {
  const { token, user } = useAuth();
  const [topics, setTopics] = useState<HelpTopic[]>([]);
  const [checklist, setChecklist] = useState<string[]>([]);
  const [demo, setDemo] = useState<DemoStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const isAdmin = user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    try {
      setTopics((await api.helpTopics(token)).topics);
      setChecklist((await api.exposureChecklist(token)).checklist);
      setDemo(await api.demoStatus(token));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load help.');
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const toggleDemo = async () => {
    if (!token || !demo) return;
    setBusy(true);
    setError(null);
    try {
      setDemo(demo.demo_mode ? await api.disableDemo(token) : await api.enableDemo(token));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to change demo mode.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card" aria-label="Help and demo">
      <h2>Help &amp; demo</h2>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}

      {demo && (
        <div className="preview">
          <p>
            Demo mode is <strong>{demo.demo_mode ? 'on' : 'off'}</strong>.{' '}
            {demo.demo_mode
              ? 'Sample data is loaded and real scans are blocked.'
              : 'Turn it on to explore with sample data and no scanning.'}
          </p>
          {isAdmin && (
            <button
              type="button"
              className="btn ghost"
              disabled={busy}
              onClick={() => void toggleDemo()}
            >
              {demo.demo_mode ? 'Disable demo mode' : 'Enable demo mode'}
            </button>
          )}
        </div>
      )}

      <h3>Guides</h3>
      <ul className="status-list">
        {topics.map((t) => (
          <li key={t.key}>
            <strong>{t.title}</strong> — {t.summary} <code>{t.doc}</code>
          </li>
        ))}
      </ul>

      <h3>Before exposing Vulna beyond your LAN</h3>
      <ol className="status-list">
        {checklist.map((item, i) => (
          <li key={i}>{item}</li>
        ))}
      </ol>
    </section>
  );
}
