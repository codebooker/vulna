import { useCallback, useEffect, useState } from 'react';
import { BookOpen } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useToast } from '../lib/toast';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { InlineError } from '../components/ui/states';
import type { DemoStatus, HelpTopic } from '../types/help';

/** Help & demo: documentation topics, the exposure checklist, and a safe demo
 *  mode (sample data, no scanning) that admins can toggle. */
export function HelpPage() {
  const { token, user } = useAuth();
  const { toast } = useToast();
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
      const next = demo.demo_mode ? await api.disableDemo(token) : await api.enableDemo(token);
      setDemo(next);
      toast('success', next.demo_mode ? 'Demo mode enabled.' : 'Demo mode disabled.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to change demo mode.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div aria-label="Help and demo">
      <h2 className="mb-4 text-[15px] font-semibold text-text">Help &amp; demo</h2>
      {error && <InlineError message={error} className="mb-3" />}

      {demo && (
        <Card className="mb-3 flex flex-wrap items-center justify-between gap-3 p-4">
          <div className="min-w-0">
            <p className="text-[13px] font-semibold text-text">
              Demo mode is {demo.demo_mode ? 'on' : 'off'}
            </p>
            <p className="text-xs text-muted">
              {demo.demo_mode
                ? 'Sample data is loaded and real scans are blocked.'
                : 'Turn it on to explore with sample data and no scanning.'}
            </p>
          </div>
          {isAdmin && (
            <Button variant="outline" disabled={busy} onClick={() => void toggleDemo()}>
              {demo.demo_mode ? 'Disable demo mode' : 'Enable demo mode'}
            </Button>
          )}
        </Card>
      )}

      <Card className="mb-3 p-4">
        <h3 className="mb-2 text-[13px] font-semibold text-text">Guides</h3>
        <ul className="flex flex-col gap-1">
          {topics.map((t) => (
            <li
              key={t.key}
              className="flex items-start gap-2.5 rounded-lg px-2 py-1.5 hover:bg-surface-2"
            >
              <BookOpen size={14} aria-hidden className="mt-0.5 shrink-0 text-accent" />
              <a
                className="min-w-0 flex-1 rounded-sm focus:outline-none focus:ring-2 focus:ring-[var(--ring)]"
                href={`https://github.com/codebooker/vulna/blob/main/${t.doc.replace(/^\/+/, '')}`}
                target="_blank"
                rel="noreferrer"
              >
                <span className="block text-[13px] font-medium text-text">{t.title}</span>
                <span className="block text-xs text-muted">
                  {t.summary} <span className="text-accent">Open guide ↗</span>
                </span>
              </a>
            </li>
          ))}
        </ul>
      </Card>

      <Card className="p-4">
        <h3 className="mb-2 text-[13px] font-semibold text-text">
          Before exposing Vulna beyond your LAN
        </h3>
        <ol className="flex list-decimal flex-col gap-1.5 pl-5">
          {checklist.map((item, i) => (
            <li key={i} className="text-[13px] leading-relaxed text-text">
              {item}
            </li>
          ))}
        </ol>
      </Card>
    </div>
  );
}

/** Kept for compatibility with older imports. */
export { HelpPage as default };
