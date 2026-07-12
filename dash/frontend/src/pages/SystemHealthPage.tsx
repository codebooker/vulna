import { useCallback, useEffect, useState } from 'react';
import { FileSearch, Wrench } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useToast } from '../lib/toast';
import { humanize } from '../lib/utils';
import { StatusBadge } from '../components/app/badges';
import { StatTile } from '../components/app/metric-card';
import { PageHeader, SectionHeader } from '../components/app/page-header';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { CodeBlock } from '../components/ui/misc';
import { ConfirmDialog } from '../components/ui/overlay';
import { CardSkeleton, InlineError } from '../components/ui/states';
import { AlertTriangle, CheckCircle2, XCircle } from 'lucide-react';
import type { DiagnosticsResult, SupportBundle, TimelineEvent } from '../types/diagnostics';

/** System Health (Vulna Doctor): per-check status with impact, data-safety,
 *  and next step, plus an event timeline and a redacted support bundle. */
export function SystemHealthPage() {
  const { token, user } = useAuth();
  const { toast } = useToast();
  const [diag, setDiag] = useState<DiagnosticsResult | null>(null);
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [bundle, setBundle] = useState<SupportBundle | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [repairOpen, setRepairOpen] = useState(false);

  const isAdmin = user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    try {
      setDiag(await api.diagnostics(token));
      setEvents((await api.diagnosticsTimeline(token)).events);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load diagnostics.');
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const previewBundle = async () => {
    if (!token) return;
    setError(null);
    try {
      setBundle(await api.supportBundle(token));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to build the support bundle.');
    }
  };

  const runRepair = async () => {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await api.repair(token, 'recreate_storage_dirs');
      await load();
      setRepairOpen(false);
      toast('success', 'Repair completed.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Repair failed.');
    } finally {
      setBusy(false);
    }
  };

  if (!diag) {
    return (
      <div aria-label="System health">
        <PageHeader
          crumbs={[{ label: 'Administration' }, { label: 'System health' }]}
          title="System health"
          description="Component and service status, with impact and next steps per check."
        />
        {error ? (
          <InlineError message={error} />
        ) : (
          <Card>
            <CardSkeleton lines={6} />
          </Card>
        )}
      </div>
    );
  }

  return (
    <div aria-label="System health">
      <PageHeader
        crumbs={[{ label: 'Administration' }, { label: 'System health' }]}
        title="System health"
        description="Component and service status, with impact and next steps per check."
        actions={
          isAdmin && (
            <>
              <Button variant="outline" onClick={() => void previewBundle()}>
                <FileSearch size={14} aria-hidden /> Preview support bundle
              </Button>
              <Button variant="outline" disabled={busy} onClick={() => setRepairOpen(true)}>
                <Wrench size={14} aria-hidden /> Repair: recreate storage dirs
              </Button>
            </>
          )
        }
      />

      {error && <InlineError message={error} className="mb-3" />}

      <div className="mb-4 grid grid-cols-3 gap-3">
        <StatTile
          label="Failing"
          value={diag.summary.fail}
          icon={XCircle}
          tone={diag.summary.fail > 0 ? 'bad' : 'default'}
        />
        <StatTile
          label="Warnings"
          value={diag.summary.warn}
          icon={AlertTriangle}
          tone={diag.summary.warn > 0 ? 'warn' : 'default'}
        />
        <StatTile label="Healthy" value={diag.summary.ok} icon={CheckCircle2} tone="ok" />
      </div>

      <Card className="mb-4 divide-y divide-border">
        {diag.checks.map((c) => (
          <div key={c.component} className="flex flex-wrap items-start gap-2.5 px-4 py-2.5">
            <StatusBadge status={c.status} />
            <div className="min-w-0 flex-1">
              <p className="text-[13px] font-medium text-text">
                {humanize(c.component)}{' '}
                <span className="font-normal text-muted">— {c.summary}</span>
              </p>
              {c.status !== 'ok' && (
                <p className="mt-0.5 text-xs text-muted">
                  Impact: {c.impact}. Data: {c.data_safety}. Next: {c.next_step}
                </p>
              )}
            </div>
          </div>
        ))}
      </Card>

      {bundle && (
        <Card className="mb-4 p-4">
          <p className="mb-2 text-[13px] text-text">
            Support bundle{' '}
            <Badge tone={bundle.secret_scan.clean ? 'ok' : 'bad'}>
              {bundle.secret_scan.clean ? 'no secrets detected' : 'SECRETS DETECTED'}
            </Badge>{' '}
            — review before sharing. Included sections:{' '}
            {bundle.manifest.map((m) => m.section).join(', ')}.
          </p>
          <details>
            <summary className="cursor-pointer text-xs font-medium text-accent-strong">
              Bundle preview (redacted)
            </summary>
            <CodeBlock className="mt-2 max-h-72 overflow-y-auto">
              {JSON.stringify(bundle.bundle, null, 2)}
            </CodeBlock>
          </details>
        </Card>
      )}

      <SectionHeader title="Recent events" />
      <Card className="divide-y divide-border">
        {events.length === 0 ? (
          <p className="px-4 py-4 text-center text-xs text-muted">No recent events.</p>
        ) : (
          events.slice(0, 8).map((e, i) => (
            <div key={i} className="flex items-center gap-2.5 px-4 py-2">
              <Badge tone="neutral">{e.kind}</Badge>
              <span className="truncate text-[13px] text-text">{e.summary}</span>
            </div>
          ))
        )}
      </Card>

      <ConfirmDialog
        open={repairOpen}
        onClose={() => setRepairOpen(false)}
        busy={busy}
        title="Run the safe repair “recreate storage dirs”?"
        body="This recreates missing storage directories. It is safe and does not delete data."
        confirmLabel="Run repair"
        onConfirm={() => void runRepair()}
      />
    </div>
  );
}
