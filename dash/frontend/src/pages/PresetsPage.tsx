import { useCallback, useEffect, useState } from 'react';
import { SlidersHorizontal } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { cn } from '../lib/utils';
import { PageHeader } from '../components/app/page-header';
import { Badge } from '../components/ui/badge';
import { Card } from '../components/ui/card';
import { Code } from '../components/ui/misc';
import { Drawer } from '../components/ui/overlay';
import { CardSkeleton, EmptyState, InlineError } from '../components/ui/states';
import type { Preset, PresetPreview } from '../types/presets';

/** Scan presets: pick an outcome, not scanner flags. Preview opens in a drawer
 *  and shows exactly which stages run and why anything is skipped. */
export function PresetsPage() {
  const { token } = useAuth();
  const [presets, setPresets] = useState<Preset[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [preview, setPreview] = useState<PresetPreview | null>(null);
  const [loading, setLoading] = useState(true);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const res = await api.listPresets(token);
      setPresets(res.presets);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load presets.');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const choose = async (key: string) => {
    if (!token) return;
    setSelected(key);
    setPreview(null);
    setError(null);
    setPreviewLoading(true);
    try {
      setPreview(await api.previewPreset(token, key, 256));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to preview preset.');
    } finally {
      setPreviewLoading(false);
    }
  };

  const selectedPreset = presets.find((p) => p.key === selected);

  return (
    <div aria-label="Scan presets">
      <PageHeader
        crumbs={[{ label: 'Management' }, { label: 'Scan presets' }]}
        title="Scan presets"
        description="Pick an outcome, not scanner flags. Every preset is non-intrusive by default; a preview shows exactly which stages run."
      />

      {error && !selected && <InlineError message={error} className="mb-3" />}

      {loading ? (
        <Card>
          <CardSkeleton lines={4} />
        </Card>
      ) : presets.length === 0 ? (
        <Card>
          <EmptyState
            icon={SlidersHorizontal}
            title="No presets available"
            description="Presets ship with the scanner pack; check System health if this list stays empty."
          />
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {presets.map((p) => (
            <button
              key={p.key}
              type="button"
              onClick={() => void choose(p.key)}
              className={cn(
                'rounded-xl border bg-surface p-4 text-left shadow-[var(--shadow-sm)] transition-colors',
                selected === p.key
                  ? 'border-accent bg-[var(--accent-tint)]'
                  : 'border-border hover:border-border-strong hover:bg-surface-2',
              )}
            >
              <p className="text-[13px] font-semibold text-text">{p.name}</p>
              <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-muted">{p.use_case}</p>
              <p className="mt-2.5 flex items-center gap-1.5">
                <Badge tone="neutral">{p.workload_class}</Badge>
                <Badge tone="neutral">v{p.version}</Badge>
              </p>
            </button>
          ))}
        </div>
      )}

      <Drawer
        open={selected !== null}
        onClose={() => {
          setSelected(null);
          setPreview(null);
        }}
        title={selectedPreset?.name ?? 'Preset preview'}
        description="Stages for a ~256-host scope"
      >
        {previewLoading && <CardSkeleton lines={5} />}
        {error && selected && <InlineError message={error} />}
        {preview && (
          <div className="flex flex-col gap-4">
            {preview.blocked && (
              <InlineError message="This preset needs a scanner that is not installed. Install it, or enable downgrade, before running." />
            )}
            {preview.capability_warning && (
              <p
                className="rounded-lg border border-warn/30 bg-warn/10 px-3 py-2 text-xs text-warn"
                role="alert"
              >
                {preview.capability_warning}
              </p>
            )}

            <div className="grid grid-cols-2 gap-2">
              <div className="rounded-lg border border-border bg-surface-2 px-3 py-2">
                <p className="text-[11px] text-muted">Workload</p>
                <p className="text-[13px] font-semibold text-text">
                  {preview.estimate.workload_class}
                </p>
              </div>
              <div className="rounded-lg border border-border bg-surface-2 px-3 py-2">
                <p className="text-[11px] text-muted">Duration</p>
                <p className="text-[13px] font-semibold text-text">
                  {preview.estimate.duration_range}
                </p>
              </div>
              <div className="rounded-lg border border-border bg-surface-2 px-3 py-2">
                <p className="text-[11px] text-muted">Suggested rate</p>
                <p className="text-[13px] font-semibold text-text">
                  {preview.tuning.packets_per_second} pps
                </p>
              </div>
              <div className="rounded-lg border border-border bg-surface-2 px-3 py-2">
                <p className="text-[11px] text-muted">Concurrency</p>
                <p className="text-[13px] font-semibold text-text">{preview.tuning.concurrency}</p>
              </div>
            </div>

            <section>
              <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
                Stages that will run
              </h3>
              <ul className="flex flex-col gap-1.5">
                {preview.stages_to_run.map((s) => (
                  <li
                    key={s.key}
                    className="flex items-center justify-between gap-2 rounded-lg border border-border px-3 py-2"
                  >
                    <span className="text-[13px] text-text">{s.label}</span>
                    <span className="flex items-center gap-1.5">
                      <Badge tone="ok">{s.classification}</Badge>
                      <Code>{s.scanner}</Code>
                    </span>
                  </li>
                ))}
              </ul>
            </section>

            {preview.skipped.length > 0 && (
              <section>
                <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
                  Why some stages are skipped
                </h3>
                <ul className="flex flex-col gap-1.5">
                  {preview.skipped.map((s) => (
                    <li key={s.stage} className="rounded-lg border border-border px-3 py-2">
                      <Badge tone="neutral" className="mb-1">
                        skipped
                      </Badge>
                      <p className="text-xs leading-relaxed text-muted">{s.reason}</p>
                    </li>
                  ))}
                </ul>
              </section>
            )}
          </div>
        )}
      </Drawer>
    </div>
  );
}
