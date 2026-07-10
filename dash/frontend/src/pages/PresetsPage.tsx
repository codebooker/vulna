import { useCallback, useEffect, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import type { Preset, PresetPreview } from '../types/presets';

/** Browse the built-in scan presets and preview exactly which stages a preset
 *  will run — and, for anything skipped, why. Presets are convenience over the
 *  same signed-job controls; intrusive checks are never inside a preset. */
export function PresetsPage() {
  const { token } = useAuth();
  const [presets, setPresets] = useState<Preset[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [preview, setPreview] = useState<PresetPreview | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!token) return;
    try {
      const res = await api.listPresets(token);
      setPresets(res.presets);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load presets.');
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
    try {
      setPreview(await api.previewPreset(token, key, 256));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to preview preset.');
    }
  };

  return (
    <div className="card">
      <h2>Scan presets</h2>
      <p className="detail">
        Pick an outcome, not scanner flags. Every preset is non-intrusive by default; a preview
        shows exactly which stages run and explains anything skipped.
      </p>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <div className="preset-grid">
        {presets.map((p) => (
          <button
            key={p.key}
            type="button"
            className={`preset-card${selected === p.key ? ' active' : ''}`}
            onClick={() => void choose(p.key)}
          >
            <strong>{p.name}</strong>
            <span className="detail">{p.use_case}</span>
            <span className="tag">
              {p.workload_class} · v{p.version}
            </span>
          </button>
        ))}
      </div>

      {preview && (
        <div className="preview">
          <h3>{presets.find((p) => p.key === preview.preset)?.name}</h3>
          {preview.blocked && (
            <p className="warn">
              ⚠ This preset needs a scanner that is not installed. Install it, or enable downgrade,
              before running.
            </p>
          )}
          <p className="detail">
            Estimate: {preview.estimate.workload_class} workload, {preview.estimate.duration_range}{' '}
            (~{preview.estimate.size_class} scope). Suggested rate{' '}
            {preview.tuning.packets_per_second} pps, concurrency {preview.tuning.concurrency}.
          </p>
          <p>
            <strong>Stages that will run:</strong>
          </p>
          <ul className="status-list">
            {preview.stages_to_run.map((s) => (
              <li key={s.key}>
                <span className="ok">{s.classification}</span> {s.label} <code>({s.scanner})</code>
              </li>
            ))}
          </ul>
          {preview.skipped.length > 0 && (
            <>
              <p>
                <strong>Why some stages are skipped:</strong>
              </p>
              <ul className="status-list">
                {preview.skipped.map((s) => (
                  <li key={s.stage}>
                    <span className="pending">skipped</span> {s.reason}
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </div>
  );
}
