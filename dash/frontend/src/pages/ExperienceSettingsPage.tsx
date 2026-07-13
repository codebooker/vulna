import { useCallback, useEffect, useState } from 'react';
import { Eye, ShieldCheck } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { Field, Select } from '../components/ui/input';
import { InlineError } from '../components/ui/states';
import type {
  Experience,
  ExperienceChange,
  ExperiencePreview,
  ExperienceProfile,
} from '../types/experience';

const PROFILE_LABELS: Record<ExperienceProfile, string> = {
  small_business: 'Small Business',
  enterprise: 'Enterprise',
  custom: 'Custom',
};

function routeLabel(key: string) {
  return key.replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function ExperienceSettingsPage() {
  const { token, user } = useAuth();
  const [current, setCurrent] = useState<Experience | null>(null);
  const [draft, setDraft] = useState<ExperienceChange | null>(null);
  const [preview, setPreview] = useState<ExperiencePreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const isAdmin = user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    try {
      const value = await api.experience(token);
      setCurrent(value);
      setDraft({
        experience_profile: value.experience_profile,
        feature_overrides: value.feature_overrides,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load the experience profile.');
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const showPreview = async () => {
    if (!token || !draft) return;
    setBusy(true);
    setError(null);
    try {
      setPreview(await api.previewExperience(token, draft));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not preview this profile.');
    } finally {
      setBusy(false);
    }
  };

  const apply = async () => {
    if (!token || !draft) return;
    setBusy(true);
    setError(null);
    try {
      const value = await api.updateExperience(token, draft);
      setCurrent(value);
      setPreview(null);
      window.dispatchEvent(new Event('vulna-experience-changed'));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not update the profile.');
    } finally {
      setBusy(false);
    }
  };

  if (!current || !draft) return error ? <InlineError message={error} /> : <p>Loading…</p>;

  return (
    <div className="flex max-w-3xl flex-col gap-4">
      <Card className="p-5">
        <div className="mb-4 flex items-start gap-3">
          <div className="rounded-lg bg-[var(--accent-tint)] p-2 text-accent">
            <Eye size={17} aria-hidden />
          </div>
          <div>
            <h2 className="text-[15px] font-semibold text-text">Dashboard experience</h2>
            <p className="mt-1 text-xs leading-relaxed text-muted">{current.note}</p>
          </div>
        </div>

        {error && <InlineError message={error} className="mb-3" />}

        <Field label="Experience profile" htmlFor="experience-profile">
          <Select
            id="experience-profile"
            value={draft.experience_profile}
            disabled={!isAdmin}
            onChange={(event) => {
              setDraft({
                experience_profile: event.target.value as ExperienceProfile,
                feature_overrides: draft.feature_overrides,
              });
              setPreview(null);
            }}
          >
            {Object.entries(PROFILE_LABELS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </Select>
        </Field>

        {draft.experience_profile === 'custom' && (
          <fieldset className="mt-4">
            <legend className="mb-2 text-xs font-medium text-muted">Navigation visibility</legend>
            <div className="grid gap-2 sm:grid-cols-2">
              {Object.keys(current.route_visibility).map((key) => (
                <label
                  key={key}
                  className="flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-[13px] text-text"
                >
                  <input
                    type="checkbox"
                    checked={draft.feature_overrides[key] ?? true}
                    disabled={!isAdmin}
                    onChange={(event) => {
                      setDraft((value) =>
                        value
                          ? {
                              ...value,
                              feature_overrides: {
                                ...value.feature_overrides,
                                [key]: event.target.checked,
                              },
                            }
                          : value,
                      );
                      setPreview(null);
                    }}
                    className="accent-[var(--accent)]"
                  />
                  {routeLabel(key)}
                </label>
              ))}
            </div>
          </fieldset>
        )}

        {isAdmin ? (
          <Button
            className="mt-4"
            variant="primary"
            loading={busy}
            onClick={() => void showPreview()}
          >
            Preview change
          </Button>
        ) : (
          <p className="mt-4 text-xs text-muted">Only administrators can change this profile.</p>
        )}
      </Card>

      {preview && (
        <Card className="border-accent/30 p-5">
          <div className="flex items-start gap-3">
            <ShieldCheck size={18} className="mt-0.5 text-ok" aria-hidden />
            <div className="min-w-0 flex-1">
              <h3 className="text-sm font-semibold text-text">Confirm presentation change</h3>
              <p className="mt-1 text-xs leading-relaxed text-muted">
                Configuration, policies, permissions, security controls, direct authorized access,
                and background jobs are preserved.
              </p>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {preview.changed_routes.length ? (
                  preview.changed_routes.map((route) => (
                    <Badge key={route} tone="accent">
                      {routeLabel(route)}
                    </Badge>
                  ))
                ) : (
                  <Badge>No navigation changes</Badge>
                )}
              </div>
              <div className="mt-4 flex gap-2">
                <Button variant="primary" loading={busy} onClick={() => void apply()}>
                  Confirm profile
                </Button>
                <Button variant="ghost" onClick={() => setPreview(null)}>
                  Cancel
                </Button>
              </div>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
