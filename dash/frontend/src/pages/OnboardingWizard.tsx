import { useCallback, useEffect, useState } from 'react';
import { Check, Circle, Download, Rocket } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { cn } from '../lib/utils';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { Field, Input, Select } from '../components/ui/input';
import { Code, Progress } from '../components/ui/misc';
import { EmptyState, InlineError } from '../components/ui/states';
import type {
  CompleteStepPayload,
  OnboardingState,
  ProfilePlan,
  ScanPreset,
  ScanSummary,
  ScopePreview,
} from '../types/onboarding';

const STEP_LABELS: Record<string, string> = {
  admin: 'Welcome',
  profile_plan: 'Profile plan',
  recovery_codes: 'Recovery codes',
  health: 'System health',
  site: 'Name your site',
  scout: 'Local Scout',
  network: 'Detected networks',
  scope: 'Approve a scope',
  preset: 'Choose a check',
  launch: 'First assessment',
  results: 'Results',
};
const STEP_ORDER = Object.keys(STEP_LABELS);

const detail = 'text-[13px] leading-relaxed text-muted';

/** Guided first-run wizard. Resumes from the server-side step, so refreshing or
 *  reopening the browser never loses progress or duplicates work. */
export function OnboardingWizard({ onFinished }: { onFinished: () => void }) {
  const { token } = useAuth();
  const [state, setState] = useState<OnboardingState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [preset, setPreset] = useState(
    () => window.sessionStorage.getItem('vulna.onboarding.preset') ?? 'standard',
  );

  const load = useCallback(async () => {
    if (!token) return;
    try {
      setState(await api.onboardingState(token));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load setup state.');
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const advance = useCallback(
    async (payload: CompleteStepPayload) => {
      if (!token) return;
      setBusy(true);
      setError(null);
      try {
        const next = await api.completeOnboardingStep(token, payload);
        setState(next);
        if (next.completed_at) onFinished();
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Could not save progress.');
      } finally {
        setBusy(false);
      }
    },
    [token, onFinished],
  );

  const dismiss = useCallback(async () => {
    if (!token) return;
    await api.dismissOnboarding(token);
    onFinished();
  }, [token, onFinished]);

  if (!token || !state) return null;

  const step = state.current_step;
  const stepIndex = STEP_ORDER.indexOf(step);
  const doneCount = state.completed_steps.length;

  return (
    <Card className="p-5">
      <div className="mb-4 flex items-start justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-[15px] font-semibold text-text">
            <Rocket size={16} className="text-accent" aria-hidden /> Set up Vulna
          </h2>
          <p className="mt-0.5 text-xs text-muted">
            Step {Math.max(stepIndex, 0) + 1} of {STEP_ORDER.length} · {STEP_LABELS[step] ?? step}
          </p>
        </div>
        <Button variant="ghost" size="sm" onClick={() => void dismiss()}>
          Skip for now
        </Button>
      </div>

      <Progress value={doneCount} max={STEP_ORDER.length} className="mb-3" label="Setup progress" />

      <ol className="mb-5 flex flex-wrap gap-1.5">
        {STEP_ORDER.map((s, i) => {
          const isDone = state.completed_steps.includes(s);
          const isActive = i === stepIndex;
          return (
            <li
              key={s}
              aria-current={isActive ? 'step' : undefined}
              className={cn(
                'flex items-center gap-1 rounded-full px-2.5 py-1 text-[11px] font-medium',
                isDone
                  ? 'bg-ok/12 text-ok'
                  : isActive
                    ? 'bg-[var(--accent-tint)] text-accent-strong ring-1 ring-accent/30'
                    : 'bg-surface-2 text-faint',
              )}
            >
              {isDone ? (
                <Check size={11} aria-hidden />
              ) : (
                <Circle size={9} aria-hidden className={isActive ? 'fill-current' : ''} />
              )}
              {STEP_LABELS[s]}
            </li>
          );
        })}
      </ol>

      {error && <InlineError message={error} className="mb-3" />}

      <div className="min-h-[8rem]">
        {step === 'admin' && (
          <WelcomeStep busy={busy} onNext={() => void advance({ step: 'admin' })} />
        )}
        {step === 'profile_plan' && (
          <ProfilePlanStep
            token={token}
            busy={busy}
            onNext={() => void advance({ step: 'profile_plan' })}
          />
        )}
        {step === 'recovery_codes' && (
          <RecoveryStep
            token={token}
            busy={busy}
            onNext={() => void advance({ step: 'recovery_codes' })}
          />
        )}
        {step === 'health' && (
          <HealthStep token={token} onNext={() => void advance({ step: 'health' })} />
        )}
        {step === 'site' && (
          <SiteStep
            token={token}
            busy={busy}
            onNext={(siteId) => void advance({ step: 'site', site_id: siteId })}
          />
        )}
        {step === 'scout' && (
          <ScoutStep token={token} onNext={() => void advance({ step: 'scout' })} />
        )}
        {step === 'network' && (
          <NetworkStep token={token} onNext={() => void advance({ step: 'network' })} />
        )}
        {step === 'scope' && (
          <ScopeStep
            token={token}
            siteId={state.site_id}
            onApproved={(scopeId, demo) =>
              void advance({ step: 'scope', scope_id: scopeId, demo_used: demo })
            }
          />
        )}
        {step === 'preset' && (
          <PresetStep
            token={token}
            selected={preset}
            onNext={(value) => {
              setPreset(value);
              window.sessionStorage.setItem('vulna.onboarding.preset', value);
              void advance({ step: 'preset' });
            }}
          />
        )}
        {step === 'launch' && (
          <LaunchStep
            token={token}
            scopeId={state.scope_id}
            preset={preset}
            onLaunched={(jobId) => void advance({ step: 'launch', first_job_id: jobId })}
          />
        )}
        {step === 'results' && <ResultsStep onDone={() => void advance({ step: 'results' })} />}
      </div>
    </Card>
  );
}

function StatusDot({ ok }: { ok: boolean }) {
  return (
    <span
      className={cn('inline-block h-2 w-2 shrink-0 rounded-full', ok ? 'bg-ok' : 'bg-warn')}
      aria-hidden
    />
  );
}

function WelcomeStep({ busy, onNext }: { busy: boolean; onNext: () => void }) {
  return (
    <div className="flex flex-col items-start gap-4">
      <p className={detail}>
        This short setup gets you from here to a safe first assessment. Nothing is scanned until you
        explicitly approve a target range. You can leave and come back anytime.
      </p>
      <Button variant="primary" disabled={busy} onClick={onNext}>
        Get started
      </Button>
    </div>
  );
}

function ProfilePlanStep({
  token,
  busy,
  onNext,
}: {
  token: string;
  busy: boolean;
  onNext: () => void;
}) {
  const [plan, setPlan] = useState<ProfilePlan | null>(null);
  const [answers, setAnswers] = useState<Record<string, unknown>>({});
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void api
      .profilePlan(token)
      .then((value) => {
        setPlan(value);
        setAnswers(value.answers);
        setSaved(value.updated_at !== null);
      })
      .catch((err) =>
        setError(err instanceof Error ? err.message : 'Could not load profile planning.'),
      );
  }, [token]);

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const value = await api.updateProfilePlan(token, answers);
      setPlan(value);
      setSaved(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save planning answers.');
    } finally {
      setSaving(false);
    }
  };

  if (!plan) return error ? <InlineError message={error} /> : <p className={detail}>Loading…</p>;

  return (
    <div className="flex flex-col items-start gap-4">
      <p className={detail}>
        Tell us about your environment. Recommendations are advisory: nothing here changes a policy,
        enables a high-impact control, or sends data off-host.
      </p>
      {error && <InlineError message={error} />}
      <div className="grid w-full gap-3 sm:grid-cols-2">
        {plan.questions.map((question) => (
          <Field key={question.key} label={question.label} htmlFor={`plan-${question.key}`}>
            {question.kind === 'boolean' || question.kind === 'select' ? (
              <Select
                id={`plan-${question.key}`}
                value={String(answers[question.key] ?? '')}
                onChange={(event) => {
                  const value =
                    question.kind === 'boolean'
                      ? event.target.value === 'true'
                      : event.target.value;
                  setAnswers((current) => ({ ...current, [question.key]: value }));
                  setSaved(false);
                }}
              >
                <option value="">Select…</option>
                {(question.kind === 'boolean' ? ['true', 'false'] : question.options).map(
                  (option) => (
                    <option key={option} value={option}>
                      {option === 'true' ? 'Yes' : option === 'false' ? 'No' : option}
                    </option>
                  ),
                )}
              </Select>
            ) : (
              <Input
                id={`plan-${question.key}`}
                type={question.kind === 'number' ? 'number' : 'text'}
                min={question.kind === 'number' ? 0 : undefined}
                value={String(answers[question.key] ?? '')}
                onChange={(event) => {
                  const value =
                    question.kind === 'number' ? Number(event.target.value) : event.target.value;
                  setAnswers((current) => ({ ...current, [question.key]: value }));
                  setSaved(false);
                }}
              />
            )}
          </Field>
        ))}
      </div>
      {!saved ? (
        <Button variant="primary" loading={saving} onClick={() => void save()}>
          Show recommendations
        </Button>
      ) : (
        <>
          <ul className="flex w-full flex-col gap-2">
            {plan.recommendations.map((recommendation) => (
              <li
                key={`${recommendation.capability}-${recommendation.status}`}
                className="rounded-lg border border-border px-3 py-2.5"
              >
                <span className="flex items-center gap-2 text-[13px] font-medium text-text">
                  {recommendation.capability}
                  <Badge tone={recommendation.status === 'available' ? 'ok' : 'neutral'}>
                    {recommendation.status}
                  </Badge>
                </span>
                <p className="mt-1 text-xs text-muted">{recommendation.reason}</p>
              </li>
            ))}
          </ul>
          <Button variant="primary" disabled={busy} onClick={onNext}>
            Continue
          </Button>
        </>
      )}
    </div>
  );
}

function RecoveryStep({
  token,
  busy,
  onNext,
}: {
  token: string;
  busy: boolean;
  onNext: () => void;
}) {
  const [codes, setCodes] = useState<string[] | null>(null);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const generate = async () => {
    setError(null);
    try {
      const res = await api.generateRecoveryCodes(token);
      setCodes(res.codes);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not generate codes.');
    }
  };

  const download = () => {
    if (!codes) return;
    const blob = new Blob([codes.join('\n') + '\n'], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'vulna-recovery-codes.txt';
    a.click();
    URL.revokeObjectURL(url);
    setSaved(true);
  };

  return (
    <div className="flex flex-col items-start gap-4">
      <p className={detail}>
        Recovery codes let you regain access if you lose your password. Each code works once. Store
        them somewhere safe — they are shown only now.
      </p>
      {error && <InlineError message={error} />}
      {!codes ? (
        <Button variant="primary" onClick={() => void generate()}>
          Generate recovery codes
        </Button>
      ) : (
        <>
          <ul className="grid w-full max-w-md grid-cols-2 gap-1.5 rounded-lg border border-border bg-surface-2/60 p-3">
            {codes.map((c) => (
              <li key={c}>
                <Code>{c}</Code>
              </li>
            ))}
          </ul>
          <div className="flex flex-wrap items-center gap-3">
            <Button variant="outline" size="sm" onClick={download}>
              <Download size={13} aria-hidden /> Download
            </Button>
            <label className="flex items-center gap-2 text-[13px] text-text">
              <input
                type="checkbox"
                checked={saved}
                onChange={(e) => setSaved(e.target.checked)}
                className="accent-[var(--accent)]"
              />
              I saved these codes
            </label>
          </div>
          <Button variant="primary" disabled={!saved || busy} onClick={onNext}>
            Continue
          </Button>
        </>
      )}
    </div>
  );
}

function HealthStep({ token, onNext }: { token: string; onNext: () => void }) {
  const [health, setHealth] = useState<Record<string, string> | null>(null);
  useEffect(() => {
    void api
      .componentHealth(token)
      .then((h) => setHealth(h as unknown as Record<string, string>))
      .catch(() => setHealth(null));
  }, [token]);
  return (
    <div className="flex flex-col items-start gap-4">
      <p className={detail}>A quick check that the core components are healthy.</p>
      {health ? (
        <ul className="flex w-full max-w-md flex-col gap-1.5">
          {Object.entries(health).map(([k, v]) => (
            <li
              key={k}
              className="flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-[13px]"
            >
              <StatusDot ok={v === 'ok' || v === 'connected'} />
              <span className="text-text">{k.replace(/_/g, ' ')}</span>
              <span className="ml-auto text-xs text-muted">{v}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className={detail}>Checking…</p>
      )}
      <Button variant="primary" onClick={onNext}>
        Continue
      </Button>
    </div>
  );
}

function SiteStep({
  token,
  busy,
  onNext,
}: {
  token: string;
  busy: boolean;
  onNext: (siteId: string) => void;
}) {
  const [name, setName] = useState('Local Site');
  const [existingId, setExistingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void api.listSites(token).then((page) => {
      if (page.items.length > 0) {
        setExistingId(page.items[0].id);
        setName(page.items[0].name);
      }
    });
  }, [token]);

  const submit = async () => {
    setError(null);
    try {
      if (existingId) {
        onNext(existingId);
        return;
      }
      const code =
        name
          .trim()
          .toUpperCase()
          .replace(/[^A-Z0-9]+/g, '-')
          .slice(0, 16) || 'SITE';
      const site = await api.createSite(token, { name: name.trim(), code });
      onNext(site.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save the site.');
    }
  };

  return (
    <div className="flex flex-col items-start gap-4">
      <p className={detail}>
        A “site” is a location you assess (your home lab, an office, a cloud VPC). You can add more
        later.
      </p>
      {error && <InlineError message={error} />}
      <Field label="Site name" htmlFor="ob-site" className="w-full max-w-sm">
        <Input id="ob-site" value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      <Button variant="primary" disabled={busy} onClick={() => void submit()}>
        {existingId ? 'Use this site' : 'Create site'}
      </Button>
    </div>
  );
}

function ScoutStep({ token, onNext }: { token: string; onNext: () => void }) {
  const [status, setStatus] = useState<string>('checking');
  const check = useCallback(() => {
    setStatus('checking');
    void api
      .componentHealth(token)
      .then((h) => setStatus(h.local_scout))
      .catch(() => setStatus('unknown'));
  }, [token]);
  useEffect(() => check(), [check]);
  const connected = status === 'connected' || status === 'ok';
  return (
    <div className="flex flex-col items-start gap-4">
      <p className={detail}>
        Your local Scout is the component that performs the assessment. It authenticates with a
        client certificate and only runs signed jobs within approved scopes.
      </p>
      <div className="flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-[13px]">
        <StatusDot ok={connected} />
        <span className="text-text">Local Scout</span>
        <Badge tone={connected ? 'ok' : 'neutral'}>{status}</Badge>
      </div>
      {!connected && (
        <p className={detail}>
          Install and approve a Scout, then wait for it to connect. Setup cannot launch a scan
          through an offline appliance.
        </p>
      )}
      <div className="flex gap-2">
        <Button variant="outline" onClick={check}>
          Check again
        </Button>
        <Button variant="primary" disabled={!connected} onClick={onNext}>
          Continue
        </Button>
      </div>
    </div>
  );
}

function NetworkStep({ token, onNext }: { token: string; onNext: () => void }) {
  const [candidates, setCandidates] = useState<string[]>([]);
  const [note, setNote] = useState('');
  useEffect(() => {
    void api.networkCandidates(token).then((c) => {
      setCandidates(c.candidates);
      setNote(c.note);
    });
  }, [token]);
  return (
    <div className="flex flex-col items-start gap-4">
      <p className={detail}>
        These private ranges were detected on the Scout’s host. They are{' '}
        <strong className="text-text">suggestions only</strong> — nothing here is approved or
        scanned.
      </p>
      {candidates.length > 0 ? (
        <div className="flex flex-wrap gap-1.5">
          {candidates.map((c) => (
            <Code key={c}>{c}</Code>
          ))}
        </div>
      ) : (
        <p className={detail}>No ranges detected yet (or the Scout is still connecting).</p>
      )}
      {note && <p className="text-xs text-faint">{note}</p>}
      <Button variant="primary" onClick={onNext}>
        Continue
      </Button>
    </div>
  );
}

function ScopeStep({
  token,
  siteId,
  onApproved,
}: {
  token: string;
  siteId: string | null;
  onApproved: (scopeId: string, demo: boolean) => void;
}) {
  const [cidr, setCidr] = useState('');
  const [demo, setDemo] = useState(false);
  const [preview, setPreview] = useState<ScopePreview | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const chooseDemo = async () => {
    const target = await api.demoTarget(token);
    setCidr(target.cidr);
    setDemo(true);
    setPreview(null);
    setError(null);
  };

  const runPreview = async () => {
    setError(null);
    setConfirmed(false);
    try {
      setPreview(await api.scopePreview(token, cidr));
    } catch (err) {
      setPreview(null);
      setError(err instanceof ApiError ? err.message : 'Invalid range.');
    }
  };

  const approve = async () => {
    if (!siteId) {
      setError('No site selected yet.');
      return;
    }
    setError(null);
    try {
      const scope = await api.createScope(token, {
        site_id: siteId,
        name: demo ? 'Demo (loopback)' : `Scope ${cidr}`,
        cidr,
      });
      onApproved(scope.id, demo);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not approve the scope.');
    }
  };

  const canApprove = preview !== null && (!preview.requires_confirmation || confirmed);

  return (
    <div className="flex flex-col items-start gap-3">
      <p className={detail}>
        Approve exactly what Vulna may assess. Only private ranges are allowed by default;{' '}
        <Code>0.0.0.0/0</Code> and public space are rejected. Not sure? Try the isolated demo.
      </p>
      {error && <InlineError message={error} />}
      <div className="flex w-full max-w-xl flex-wrap items-end gap-2">
        <Field label="Target range (CIDR)" htmlFor="ob-cidr" className="min-w-[14rem] flex-1">
          <Input
            id="ob-cidr"
            value={cidr}
            placeholder="e.g. 192.168.1.0/24"
            onChange={(e) => {
              setCidr(e.target.value);
              setDemo(false);
              setPreview(null);
            }}
          />
        </Field>
        <Button variant="outline" onClick={() => void chooseDemo()}>
          Use demo target
        </Button>
        <Button variant="secondary" disabled={!cidr} onClick={() => void runPreview()}>
          Preview
        </Button>
      </div>

      {preview && (
        <div className="w-full max-w-xl rounded-lg border border-border bg-surface-2/60 p-3.5">
          <p className="text-[13px] text-text">
            <Code>{preview.cidr}</Code> — about <strong>{preview.host_estimate}</strong> hosts (
            {preview.is_private ? 'private' : 'public'}).
          </p>
          {preview.warnings.map((w) => (
            <p key={w} className="mt-1.5 text-xs text-warn">
              ⚠ {w}
            </p>
          ))}
          {preview.requires_confirmation && (
            <label className="mt-2.5 flex items-center gap-2 text-[13px] text-text">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
                className="accent-[var(--accent)]"
              />
              I understand and want to approve this range.
            </label>
          )}
          <Button
            variant="primary"
            className="mt-3"
            disabled={!canApprove}
            onClick={() => void approve()}
          >
            Approve scope
          </Button>
        </div>
      )}
    </div>
  );
}

function PresetStep({
  token,
  selected,
  onNext,
}: {
  token: string;
  selected: string;
  onNext: (preset: string) => void;
}) {
  const [presets, setPresets] = useState<ScanPreset[]>([]);
  const [selection, setSelection] = useState(selected);
  useEffect(() => {
    void api.scanPresets(token).then((r) => setPresets(r.presets));
  }, [token]);
  return (
    <div className="flex flex-col items-start gap-4">
      <p className={detail}>Choose what kind of check to run. The safe default is recommended.</p>
      <div className="grid w-full grid-cols-1 gap-2.5 sm:grid-cols-2">
        {presets.map((p) => (
          <button
            key={p.key}
            type="button"
            aria-pressed={selection === p.key}
            onClick={() => setSelection(p.key)}
            className={cn(
              'rounded-lg border p-3.5 text-left transition-colors',
              selection === p.key
                ? 'border-accent bg-[var(--accent-tint)]'
                : 'border-border hover:bg-surface-2',
            )}
          >
            <p className="text-[13px] font-semibold text-text">{p.name}</p>
            <p className={cn(detail, 'mt-0.5')}>{p.description}</p>
            <ul className="mt-2 flex flex-wrap gap-1">
              {p.checks.map((c) => (
                <li key={c}>
                  <Badge tone="neutral">{c}</Badge>
                </li>
              ))}
            </ul>
            <p className="mt-2 text-xs text-faint">
              Resource use: {p.resource_class} · Duration: {p.duration_class}
            </p>
          </button>
        ))}
      </div>
      <Button variant="primary" disabled={!selection} onClick={() => onNext(selection)}>
        Use {presets.find((item) => item.key === selection)?.name ?? 'selected check'}
      </Button>
    </div>
  );
}

function LaunchStep({
  token,
  scopeId,
  preset,
  onLaunched,
}: {
  token: string;
  scopeId: string | null;
  preset: string;
  onLaunched: (jobId: string) => void;
}) {
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [target, setTarget] = useState<{
    cidr: string;
    networkId: string;
    probeId: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [launching, setLaunching] = useState(false);

  useEffect(() => {
    void (async () => {
      try {
        const [scopes, networks, probes] = await Promise.all([
          api.listScopes(token),
          api.listNetworks(token),
          api.listProbes(token),
        ]);
        const scope = scopes.items.find((item) => item.id === scopeId);
        if (!scope) throw new Error('The approved onboarding scope could not be found.');
        const network = networks.find((item) => item.id === scope.network_id);
        if (!network) throw new Error('The approved scope is not attached to a network.');
        const binding = network.scouts.find((item) => item.is_primary);
        const probe = probes.items.find(
          (item) => item.id === binding?.probe_id && item.status === 'enrolled',
        );
        if (!probe) {
          throw new Error('The selected network has no enrolled primary Scout.');
        }
        setTarget({ cidr: scope.cidr, networkId: network.id, probeId: probe.id });
        setSummary(await api.scanSummary(token, preset, [scope.cidr]));
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Could not build the summary.');
      }
    })();
  }, [token, scopeId, preset]);

  const launch = async () => {
    if (!target) return;
    setLaunching(true);
    setError(null);
    try {
      const job = await api.createJob(
        token,
        target.probeId,
        [target.cidr],
        target.networkId,
        preset,
      );
      onLaunched(job.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not launch the assessment.');
    } finally {
      setLaunching(false);
    }
  };

  return (
    <div className="flex flex-col items-start gap-4">
      <p className="text-[13px] font-semibold text-text">Before you launch</p>
      {error && <InlineError message={error} />}
      {summary ? (
        <>
          <ul className="flex w-full max-w-xl flex-col gap-1.5 rounded-lg border border-border bg-surface-2/60 p-3.5 text-[13px] text-text">
            <li>
              <span className="text-muted">Targets:</span> {summary.targets.join(', ')}
            </li>
            <li>
              <span className="text-muted">About</span> {summary.host_estimate}{' '}
              <span className="text-muted">hosts</span>
            </li>
            <li>
              <span className="text-muted">Checks:</span> {summary.checks.join('; ')}
            </li>
            <li>
              <span className="text-muted">Intrusive:</span> {summary.intrusive ? 'yes' : 'no'} ·
              Credentials: no · Active web: no
            </li>
            <li>
              <span className="text-muted">Resource use:</span> {summary.resource_class} · Duration:{' '}
              {summary.duration_class}
            </li>
            <li className="text-muted">{summary.data_retention}</li>
          </ul>
          <Button
            variant="primary"
            loading={launching}
            disabled={launching}
            onClick={() => void launch()}
          >
            {launching ? 'Launching…' : 'Launch assessment'}
          </Button>
        </>
      ) : (
        <p className={detail}>Preparing summary…</p>
      )}
    </div>
  );
}

function ResultsStep({ onDone }: { onDone: () => void }) {
  return (
    <div className="flex flex-col items-start gap-4">
      <EmptyState
        compact
        icon={Rocket}
        title="Your first assessment is running"
        description="As the Scout works, assets (hosts) and services (open ports) appear, then findings. Each finding shows what it is, how confident Vulna is, its priority, how to remediate it, and how to verify the fix. Generate a report anytime from Reports."
      />
      <Button variant="primary" onClick={onDone}>
        Finish setup
      </Button>
    </div>
  );
}
