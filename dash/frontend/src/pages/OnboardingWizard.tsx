import { useCallback, useEffect, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import type {
  CompleteStepPayload,
  OnboardingState,
  ScanPreset,
  ScanSummary,
  ScopePreview,
} from '../types/onboarding';

const STEP_LABELS: Record<string, string> = {
  admin: 'Welcome',
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

/** Guided first-run wizard. Resumes from the server-side step, so refreshing or
 *  reopening the browser never loses progress or duplicates work. */
export function OnboardingWizard({ onFinished }: { onFinished: () => void }) {
  const { token } = useAuth();
  const [state, setState] = useState<OnboardingState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

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

  return (
    <div className="card wizard">
      <div className="wizard-head">
        <h2>Set up Vulna</h2>
        <button type="button" className="btn ghost" onClick={() => void dismiss()}>
          Skip for now
        </button>
      </div>
      <ol className="wizard-steps">
        {STEP_ORDER.map((s, i) => (
          <li
            key={s}
            className={
              state.completed_steps.includes(s) ? 'done' : i === stepIndex ? 'active' : 'todo'
            }
          >
            {STEP_LABELS[s]}
          </li>
        ))}
      </ol>

      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}

      <div className="wizard-body">
        {step === 'admin' && (
          <WelcomeStep busy={busy} onNext={() => void advance({ step: 'admin' })} />
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
          <PresetStep token={token} onNext={() => void advance({ step: 'preset' })} />
        )}
        {step === 'launch' && (
          <LaunchStep
            token={token}
            scopeId={state.scope_id}
            onLaunched={(jobId) => void advance({ step: 'launch', first_job_id: jobId })}
          />
        )}
        {step === 'results' && <ResultsStep onDone={() => void advance({ step: 'results' })} />}
      </div>
    </div>
  );
}

function WelcomeStep({ busy, onNext }: { busy: boolean; onNext: () => void }) {
  return (
    <div>
      <p className="detail">
        This short setup gets you from here to a safe first assessment. Nothing is scanned until you
        explicitly approve a target range. You can leave and come back anytime.
      </p>
      <button type="button" className="btn" disabled={busy} onClick={onNext}>
        Get started
      </button>
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
    <div>
      <p className="detail">
        Recovery codes let you regain access if you lose your password. Each code works once. Store
        them somewhere safe — they are shown only now.
      </p>
      {error && <p className="error">{error}</p>}
      {!codes ? (
        <button type="button" className="btn" onClick={() => void generate()}>
          Generate recovery codes
        </button>
      ) : (
        <>
          <ul className="codes">
            {codes.map((c) => (
              <li key={c}>
                <code>{c}</code>
              </li>
            ))}
          </ul>
          <div className="row">
            <button type="button" className="btn ghost" onClick={download}>
              Download
            </button>
            <label className="inline">
              <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />{' '}
              I saved these codes
            </label>
          </div>
          <button type="button" className="btn" disabled={!saved || busy} onClick={onNext}>
            Continue
          </button>
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
    <div>
      <p className="detail">A quick check that the core components are healthy.</p>
      {health ? (
        <ul className="status-list">
          {Object.entries(health).map(([k, v]) => (
            <li key={k}>
              <span className={v === 'ok' || v === 'connected' ? 'ok' : 'pending'}>{v}</span>{' '}
              {k.replace(/_/g, ' ')}
            </li>
          ))}
        </ul>
      ) : (
        <p className="detail">Checking…</p>
      )}
      <button type="button" className="btn" onClick={onNext}>
        Continue
      </button>
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
    <div>
      <p className="detail">
        A “site” is a location you assess (your home lab, an office, a cloud VPC). You can add more
        later.
      </p>
      {error && <p className="error">{error}</p>}
      <label className="field">
        Site name
        <input value={name} onChange={(e) => setName(e.target.value)} />
      </label>
      <button type="button" className="btn" disabled={busy} onClick={() => void submit()}>
        {existingId ? 'Use this site' : 'Create site'}
      </button>
    </div>
  );
}

function ScoutStep({ token, onNext }: { token: string; onNext: () => void }) {
  const [status, setStatus] = useState<string>('checking');
  useEffect(() => {
    void api
      .componentHealth(token)
      .then((h) => setStatus(h.local_scout))
      .catch(() => setStatus('unknown'));
  }, [token]);
  return (
    <div>
      <p className="detail">
        Your local Scout is the component that performs the assessment. It authenticates with a
        client certificate and only runs signed jobs within approved scopes.
      </p>
      <p>
        Local Scout: <span className={status === 'connected' ? 'ok' : 'pending'}>{status}</span>
      </p>
      <button type="button" className="btn" onClick={onNext}>
        Continue
      </button>
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
    <div>
      <p className="detail">
        These private ranges were detected on the Scout’s host. They are{' '}
        <strong>suggestions only</strong> — nothing here is approved or scanned.
      </p>
      {candidates.length > 0 ? (
        <ul className="codes">
          {candidates.map((c) => (
            <li key={c}>
              <code>{c}</code>
            </li>
          ))}
        </ul>
      ) : (
        <p className="detail">No ranges detected yet (or the Scout is still connecting).</p>
      )}
      <p className="detail">{note}</p>
      <button type="button" className="btn" onClick={onNext}>
        Continue
      </button>
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
    <div>
      <p className="detail">
        Approve exactly what Vulna may assess. Only private ranges are allowed by default;{' '}
        <code>0.0.0.0/0</code> and public space are rejected. Not sure? Try the isolated demo.
      </p>
      {error && <p className="error">{error}</p>}
      <div className="row">
        <label className="field">
          Target range (CIDR)
          <input
            value={cidr}
            placeholder="e.g. 192.168.1.0/24"
            onChange={(e) => {
              setCidr(e.target.value);
              setDemo(false);
              setPreview(null);
            }}
          />
        </label>
        <button type="button" className="btn ghost" onClick={() => void chooseDemo()}>
          Use demo target
        </button>
      </div>
      <button
        type="button"
        className="btn ghost"
        disabled={!cidr}
        onClick={() => void runPreview()}
      >
        Preview
      </button>

      {preview && (
        <div className="preview">
          <p>
            <code>{preview.cidr}</code> — about <strong>{preview.host_estimate}</strong> hosts (
            {preview.is_private ? 'private' : 'public'}).
          </p>
          {preview.warnings.map((w) => (
            <p key={w} className="warn">
              ⚠ {w}
            </p>
          ))}
          {preview.requires_confirmation && (
            <label className="inline">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
              />{' '}
              I understand and want to approve this range.
            </label>
          )}
          <button
            type="button"
            className="btn"
            disabled={!canApprove}
            onClick={() => void approve()}
          >
            Approve scope
          </button>
        </div>
      )}
    </div>
  );
}

function PresetStep({ token, onNext }: { token: string; onNext: () => void }) {
  const [presets, setPresets] = useState<ScanPreset[]>([]);
  useEffect(() => {
    void api.scanPresets(token).then((r) => setPresets(r.presets));
  }, [token]);
  return (
    <div>
      <p className="detail">Choose what kind of check to run. The safe default is recommended.</p>
      {presets.map((p) => (
        <div key={p.key} className="preset">
          <h3>{p.name}</h3>
          <p className="detail">{p.description}</p>
          <ul>
            {p.checks.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
          <p className="detail">
            Resource use: {p.resource_class}. Duration: {p.duration_class}.
          </p>
        </div>
      ))}
      <button type="button" className="btn" onClick={onNext}>
        Use Standard Security Check
      </button>
    </div>
  );
}

function LaunchStep({
  token,
  scopeId,
  onLaunched,
}: {
  token: string;
  scopeId: string | null;
  onLaunched: (jobId: string) => void;
}) {
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [cidr, setCidr] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [launching, setLaunching] = useState(false);

  useEffect(() => {
    void (async () => {
      try {
        const scopes = await api.listScopes(token);
        const scope = scopes.items.find((s) => s.id === scopeId) ?? scopes.items[0];
        if (!scope) return;
        setCidr(scope.cidr);
        setSummary(await api.scanSummary(token, 'standard', [scope.cidr]));
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Could not build the summary.');
      }
    })();
  }, [token, scopeId]);

  const launch = async () => {
    if (!cidr) return;
    setLaunching(true);
    setError(null);
    try {
      const probes = await api.listProbes(token);
      const probe = probes.items.find((p) => p.status === 'enrolled') ?? probes.items[0];
      if (!probe) {
        setError('No enrolled Scout is available to run the assessment.');
        return;
      }
      const job = await api.createJob(token, probe.id, [cidr]);
      onLaunched(job.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not launch the assessment.');
    } finally {
      setLaunching(false);
    }
  };

  return (
    <div>
      <h3>Before you launch</h3>
      {error && <p className="error">{error}</p>}
      {summary ? (
        <>
          <ul className="status-list">
            <li>Targets: {summary.targets.join(', ')}</li>
            <li>About {summary.host_estimate} hosts</li>
            <li>Checks: {summary.checks.join('; ')}</li>
            <li>
              Intrusive: {summary.intrusive ? 'yes' : 'no'} · Credentials: no · Active web: no
            </li>
            <li>
              Resource use: {summary.resource_class} · Duration: {summary.duration_class}
            </li>
            <li>{summary.data_retention}</li>
          </ul>
          <button type="button" className="btn" disabled={launching} onClick={() => void launch()}>
            {launching ? 'Launching…' : 'Launch assessment'}
          </button>
        </>
      ) : (
        <p className="detail">Preparing summary…</p>
      )}
    </div>
  );
}

function ResultsStep({ onDone }: { onDone: () => void }) {
  return (
    <div>
      <h3>Your first assessment is running</h3>
      <p className="detail">
        As the Scout works, <strong>assets</strong> (hosts) and <strong>services</strong> (open
        ports) appear below, then <strong>findings</strong>. Each finding shows what it is, how
        confident Vulna is, its priority, how to remediate it, and how to verify the fix. Generate a
        report anytime from the Reports panel.
      </p>
      <button type="button" className="btn" onClick={onDone}>
        Finish setup
      </button>
    </div>
  );
}
