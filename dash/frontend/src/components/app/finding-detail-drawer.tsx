import { useEffect, useState } from 'react';
import { ArrowLeft, ShieldAlert } from 'lucide-react';
import { api } from '../../api/client';
import { useAuth } from '../../auth/useAuth';
import { useToast } from '../../lib/toast';
import { formatWhenFull, humanize } from '../../lib/utils';
import { PriorityBadge, RiskIndicator, SeverityBadge, StatusBadge } from './badges';
import { Button } from '../ui/button';
import { Field, Textarea } from '../ui/input';
import { Code, CodeBlock, DetailRow } from '../ui/misc';
import { Drawer, Modal } from '../ui/overlay';
import { InlineError } from '../ui/states';
import { Tabs } from '../ui/tabs';
import type { Finding } from '../../types/finding';

const DETAIL_TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'assets', label: 'Affected assets' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'resolution', label: 'Resolution' },
  { id: 'references', label: 'References' },
  { id: 'activity', label: 'Activity' },
];

/** The finding-detail slider, shared by the Findings page and the Assets page so
 *  a vulnerability opens the same rich detail wherever it's clicked.
 *
 *  - `onBack` (optional) shows a back arrow in the header — used when the drawer
 *    was opened from another context (e.g. an asset) to return there.
 *  - `assetName` / `onViewAsset` render the affected asset by name and make it a
 *    link, instead of showing the raw asset id. */
export function FindingDetailDrawer({
  finding,
  onClose,
  onBack,
  onChanged,
  assetName,
  onViewAsset,
}: {
  finding: Finding | null;
  onClose: () => void;
  onBack?: () => void;
  onChanged?: () => void;
  assetName?: string | null;
  onViewAsset?: (assetId: string) => void;
}) {
  const { token, user } = useAuth();
  const { toast } = useToast();
  const [current, setCurrent] = useState<Finding | null>(finding);
  const [tab, setTab] = useState('overview');
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [fpOpen, setFpOpen] = useState(false);
  const [fpReason, setFpReason] = useState('');

  useEffect(() => {
    setCurrent(finding);
    setTab('overview');
    setActionError(null);
    setFpOpen(false);
    setFpReason('');
  }, [finding]);

  const act = async (fn: () => Promise<unknown>, success: string) => {
    if (!token || !current) return;
    setBusy(true);
    setActionError(null);
    try {
      await fn();
      const fresh = await api.getFinding(token, current.id);
      setCurrent(fresh);
      onChanged?.();
      toast('success', success);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Action failed.');
    } finally {
      setBusy(false);
    }
  };

  const markFixedAndVerify = () =>
    act(async () => {
      if (!token || !current) return;
      await api.updateFinding(token, current.id, { status: 'ready_for_verification' });
      await api.rescanFinding(token, current.id);
    }, 'Re-check queued — the finding closes once verification succeeds.');

  const assignToMe = () =>
    act(async () => {
      if (!token || !current || !user) return;
      await api.updateFinding(token, current.id, { status: 'assigned', owner_user_id: user.id });
    }, 'Finding assigned to you.');

  const submitFalsePositive = () =>
    act(async () => {
      if (!token || !current) return;
      await api.updateFinding(token, current.id, {
        status: 'false_positive',
        false_positive_reason: fpReason,
      });
      setFpOpen(false);
      setFpReason('');
    }, 'Marked as false positive.');

  return (
    <>
      <Drawer
        open={finding !== null}
        onClose={onClose}
        size="lg"
        title={
          current ? (
            <span className="flex items-center gap-2">
              {onBack && (
                <button
                  type="button"
                  onClick={onBack}
                  aria-label="Back"
                  className="-ml-1 shrink-0 rounded-md p-1 text-muted hover:bg-surface-2 hover:text-text"
                >
                  <ArrowLeft size={15} aria-hidden />
                </button>
              )}
              <ShieldAlert size={15} className="shrink-0 text-accent" aria-hidden />
              {current.title}
            </span>
          ) : (
            ''
          )
        }
        description={
          current ? `${humanize(current.severity)} severity · ${current.scanner_name}` : undefined
        }
        footer={
          current && (
            <>
              <Button variant="ghost" disabled={busy} onClick={() => void assignToMe()}>
                Assign to me
              </Button>
              <Button variant="outline" disabled={busy} onClick={() => setFpOpen(true)}>
                False positive
              </Button>
              <Button variant="primary" loading={busy} onClick={() => void markFixedAndVerify()}>
                Mark fixed &amp; verify
              </Button>
            </>
          )
        }
      >
        {current && (
          <div>
            {actionError && <InlineError message={actionError} className="mb-3" />}
            <div className="mb-3 flex flex-wrap items-center gap-1.5">
              <SeverityBadge severity={current.severity} />
              <PriorityBadge priority={current.priority} />
              <StatusBadge status={current.status} />
              {current.known_exploited && (
                <span className="rounded-md border border-sev-critical/30 bg-sev-critical/10 px-1.5 py-px text-[11px] font-semibold text-sev-critical">
                  Known exploited (KEV)
                </span>
              )}
            </div>

            <Tabs tabs={DETAIL_TABS} value={tab} onChange={setTab} className="mb-4" />

            {tab === 'overview' && (
              <div className="flex flex-col gap-4">
                <section>
                  <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">
                    What Vulna observed
                  </h3>
                  <p className="text-[13px] leading-relaxed text-text">
                    {current.description ?? current.title}
                  </p>
                </section>
                <section>
                  <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">
                    Why it matters
                  </h3>
                  <dl className="divide-y divide-border rounded-lg border border-border px-3">
                    <DetailRow label="Severity">{humanize(current.severity)}</DetailRow>
                    {current.cvss_score != null && (
                      <DetailRow label="CVSS">
                        <RiskIndicator score={current.cvss_score} />
                      </DetailRow>
                    )}
                    {current.epss_score != null && (
                      <DetailRow label="EPSS">{Math.round(current.epss_score * 100)}%</DetailRow>
                    )}
                    <DetailRow label="Priority">
                      <PriorityBadge priority={current.priority} />
                    </DetailRow>
                    <DetailRow label="Confidence">
                      {current.confidence_label} ({current.confidence}/100)
                    </DetailRow>
                  </dl>
                  <p className="mt-2 text-xs text-muted">{current.priority_rationale}</p>
                </section>
                {current.cve_ids_json.length > 0 && (
                  <section>
                    <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">
                      CVEs
                    </h3>
                    <div className="flex flex-wrap gap-1.5">
                      {current.cve_ids_json.map((cve) => (
                        <Code key={cve}>{cve}</Code>
                      ))}
                    </div>
                  </section>
                )}
              </div>
            )}

            {tab === 'assets' && (
              <dl className="divide-y divide-border rounded-lg border border-border px-3">
                <DetailRow label="Asset">
                  {current.asset_id ? (
                    onViewAsset ? (
                      <button
                        type="button"
                        onClick={() => onViewAsset(current.asset_id!)}
                        className="font-medium text-accent hover:underline"
                      >
                        {assetName ?? current.asset_id}
                      </button>
                    ) : (
                      (assetName ?? <Code>{current.asset_id}</Code>)
                    )
                  ) : (
                    '—'
                  )}
                </DetailRow>
                <DetailRow label="Service">
                  {current.service_id ? <Code>{current.service_id}</Code> : '—'}
                </DetailRow>
                <DetailRow label="Scanner">{current.scanner_name}</DetailRow>
              </dl>
            )}

            {tab === 'evidence' && (
              <div>
                <p className="mb-2 text-xs text-muted">
                  Raw technical evidence captured by the scanner.
                </p>
                <CodeBlock>{JSON.stringify(current.evidence_json, null, 2)}</CodeBlock>
              </div>
            )}

            {tab === 'resolution' && (
              <div className="flex flex-col gap-4">
                <section>
                  <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">
                    Practical remediation
                  </h3>
                  <p className="text-[13px] leading-relaxed text-text">
                    {current.remediation ?? 'No specific remediation recorded.'}
                  </p>
                </section>
                <section>
                  <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">
                    How to verify the fix
                  </h3>
                  <p className="text-[13px] leading-relaxed text-muted">
                    After remediating, use <em className="text-text">Mark fixed &amp; verify</em>.
                    Vulna re-checks and only closes the finding when the configured verification
                    succeeds.
                  </p>
                </section>
              </div>
            )}

            {tab === 'references' && (
              <div>
                {current.references_json.length === 0 ? (
                  <p className="text-xs text-muted">No references recorded.</p>
                ) : (
                  <ul className="flex flex-col gap-1.5">
                    {current.references_json.map((r) => (
                      <li key={r}>
                        <Code className="break-all">{r}</Code>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}

            {tab === 'activity' && (
              <dl className="divide-y divide-border rounded-lg border border-border px-3">
                <DetailRow label="Status">
                  <StatusBadge status={current.status} />
                </DetailRow>
                <DetailRow label="Owner">
                  {current.owner_user_id ? <Code>{current.owner_user_id}</Code> : 'Unassigned'}
                </DetailRow>
                <DetailRow label="Validation">{humanize(current.validation_status)}</DetailRow>
                <DetailRow label="Last verified">
                  {formatWhenFull(current.last_verified_at)}
                </DetailRow>
                <DetailRow label="Resolved">{formatWhenFull(current.resolved_at)}</DetailRow>
              </dl>
            )}
          </div>
        )}
      </Drawer>

      {/* False-positive reason modal (replaces window.prompt) */}
      <Modal
        open={fpOpen}
        onClose={() => setFpOpen(false)}
        title="Mark as false positive"
        description="Explain why this finding is not a real issue. The reason is stored with the finding."
        footer={
          <>
            <Button variant="ghost" onClick={() => setFpOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" loading={busy} onClick={() => void submitFalsePositive()}>
              Confirm
            </Button>
          </>
        }
      >
        <Field label="Reason" htmlFor="fp-reason">
          <Textarea
            id="fp-reason"
            value={fpReason}
            onChange={(e) => setFpReason(e.target.value)}
            placeholder="e.g. The service is not exposed beyond the management VLAN."
          />
        </Field>
      </Modal>
    </>
  );
}
