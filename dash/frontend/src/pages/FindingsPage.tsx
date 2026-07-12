import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ShieldAlert } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useNav } from '../lib/nav';
import { useToast } from '../lib/toast';
import { formatWhenFull, humanize } from '../lib/utils';
import {
  normalizeSeverity,
  PriorityBadge,
  RiskIndicator,
  SeverityBadge,
  StatusBadge,
} from '../components/app/badges';
import { DataTable, type ColumnDef, type FilterDef } from '../components/app/data-table';
import { PageHeader } from '../components/app/page-header';
import { Button } from '../components/ui/button';
import { Field, Textarea } from '../components/ui/input';
import { Code, CodeBlock, DetailRow } from '../components/ui/misc';
import { Drawer, Modal } from '../components/ui/overlay';
import { InlineError } from '../components/ui/states';
import { Tabs } from '../components/ui/tabs';
import type { Finding } from '../types/finding';

const DETAIL_TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'assets', label: 'Affected assets' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'resolution', label: 'Resolution' },
  { id: 'references', label: 'References' },
  { id: 'activity', label: 'Activity' },
];

/** Findings: a professional data table over the live findings API, with a
 *  tabbed detail drawer and the original one-click workflows. */
export function FindingsPage() {
  const { token, user } = useAuth();
  const { current } = useNav();
  const { toast } = useToast();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [tab, setTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [fpOpen, setFpOpen] = useState(false);
  const [fpReason, setFpReason] = useState('');

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const page = await api.listFindings(token, 500);
      setFindings(page.items);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load findings.');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const openDetail = (f: Finding) => {
    setSelected(f);
    setTab('overview');
    setActionError(null);
  };

  // Deep link from elsewhere (e.g. an asset's vulnerabilities): #findings?finding=<id>
  // opens that finding's detail once, without reopening after the user closes it.
  const deepFindingId = current.params.finding;
  const handledDeepLink = useRef<string | null>(null);
  useEffect(() => {
    if (!deepFindingId || handledDeepLink.current === deepFindingId) return;
    const match = findings.find((f) => f.id === deepFindingId);
    if (match) {
      handledDeepLink.current = deepFindingId;
      openDetail(match);
    }
  }, [deepFindingId, findings]);

  const act = async (fn: () => Promise<unknown>, success: string) => {
    if (!token || !selected) return;
    setBusy(true);
    setActionError(null);
    try {
      await fn();
      const fresh = await api.getFinding(token, selected.id);
      setSelected(fresh);
      await load();
      toast('success', success);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Action failed.');
    } finally {
      setBusy(false);
    }
  };

  const markFixedAndVerify = () =>
    act(async () => {
      if (!token || !selected) return;
      await api.updateFinding(token, selected.id, { status: 'ready_for_verification' });
      await api.rescanFinding(token, selected.id);
    }, 'Re-check queued — the finding closes once verification succeeds.');

  const assignToMe = () =>
    act(async () => {
      if (!token || !selected || !user) return;
      await api.updateFinding(token, selected.id, { status: 'assigned', owner_user_id: user.id });
    }, 'Finding assigned to you.');

  const submitFalsePositive = () =>
    act(async () => {
      if (!token || !selected) return;
      await api.updateFinding(token, selected.id, {
        status: 'false_positive',
        false_positive_reason: fpReason,
      });
      setFpOpen(false);
      setFpReason('');
    }, 'Marked as false positive.');

  const columns: ColumnDef<Finding>[] = useMemo(
    () => [
      {
        id: 'title',
        header: 'Finding',
        cell: (f) => (
          <span className="block max-w-72 truncate font-medium text-text" title={f.title}>
            {f.title}
          </span>
        ),
        sortValue: (f) => f.title,
        csvValue: (f) => f.title,
      },
      {
        id: 'id',
        header: 'Identifier',
        defaultHidden: true,
        cell: (f) => <span className="font-mono text-xs text-muted">{f.id.slice(0, 8)}</span>,
        sortValue: (f) => f.id,
        csvValue: (f) => f.id,
      },
      {
        id: 'severity',
        header: 'Severity',
        cell: (f) => <SeverityBadge severity={f.severity} />,
        sortValue: (f) =>
          ['info', 'low', 'medium', 'high', 'critical'].indexOf(normalizeSeverity(f.severity)),
        csvValue: (f) => f.severity,
      },
      {
        id: 'priority',
        header: 'Priority',
        cell: (f) => <PriorityBadge priority={f.priority} />,
        sortValue: (f) => ['informational', 'watch', 'plan', 'fix_now'].indexOf(f.priority),
        csvValue: (f) => f.priority,
      },
      {
        id: 'risk',
        header: 'Risk score',
        cell: (f) => <RiskIndicator score={f.cvss_score} />,
        sortValue: (f) => f.cvss_score ?? -1,
        csvValue: (f) => (f.cvss_score != null ? String(f.cvss_score) : ''),
        align: 'right',
      },
      {
        id: 'asset',
        header: 'Affected asset',
        cell: (f) =>
          f.asset_id ? (
            <span className="font-mono text-xs text-muted">{f.asset_id.slice(0, 12)}</span>
          ) : (
            <span className="text-faint">—</span>
          ),
        sortValue: (f) => f.asset_id ?? '',
        csvValue: (f) => f.asset_id ?? '',
      },
      {
        id: 'site',
        header: 'Site',
        defaultHidden: true,
        cell: (f) => <span className="font-mono text-xs text-muted">{f.site_id.slice(0, 8)}</span>,
        sortValue: (f) => f.site_id,
        csvValue: (f) => f.site_id,
      },
      {
        id: 'kev',
        header: 'Exploited',
        cell: (f) =>
          f.known_exploited ? (
            <span className="text-xs font-semibold text-sev-critical">KEV</span>
          ) : (
            <span className="text-faint">—</span>
          ),
        sortValue: (f) => (f.known_exploited ? 1 : 0),
        csvValue: (f) => (f.known_exploited ? 'yes' : 'no'),
      },
      {
        id: 'confidence',
        header: 'Confidence',
        defaultHidden: true,
        cell: (f) => <span className="text-xs text-muted">{f.confidence_label}</span>,
        sortValue: (f) => f.confidence,
        csvValue: (f) => f.confidence_label,
      },
      {
        id: 'fix',
        header: 'Fix available',
        cell: (f) =>
          f.remediation ? (
            <span className="text-xs text-ok">Yes</span>
          ) : (
            <span className="text-faint">—</span>
          ),
        sortValue: (f) => (f.remediation ? 1 : 0),
        csvValue: (f) => (f.remediation ? 'yes' : 'no'),
      },
      {
        id: 'owner',
        header: 'Owner',
        defaultHidden: true,
        cell: (f) =>
          f.owner_user_id ? (
            <span className="font-mono text-xs text-muted">{f.owner_user_id.slice(0, 8)}</span>
          ) : (
            <span className="text-faint">Unassigned</span>
          ),
        sortValue: (f) => f.owner_user_id ?? '',
        csvValue: (f) => f.owner_user_id ?? '',
      },
      {
        id: 'status',
        header: 'Status',
        cell: (f) => <StatusBadge status={f.status} />,
        sortValue: (f) => f.status,
        csvValue: (f) => f.status,
      },
      {
        id: 'verified',
        header: 'Last verified',
        defaultHidden: true,
        cell: (f) => (
          <span className="text-xs text-muted">{formatWhenFull(f.last_verified_at)}</span>
        ),
        sortValue: (f) => f.last_verified_at ?? '',
        csvValue: (f) => f.last_verified_at ?? '',
      },
    ],
    [],
  );

  const filters: FilterDef<Finding>[] = useMemo(
    () => [
      {
        id: 'severity',
        label: 'Severity',
        options: ['critical', 'high', 'medium', 'low', 'info'].map((s) => ({
          value: s,
          label: humanize(s),
        })),
        predicate: (f, v) => normalizeSeverity(f.severity) === v,
      },
      {
        id: 'priority',
        label: 'Priority',
        options: [
          { value: 'fix_now', label: 'Fix now' },
          { value: 'plan', label: 'Plan a fix' },
          { value: 'watch', label: 'Watch' },
          { value: 'informational', label: 'Informational' },
        ],
        predicate: (f, v) => f.priority === v,
      },
      {
        id: 'status',
        label: 'Status',
        options: [...new Set(findings.map((f) => f.status))].map((s) => ({
          value: s,
          label: humanize(s),
        })),
        predicate: (f, v) => f.status === v,
      },
      {
        id: 'kev',
        label: 'Exploited',
        options: [{ value: 'yes', label: 'Known exploited (KEV)' }],
        predicate: (f, v) => (v === 'yes' ? f.known_exploited : true),
      },
    ],
    [findings],
  );

  // Honor deep links: #findings?severity=critical&q=…
  const initialSeverity = current.params.severity;
  const initialQuery = current.params.q;

  return (
    <div aria-label="Findings">
      <PageHeader
        crumbs={[{ label: 'Operations' }, { label: 'Findings' }]}
        title="Findings"
        description="Tracked vulnerabilities across your assets, prioritized by risk."
      />

      <DataTable<Finding>
        key={`${initialSeverity ?? ''}|${initialQuery ?? ''}`}
        columns={columns}
        rows={
          initialSeverity
            ? findings.filter((f) => normalizeSeverity(f.severity) === initialSeverity)
            : initialQuery
              ? findings.filter((f) => f.title.toLowerCase().includes(initialQuery.toLowerCase()))
              : findings
        }
        rowKey={(f) => f.id}
        searchText={(f) => `${f.title} ${f.id} ${f.scanner_name} ${f.cve_ids_json.join(' ')}`}
        searchPlaceholder="Search findings…"
        filters={filters}
        onRowClick={openDetail}
        selectable
        loading={loading}
        error={error}
        onRetry={() => void load()}
        emptyTitle="No findings yet"
        emptyDescription="Run an assessment to populate findings across your assets."
        exportName="findings"
        storageKey="vulnadash.findings"
        defaultSort={{ id: 'severity', dir: 'desc' }}
      />

      {/* Detail drawer */}
      <Drawer
        open={selected !== null}
        onClose={() => setSelected(null)}
        size="lg"
        title={
          selected ? (
            <span className="flex items-center gap-2">
              <ShieldAlert size={15} className="shrink-0 text-accent" aria-hidden />
              {selected.title}
            </span>
          ) : (
            ''
          )
        }
        description={
          selected
            ? `${humanize(selected.severity)} severity · ${selected.scanner_name}`
            : undefined
        }
        footer={
          selected && (
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
        {selected && (
          <div>
            {actionError && <InlineError message={actionError} className="mb-3" />}
            <div className="mb-3 flex flex-wrap items-center gap-1.5">
              <SeverityBadge severity={selected.severity} />
              <PriorityBadge priority={selected.priority} />
              <StatusBadge status={selected.status} />
              {selected.known_exploited && (
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
                    {selected.description ?? selected.title}
                  </p>
                </section>
                <section>
                  <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">
                    Why it matters
                  </h3>
                  <dl className="divide-y divide-border rounded-lg border border-border px-3">
                    <DetailRow label="Severity">{humanize(selected.severity)}</DetailRow>
                    {selected.cvss_score != null && (
                      <DetailRow label="CVSS">
                        <RiskIndicator score={selected.cvss_score} />
                      </DetailRow>
                    )}
                    {selected.epss_score != null && (
                      <DetailRow label="EPSS">{Math.round(selected.epss_score * 100)}%</DetailRow>
                    )}
                    <DetailRow label="Priority">
                      <PriorityBadge priority={selected.priority} />
                    </DetailRow>
                    <DetailRow label="Confidence">
                      {selected.confidence_label} ({selected.confidence}/100)
                    </DetailRow>
                  </dl>
                  <p className="mt-2 text-xs text-muted">{selected.priority_rationale}</p>
                </section>
                {selected.cve_ids_json.length > 0 && (
                  <section>
                    <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">
                      CVEs
                    </h3>
                    <div className="flex flex-wrap gap-1.5">
                      {selected.cve_ids_json.map((cve) => (
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
                  {selected.asset_id ? <Code>{selected.asset_id}</Code> : '—'}
                </DetailRow>
                <DetailRow label="Service">
                  {selected.service_id ? <Code>{selected.service_id}</Code> : '—'}
                </DetailRow>
                <DetailRow label="Site">
                  <Code>{selected.site_id}</Code>
                </DetailRow>
                <DetailRow label="Scanner">{selected.scanner_name}</DetailRow>
              </dl>
            )}

            {tab === 'evidence' && (
              <div>
                <p className="mb-2 text-xs text-muted">
                  Raw technical evidence captured by the scanner.
                </p>
                <CodeBlock>{JSON.stringify(selected.evidence_json, null, 2)}</CodeBlock>
              </div>
            )}

            {tab === 'resolution' && (
              <div className="flex flex-col gap-4">
                <section>
                  <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">
                    Practical remediation
                  </h3>
                  <p className="text-[13px] leading-relaxed text-text">
                    {selected.remediation ?? 'No specific remediation recorded.'}
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
                {selected.references_json.length === 0 ? (
                  <p className="text-xs text-muted">No references recorded.</p>
                ) : (
                  <ul className="flex flex-col gap-1.5">
                    {selected.references_json.map((r) => (
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
                  <StatusBadge status={selected.status} />
                </DetailRow>
                <DetailRow label="Owner">
                  {selected.owner_user_id ? <Code>{selected.owner_user_id}</Code> : 'Unassigned'}
                </DetailRow>
                <DetailRow label="Validation">{humanize(selected.validation_status)}</DetailRow>
                <DetailRow label="Last verified">
                  {formatWhenFull(selected.last_verified_at)}
                </DetailRow>
                <DetailRow label="Resolved">{formatWhenFull(selected.resolved_at)}</DetailRow>
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
    </div>
  );
}
