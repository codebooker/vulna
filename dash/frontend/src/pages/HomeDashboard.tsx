import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip as ChartTooltip,
} from 'recharts';
import {
  AlertOctagon,
  HardDrive,
  Radar,
  Rocket,
  Server,
  ShieldAlert,
  Target,
  X,
} from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useNav } from '../lib/nav';
import { formatRelative, humanize } from '../lib/utils';
import {
  normalizeSeverity,
  PriorityBadge,
  StatusBadge,
  type Severity,
} from '../components/app/badges';
import { ChartContainer, chartTheme } from '../components/app/chart-container';
import { SeverityMetricCard, StatTile } from '../components/app/metric-card';
import { PageHeader, ViewAllLink } from '../components/app/page-header';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card, CardBody, CardHeader } from '../components/ui/card';
import { Progress } from '../components/ui/misc';
import { CardSkeleton, ErrorState } from '../components/ui/states';
import type { DashboardSummary } from '../types/dashboard';
import type { Finding } from '../types/finding';
import type { ProbeSummary, OnboardingState } from '../types/onboarding';
import type { ScanSchedule } from '../types/schedule';
import type { Site } from '../types/inventory';

const SEV_KEYS = ['critical', 'high', 'medium', 'low'] as const;

/** Concise operational Overview: severity cards, compact metrics, charts, and
 *  short "View all" sections. Designed to fit one desktop screen. */
export function HomeDashboard() {
  const { token } = useAuth();
  const { go } = useNav();
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [schedules, setSchedules] = useState<ScanSchedule[]>([]);
  const [probes, setProbes] = useState<ProbeSummary[]>([]);
  const [onboarding, setOnboarding] = useState<OnboardingState | null>(null);
  const [setupHidden, setSetupHidden] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [assetTotal, setAssetTotal] = useState(0);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      // The summary powers the headline; the rest fills the compact sections.
      const [sum, f, s, sch, p, ob, a] = await Promise.all([
        api.dashboardSummary(token),
        api.listFindingSnapshot(token).catch(() => null),
        api.listSites(token).catch(() => null),
        api.listSchedules(token).catch(() => []),
        api.listProbes(token).catch(() => null),
        api.onboardingState(token).catch(() => null),
        api.listAssets(token).catch(() => null),
      ]);
      setSummary(sum);
      setFindings(f?.items ?? []);
      setSites(s?.items ?? []);
      setSchedules(sch ?? []);
      setProbes(p?.items ?? []);
      setOnboarding(ob);
      setAssetTotal(a?.total ?? 0);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load the dashboard.');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  /* -------- derived, all from the same findings dataset so counts agree -------- */

  const active = useMemo(() => findings.filter((f) => f.resolved_at === null), [findings]);
  const resolved = useMemo(() => findings.filter((f) => f.resolved_at !== null), [findings]);

  const sevCounts = useMemo(() => {
    const counts: Record<Severity, { total: number; fresh: number; resolved: number }> = {
      critical: { total: 0, fresh: 0, resolved: 0 },
      high: { total: 0, fresh: 0, resolved: 0 },
      medium: { total: 0, fresh: 0, resolved: 0 },
      low: { total: 0, fresh: 0, resolved: 0 },
      info: { total: 0, fresh: 0, resolved: 0 },
    };
    for (const f of active) {
      const sev = normalizeSeverity(f.severity);
      counts[sev].total += 1;
      if (f.status === 'new') counts[sev].fresh += 1;
    }
    for (const f of resolved) counts[normalizeSeverity(f.severity)].resolved += 1;
    return counts;
  }, [active, resolved]);

  const donutData = useMemo(
    () =>
      (['critical', 'high', 'medium', 'low', 'info'] as const)
        .map((sev) => ({ sev, name: humanize(sev), value: sevCounts[sev].total }))
        .filter((d) => d.value > 0),
    [sevCounts],
  );

  const riskBySite = useMemo(() => {
    const map = new Map<string, { critical: number; high: number; total: number }>();
    for (const f of active) {
      const cur = map.get(f.site_id) ?? { critical: 0, high: 0, total: 0 };
      const sev = normalizeSeverity(f.severity);
      if (sev === 'critical') cur.critical += 1;
      if (sev === 'high') cur.high += 1;
      cur.total += 1;
      map.set(f.site_id, cur);
    }
    const name = (id: string) => sites.find((s) => s.id === id)?.name ?? id.slice(0, 8);
    return [...map.entries()]
      .map(([siteId, v]) => ({ site: name(siteId), ...v }))
      .sort((a, b) => b.critical * 3 + b.high - (a.critical * 3 + a.high))
      .slice(0, 5);
  }, [active, sites]);

  const riskyAssets = useMemo(() => {
    const map = new Map<string, { critical: number; high: number; total: number }>();
    for (const f of active) {
      if (!f.asset_id) continue;
      const cur = map.get(f.asset_id) ?? { critical: 0, high: 0, total: 0 };
      const sev = normalizeSeverity(f.severity);
      if (sev === 'critical') cur.critical += 1;
      if (sev === 'high') cur.high += 1;
      cur.total += 1;
      map.set(f.asset_id, cur);
    }
    return [...map.entries()]
      .map(([assetId, v]) => ({ assetId, ...v }))
      .sort((a, b) => b.critical * 3 + b.high - (a.critical * 3 + a.high))
      .slice(0, 5);
  }, [active]);

  const failedSchedules = schedules.filter((s) => s.last_error);
  const recentScans = [...schedules]
    .filter((s) => s.last_run_at)
    .sort((a, b) => (b.last_run_at ?? '').localeCompare(a.last_run_at ?? ''))
    .slice(0, 4);
  const offlineAppliances = probes.filter(
    (p) => !['connected', 'online', 'enrolled', 'active'].includes(p.status.toLowerCase()),
  );
  const totalAssets = assetTotal;
  const attentionAssets = riskyAssets.filter((a) => a.critical > 0 || a.high > 0).length;
  const coveragePct = summary
    ? summary.unassessed.approved_scopes > 0
      ? Math.min(
          100,
          Math.round(
            (summary.unassessed.completed_scans / summary.unassessed.approved_scopes) * 100,
          ),
        )
      : 0
    : 0;

  const showSetup =
    onboarding !== null &&
    onboarding.completed_at === null &&
    !onboarding.dismissed &&
    !setupHidden;
  const setupProgress = onboarding ? onboarding.completed_steps.length : 0;

  const dismissSetup = async () => {
    setSetupHidden(true);
    if (token) {
      try {
        await api.dismissOnboarding(token);
      } catch {
        // non-fatal
      }
    }
  };

  if (error && !summary) {
    return <ErrorState message={error} onRetry={() => void load()} />;
  }

  return (
    <div aria-label="Overview">
      <PageHeader
        title="Overview"
        description="What needs attention right now, across every site."
      />

      {/* Compact, dismissible setup card (full checklist lives on Getting started) */}
      {showSetup && (
        <Card className="mb-4 border-accent/30 bg-[var(--accent-tint)]">
          <div className="flex flex-wrap items-center gap-3 px-4 py-3">
            <Rocket size={16} className="shrink-0 text-accent-strong" aria-hidden />
            <div className="min-w-0 flex-1">
              <p className="text-[13px] font-semibold text-text">Finish setting up Vulna</p>
              <p className="text-xs text-muted">
                {setupProgress} step{setupProgress === 1 ? '' : 's'} done — nothing is scanned until
                you approve a target range.
              </p>
            </div>
            <Button variant="primary" size="sm" onClick={() => go('getting-started')}>
              Continue setup
            </Button>
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label="Dismiss setup card"
              onClick={() => void dismissSetup()}
            >
              <X size={14} />
            </Button>
          </div>
        </Card>
      )}

      {/* Next recommended action */}
      {summary && (
        <div className="mb-4 flex items-center gap-2.5 rounded-lg border border-border bg-surface px-3.5 py-2.5 text-[13px]">
          <span
            aria-hidden
            className={
              summary.next_action.priority === 'fix_now'
                ? 'h-2 w-2 shrink-0 animate-pulse rounded-full bg-sev-critical'
                : 'h-2 w-2 shrink-0 rounded-full bg-accent'
            }
          />
          <span className="font-semibold text-text">Next</span>
          <span className="min-w-0 flex-1 truncate text-muted">{summary.next_action.message}</span>
        </div>
      )}

      {/* Severity metric cards */}
      <div className="mb-3 grid grid-cols-2 gap-3 xl:grid-cols-4">
        {SEV_KEYS.map((sev) => (
          <SeverityMetricCard
            key={sev}
            loading={loading}
            label={humanize(sev)}
            count={sevCounts[sev].total}
            newCount={sevCounts[sev].fresh}
            resolvedCount={sevCounts[sev].resolved}
            delta={sevCounts[sev].fresh - sevCounts[sev].resolved}
            colorVar={`--sev-${sev}`}
            onClick={() => go('findings', { severity: sev })}
          />
        ))}
      </div>

      {/* Compact operational metrics */}
      <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
        <StatTile
          loading={loading}
          label="Total assets"
          value={totalAssets}
          icon={Server}
          onClick={() => go('assets')}
        />
        <StatTile
          loading={loading}
          label="Need attention"
          value={attentionAssets}
          icon={Target}
          tone={attentionAssets > 0 ? 'warn' : 'ok'}
          onClick={() => go('assets', { filter: 'attention' })}
        />
        <StatTile
          loading={loading}
          label="Active schedules"
          value={schedules.filter((s) => s.enabled).length}
          icon={Radar}
          onClick={() => go('scans')}
        />
        <StatTile
          loading={loading}
          label="Scan coverage"
          value={`${coveragePct}%`}
          icon={ShieldAlert}
        />
        <StatTile
          loading={loading}
          label="Offline appliances"
          value={offlineAppliances.length}
          icon={HardDrive}
          tone={offlineAppliances.length > 0 ? 'bad' : 'ok'}
          onClick={() => go('appliances')}
        />
        <StatTile
          loading={loading}
          label="Failed scans"
          value={failedSchedules.length}
          icon={AlertOctagon}
          tone={failedSchedules.length > 0 ? 'bad' : 'ok'}
          onClick={() => go('scans', { tab: 'failed' })}
        />
      </div>

      {/* Charts (real data only) */}
      <div className="mb-4 grid grid-cols-1 gap-3 lg:grid-cols-2">
        <ChartContainer
          title="Severity distribution"
          description="Active findings by severity"
          loading={loading}
          empty={donutData.length === 0}
          emptyLabel="No active findings"
        >
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={donutData}
                dataKey="value"
                nameKey="name"
                innerRadius="62%"
                outerRadius="85%"
                paddingAngle={2}
                strokeWidth={0}
                onClick={(d: { sev?: Severity }) => d.sev && go('findings', { severity: d.sev })}
              >
                {donutData.map((d) => (
                  <Cell key={d.sev} fill={chartTheme.severity[d.sev]} cursor="pointer" />
                ))}
              </Pie>
              <ChartTooltip
                {...chartTheme.tooltip}
                formatter={(value: number, name: string) => {
                  const total = donutData.reduce((n, d) => n + d.value, 0);
                  return [`${value} (${total ? Math.round((value / total) * 100) : 0}%)`, name];
                }}
              />
              <text
                x="50%"
                y="47%"
                textAnchor="middle"
                dominantBaseline="middle"
                className="fill-[var(--text)]"
                style={{ fontSize: 22, fontWeight: 700 }}
              >
                {active.length}
              </text>
              <text
                x="50%"
                y="58%"
                textAnchor="middle"
                dominantBaseline="middle"
                className="fill-[var(--muted)]"
                style={{ fontSize: 11 }}
              >
                active findings
              </text>
              <Legend
                verticalAlign="bottom"
                iconSize={8}
                formatter={(value: string) => (
                  <span style={{ color: 'var(--muted)', fontSize: 11 }}>{value}</span>
                )}
              />
            </PieChart>
          </ResponsiveContainer>
        </ChartContainer>

        {/* Risk by site */}
        <Card>
          <CardHeader title="Risk by site" actions={<ViewAllLink onClick={() => go('sites')} />} />
          <CardBody className="flex flex-col gap-2.5">
            {loading ? (
              <CardSkeleton lines={4} />
            ) : riskBySite.length === 0 ? (
              <p className="py-4 text-center text-xs text-muted">No site risk data yet.</p>
            ) : (
              riskBySite.map((s) => (
                <div key={s.site}>
                  <div className="mb-1 flex items-center justify-between text-xs">
                    <span className="truncate font-medium text-text">{s.site}</span>
                    <span className="text-muted">
                      {s.critical > 0 && (
                        <span className="mr-2 text-sev-critical">{s.critical} critical</span>
                      )}
                      {s.high > 0 && <span className="text-sev-high">{s.high} high</span>}
                      {s.critical === 0 && s.high === 0 && `${s.total} findings`}
                    </span>
                  </div>
                  <Progress
                    value={Math.min(100, s.critical * 30 + s.high * 12 + s.total * 2)}
                    tone={s.critical > 0 ? 'bad' : s.high > 0 ? 'warn' : 'accent'}
                    label={`Relative risk for ${s.site}`}
                  />
                </div>
              ))
            )}
          </CardBody>
        </Card>
      </div>

      {/* Compact sections */}
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        {/* Highest-priority findings */}
        <Card className="xl:col-span-1">
          <CardHeader
            title="Highest-priority findings"
            actions={<ViewAllLink onClick={() => go('findings')} />}
          />
          <CardBody className="flex flex-col gap-1.5 pt-0">
            {loading ? (
              <CardSkeleton lines={4} />
            ) : (summary?.needs_attention.top ?? []).length === 0 ? (
              <p className="py-3 text-center text-xs text-muted">
                Nothing needs attention right now.
              </p>
            ) : (
              summary?.needs_attention.top.slice(0, 4).map((t) => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => go('findings', { q: t.title })}
                  className="rounded-lg border border-transparent px-2 py-1.5 text-left transition-colors hover:border-border hover:bg-surface-2"
                >
                  <span className="flex items-center gap-2">
                    <PriorityBadge priority={t.priority} />
                    <span className="truncate text-[13px] font-medium text-text">{t.title}</span>
                  </span>
                  <span className="mt-0.5 block truncate text-xs text-muted">
                    {humanize(t.severity)} severity · {t.confidence_label} confidence. {t.rationale}
                  </span>
                </button>
              ))
            )}
          </CardBody>
        </Card>

        {/* Highest-risk assets */}
        <Card>
          <CardHeader
            title="Highest-risk assets"
            actions={<ViewAllLink onClick={() => go('assets')} />}
          />
          <CardBody className="flex flex-col gap-1 pt-0">
            {loading ? (
              <CardSkeleton lines={4} />
            ) : riskyAssets.length === 0 ? (
              <p className="py-3 text-center text-xs text-muted">No at-risk assets identified.</p>
            ) : (
              riskyAssets.map((a) => (
                <div
                  key={a.assetId}
                  className="flex items-center justify-between gap-2 px-2 py-1.5"
                >
                  <span className="truncate font-mono text-xs text-text">
                    {a.assetId.slice(0, 16)}
                  </span>
                  <span className="flex shrink-0 items-center gap-1.5 text-[11px]">
                    {a.critical > 0 && <Badge tone="critical">{a.critical} Critical</Badge>}
                    {a.high > 0 && <Badge tone="high">{a.high} High</Badge>}
                    <span className="text-muted">{a.total} total</span>
                  </span>
                </div>
              ))
            )}
          </CardBody>
        </Card>

        {/* Appliance health */}
        <Card>
          <CardHeader
            title="Appliance health"
            actions={<ViewAllLink onClick={() => go('appliances')} />}
          />
          <CardBody className="flex flex-col gap-1 pt-0">
            {loading ? (
              <CardSkeleton lines={3} />
            ) : probes.length === 0 ? (
              <p className="py-3 text-center text-xs text-muted">No appliances enrolled yet.</p>
            ) : (
              probes.slice(0, 4).map((p) => (
                <div key={p.id} className="flex items-center justify-between gap-2 px-2 py-1.5">
                  <span className="truncate text-[13px] text-text">{p.name}</span>
                  <StatusBadge status={p.status} />
                </div>
              ))
            )}
            {!loading && summary && (
              <div className="mt-1 border-t border-border pt-2">
                {Object.entries(summary.health).map(([k, v]) => (
                  <div key={k} className="flex items-center justify-between px-2 py-1 text-xs">
                    <span className="text-muted">{humanize(k)}</span>
                    <StatusBadge status={v} />
                  </div>
                ))}
              </div>
            )}
          </CardBody>
        </Card>

        {/* Recent scans */}
        <Card>
          <CardHeader title="Recent scans" actions={<ViewAllLink onClick={() => go('scans')} />} />
          <CardBody className="flex flex-col gap-1 pt-0">
            {loading ? (
              <CardSkeleton lines={3} />
            ) : recentScans.length === 0 ? (
              <p className="py-3 text-center text-xs text-muted">No scans have run yet.</p>
            ) : (
              recentScans.map((s) => (
                <div key={s.id} className="flex items-center justify-between gap-2 px-2 py-1.5">
                  <span className="min-w-0">
                    <span className="block truncate text-[13px] text-text">{s.name}</span>
                    <span className="block text-[11px] text-muted">
                      {formatRelative(s.last_run_at)}
                    </span>
                  </span>
                  <StatusBadge status={s.last_error ? 'failed' : 'completed'} />
                </div>
              ))
            )}
          </CardBody>
        </Card>

        {/* Failed scans */}
        <Card>
          <CardHeader
            title="Failed scans"
            actions={<ViewAllLink onClick={() => go('scans', { tab: 'failed' })} />}
          />
          <CardBody className="flex flex-col gap-1 pt-0">
            {loading ? (
              <CardSkeleton lines={2} />
            ) : failedSchedules.length === 0 ? (
              <p className="py-3 text-center text-xs text-ok">No failed scans. All clear.</p>
            ) : (
              failedSchedules.slice(0, 3).map((s) => (
                <div key={s.id} className="px-2 py-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-[13px] text-text">{s.name}</span>
                    <StatusBadge status="failed" />
                  </div>
                  <p className="mt-0.5 truncate text-[11px] text-bad" title={s.last_error ?? ''}>
                    {s.last_error}
                  </p>
                </div>
              ))
            )}
          </CardBody>
        </Card>

        {/* Recent activity */}
        <Card>
          <CardHeader
            title="Recent activity"
            actions={<ViewAllLink onClick={() => go('changes')} />}
          />
          <CardBody className="flex flex-col gap-1 pt-0">
            {loading ? (
              <CardSkeleton lines={4} />
            ) : (summary?.changed_recently.recent ?? []).length === 0 ? (
              <p className="py-3 text-center text-xs text-muted">No recent changes.</p>
            ) : (
              summary?.changed_recently.recent.slice(0, 4).map((c, i) => (
                <div key={i} className="flex items-start gap-2 px-2 py-1.5">
                  <span
                    aria-hidden
                    className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-accent"
                  />
                  <span className="min-w-0">
                    <span className="block truncate text-[13px] text-text">{c.summary}</span>
                    <span className="block text-[11px] text-muted">
                      {humanize(c.event_type)} · {formatRelative(c.created_at)}
                    </span>
                  </span>
                </div>
              ))
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
