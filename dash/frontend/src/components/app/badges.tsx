import { Badge, type BadgeTone } from '../ui/badge';
import { cn, humanize } from '../../lib/utils';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export function normalizeSeverity(s: string | null | undefined): Severity {
  const v = (s ?? '').toLowerCase();
  if (v === 'critical') return 'critical';
  if (v === 'high') return 'high';
  if (v === 'medium' || v === 'moderate') return 'medium';
  if (v === 'low') return 'low';
  return 'info';
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** Severity badge — always shows the name, never color alone. */
export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  const sev = normalizeSeverity(severity);
  return (
    <Badge tone={sev === 'info' ? 'info' : sev} dot className={className}>
      {SEVERITY_LABEL[sev]}
    </Badge>
  );
}

const STATUS_TONES: Record<string, BadgeTone> = {
  // generic
  ok: 'ok',
  connected: 'ok',
  online: 'ok',
  enrolled: 'ok',
  active: 'ok',
  completed: 'ok',
  sent: 'ok',
  verified_fixed: 'ok',
  resolved: 'ok',
  enabled: 'ok',
  running: 'accent',
  in_progress: 'accent',
  assigned: 'accent',
  ready_for_verification: 'accent',
  pending: 'warn',
  pending_approval: 'warn',
  degraded: 'warn',
  stale: 'warn',
  warning: 'warn',
  warn: 'warn',
  paused: 'warn',
  offline: 'bad',
  failed: 'bad',
  fail: 'bad',
  error: 'bad',
  killed: 'bad',
  action: 'bad',
  new: 'neutral',
  open: 'neutral',
  disabled: 'neutral',
  off: 'neutral',
  never_synced: 'neutral',
  false_positive: 'neutral',
  accepted_risk: 'neutral',
  dismissed: 'neutral',
};

/** Status badge with sensible tone mapping and readable label. */
export function StatusBadge({ status, className }: { status: string; className?: string }) {
  const key = status.toLowerCase();
  return (
    <Badge tone={STATUS_TONES[key] ?? 'neutral'} dot className={className}>
      {humanize(key)}
    </Badge>
  );
}

/** Compact 0–10 risk indicator: score plus a tinted bar. */
export function RiskIndicator({ score, className }: { score: number | null; className?: string }) {
  if (score == null || Number.isNaN(score)) return <span className="text-faint">—</span>;
  const clamped = Math.max(0, Math.min(10, score));
  const tone =
    clamped >= 9
      ? 'bg-sev-critical'
      : clamped >= 7
        ? 'bg-sev-high'
        : clamped >= 4
          ? 'bg-sev-medium'
          : 'bg-sev-low';
  return (
    <span className={cn('inline-flex items-center gap-2', className)}>
      <span className="w-7 text-right font-mono text-[12px] tabular-nums text-text">
        {clamped.toFixed(1)}
      </span>
      <span className="h-1.5 w-12 overflow-hidden rounded-full bg-surface-3" aria-hidden>
        <span
          className={cn('block h-full rounded-full', tone)}
          style={{ width: `${clamped * 10}%` }}
        />
      </span>
    </span>
  );
}

const PRIORITY_META: Record<string, { label: string; tone: BadgeTone }> = {
  fix_now: { label: 'Fix now', tone: 'critical' },
  plan: { label: 'Plan a fix', tone: 'high' },
  watch: { label: 'Watch', tone: 'medium' },
  informational: { label: 'Informational', tone: 'info' },
};

export function PriorityBadge({ priority, className }: { priority: string; className?: string }) {
  const meta = PRIORITY_META[priority] ?? {
    label: humanize(priority),
    tone: 'neutral' as BadgeTone,
  };
  return (
    <Badge tone={meta.tone} className={className}>
      {meta.label}
    </Badge>
  );
}
