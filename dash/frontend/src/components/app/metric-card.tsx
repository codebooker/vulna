import type { LucideIcon } from 'lucide-react';
import { ArrowDownRight, ArrowUpRight, Minus } from 'lucide-react';
import { cn } from '../../lib/utils';
import { Card } from '../ui/card';
import { Skeleton } from '../ui/states';

/** Compact severity metric card: count, new/resolved, and period delta. */
export function SeverityMetricCard({
  label,
  count,
  newCount,
  resolvedCount,
  delta,
  colorVar,
  onClick,
  loading,
}: {
  label: string;
  count: number;
  newCount: number;
  resolvedCount: number;
  /** Change from the previous period (negative is an improvement). */
  delta: number;
  colorVar: string;
  onClick?: () => void;
  loading?: boolean;
}) {
  const DeltaIcon = delta > 0 ? ArrowUpRight : delta < 0 ? ArrowDownRight : Minus;
  const deltaColor = delta > 0 ? 'text-bad' : delta < 0 ? 'text-ok' : 'text-faint';
  return (
    <Card
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onClick={onClick}
      onKeyDown={(e) => {
        if (onClick && (e.key === 'Enter' || e.key === ' ')) {
          e.preventDefault();
          onClick();
        }
      }}
      className={cn(
        'relative overflow-hidden px-4 py-3',
        onClick && 'cursor-pointer transition-colors hover:border-border-strong hover:bg-surface-2',
      )}
    >
      <span
        aria-hidden
        className="absolute inset-y-0 left-0 w-[3px]"
        style={{ background: `var(${colorVar})` }}
      />
      {loading ? (
        <div className="flex flex-col gap-2">
          <Skeleton className="h-3.5 w-16" />
          <Skeleton className="h-7 w-12" />
          <Skeleton className="h-3 w-24" />
        </div>
      ) : (
        <>
          <div className="flex items-center justify-between gap-2">
            <p className="text-xs font-semibold uppercase tracking-wide text-muted">{label}</p>
            <span
              className={cn('inline-flex items-center gap-0.5 text-xs font-medium', deltaColor)}
            >
              <DeltaIcon size={13} aria-hidden />
              {delta === 0 ? '0' : `${delta > 0 ? '+' : ''}${delta}`}
            </span>
          </div>
          <p className="mt-1 text-2xl font-bold leading-none tabular-nums text-text">{count}</p>
          <p className="mt-1.5 text-[11px] text-muted">
            <span className="font-medium text-text">{newCount}</span> new ·{' '}
            <span className="font-medium text-text">{resolvedCount}</span> resolved
          </p>
        </>
      )}
    </Card>
  );
}

/** Small single-stat tile used in the compact metrics strip. */
export function StatTile({
  label,
  value,
  icon: Icon,
  tone = 'default',
  onClick,
  loading,
}: {
  label: string;
  value: string | number;
  icon?: LucideIcon;
  tone?: 'default' | 'ok' | 'warn' | 'bad';
  onClick?: () => void;
  loading?: boolean;
}) {
  const valueColor =
    tone === 'ok'
      ? 'text-ok'
      : tone === 'warn'
        ? 'text-warn'
        : tone === 'bad'
          ? 'text-bad'
          : 'text-text';
  return (
    <Card
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onClick={onClick}
      onKeyDown={(e) => {
        if (onClick && (e.key === 'Enter' || e.key === ' ')) {
          e.preventDefault();
          onClick();
        }
      }}
      className={cn(
        'flex items-center gap-3 px-3.5 py-2.5',
        onClick && 'cursor-pointer transition-colors hover:border-border-strong hover:bg-surface-2',
      )}
    >
      {Icon && (
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-surface-2 text-muted">
          <Icon size={15} aria-hidden />
        </span>
      )}
      <div className="min-w-0">
        {loading ? (
          <>
            <Skeleton className="mb-1 h-4 w-10" />
            <Skeleton className="h-3 w-20" />
          </>
        ) : (
          <>
            <p className={cn('text-lg font-bold leading-tight tabular-nums', valueColor)}>
              {value}
            </p>
            <p className="truncate text-[11px] text-muted">{label}</p>
          </>
        )}
      </div>
    </Card>
  );
}
