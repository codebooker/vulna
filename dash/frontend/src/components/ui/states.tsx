import type { LucideIcon } from 'lucide-react';
import { AlertTriangle, Inbox, RefreshCw } from 'lucide-react';
import { cn } from '../../lib/utils';
import { Button } from './button';

export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden className={cn('animate-pulse rounded-md bg-surface-3', className)} />;
}

export function TableSkeleton({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="flex flex-col gap-2 p-4" role="status" aria-label="Loading">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex items-center gap-3">
          {Array.from({ length: cols }).map((_, c) => (
            <Skeleton
              key={c}
              className={cn('h-4 flex-1', c === 0 && 'max-w-8', c === 1 && 'flex-[2]')}
            />
          ))}
        </div>
      ))}
      <span className="visually-hidden">Loading…</span>
    </div>
  );
}

export function CardSkeleton({ lines = 3 }: { lines?: number }) {
  return (
    <div className="flex flex-col gap-2.5 p-4" role="status" aria-label="Loading">
      <Skeleton className="h-4 w-1/3" />
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton key={i} className="h-3.5 w-full" />
      ))}
    </div>
  );
}

export function EmptyState({
  icon: Icon = Inbox,
  title,
  description,
  action,
  compact,
  className,
}: {
  icon?: LucideIcon;
  title: string;
  description?: string;
  action?: React.ReactNode;
  compact?: boolean;
  className?: string;
}) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center text-center',
        compact ? 'gap-1.5 px-4 py-6' : 'gap-2 px-6 py-12',
        className,
      )}
    >
      <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-border bg-surface-2 text-faint">
        <Icon size={17} aria-hidden />
      </div>
      <p className="text-[13px] font-medium text-text">{title}</p>
      {description && <p className="max-w-sm text-xs text-muted">{description}</p>}
      {action && <div className="mt-1.5">{action}</div>}
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
  compact,
  className,
}: {
  message: string;
  onRetry?: () => void;
  compact?: boolean;
  className?: string;
}) {
  return (
    <div
      role="alert"
      className={cn(
        'flex flex-col items-center justify-center gap-2 text-center',
        compact ? 'px-4 py-6' : 'px-6 py-12',
        className,
      )}
    >
      <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-bad/30 bg-bad/10 text-bad">
        <AlertTriangle size={17} aria-hidden />
      </div>
      <p className="text-[13px] font-medium text-text">Something went wrong</p>
      <p className="max-w-sm text-xs text-muted">{message}</p>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry} className="mt-1">
          <RefreshCw size={13} aria-hidden /> Retry
        </Button>
      )}
    </div>
  );
}

/** Inline (non-blocking) error banner for partial failures inside a page. */
export function InlineError({ message, className }: { message: string; className?: string }) {
  return (
    <p
      role="alert"
      className={cn(
        'flex items-center gap-2 rounded-lg border border-bad/30 bg-bad/10 px-3 py-2 text-xs text-bad',
        className,
      )}
    >
      <AlertTriangle size={13} aria-hidden className="shrink-0" />
      {message}
    </p>
  );
}
