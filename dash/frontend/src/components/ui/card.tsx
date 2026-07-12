import type { HTMLAttributes, ReactNode } from 'react';
import { cn } from '../../lib/utils';

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        'rounded-xl border border-border bg-surface shadow-[var(--shadow-sm)]',
        className,
      )}
      {...props}
    />
  );
}

export function CardHeader({
  title,
  description,
  actions,
  className,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('flex items-start justify-between gap-3 px-4 pt-3.5 pb-2', className)}>
      <div className="min-w-0">
        <h3 className="text-[13px] font-semibold text-text">{title}</h3>
        {description && <p className="mt-0.5 text-xs text-muted">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-1.5">{actions}</div>}
    </div>
  );
}

export function CardBody({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('px-4 pb-4', className)} {...props} />;
}
