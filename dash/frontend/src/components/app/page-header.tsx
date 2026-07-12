import type { ReactNode } from 'react';
import { ChevronRight } from 'lucide-react';
import { cn } from '../../lib/utils';

/** Consistent page header: breadcrumb trail, title, description, actions. */
export function PageHeader({
  crumbs,
  title,
  description,
  actions,
  className,
}: {
  crumbs?: { label: string; onClick?: () => void }[];
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('mb-4 flex flex-wrap items-end justify-between gap-3', className)}>
      <div className="min-w-0">
        {crumbs && crumbs.length > 0 && (
          <nav aria-label="Breadcrumb" className="mb-1 flex items-center gap-1 text-xs text-faint">
            {crumbs.map((c, i) => (
              <span key={i} className="flex items-center gap-1">
                {i > 0 && <ChevronRight size={12} aria-hidden />}
                {c.onClick ? (
                  <button
                    type="button"
                    onClick={c.onClick}
                    className="rounded hover:text-text hover:underline"
                  >
                    {c.label}
                  </button>
                ) : (
                  <span>{c.label}</span>
                )}
              </span>
            ))}
          </nav>
        )}
        <h1 className="text-lg font-bold leading-tight text-text">{title}</h1>
        {description && <p className="mt-0.5 max-w-2xl text-[13px] text-muted">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}

/** Section heading inside a page. */
export function SectionHeader({
  title,
  actions,
  className,
}: {
  title: string;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('mb-2 flex items-center justify-between gap-3', className)}>
      <h2 className="text-[13px] font-semibold text-text">{title}</h2>
      {actions}
    </div>
  );
}

/** "View all →" link used by compact Overview sections. */
export function ViewAllLink({
  onClick,
  label = 'View all',
}: {
  onClick: () => void;
  label?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="text-xs font-medium text-accent-strong hover:underline"
    >
      {label} →
    </button>
  );
}
