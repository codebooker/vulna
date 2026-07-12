import type { ReactNode } from 'react';
import { cn } from '../../lib/utils';

export interface TabDef {
  id: string;
  label: ReactNode;
  count?: number;
}

/** Underline-style tab bar (controlled). */
export function Tabs({
  tabs,
  value,
  onChange,
  className,
}: {
  tabs: TabDef[];
  value: string;
  onChange: (id: string) => void;
  className?: string;
}) {
  return (
    <div
      role="tablist"
      className={cn('flex items-center gap-1 overflow-x-auto border-b border-border', className)}
    >
      {tabs.map((t) => {
        const active = t.id === value;
        return (
          <button
            key={t.id}
            role="tab"
            type="button"
            aria-selected={active}
            onClick={() => onChange(t.id)}
            className={cn(
              '-mb-px inline-flex items-center gap-1.5 whitespace-nowrap border-b-2 px-3 py-2 text-[13px] transition-colors',
              active
                ? 'border-accent font-semibold text-text'
                : 'border-transparent text-muted hover:border-border-strong hover:text-text',
            )}
          >
            {t.label}
            {typeof t.count === 'number' && (
              <span
                className={cn(
                  'rounded-full px-1.5 text-[11px] leading-4',
                  active ? 'bg-[var(--accent-tint)] text-accent-strong' : 'bg-surface-3 text-muted',
                )}
              >
                {t.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

/** Pill-style segmented control, for compact toggles (e.g. table/card view). */
export function Segmented({
  options,
  value,
  onChange,
  ariaLabel,
  className,
}: {
  options: { id: string; label: ReactNode; title?: string }[];
  value: string;
  onChange: (id: string) => void;
  ariaLabel?: string;
  className?: string;
}) {
  return (
    <div
      role="group"
      aria-label={ariaLabel}
      className={cn(
        'inline-flex items-center rounded-lg border border-border bg-surface-2 p-0.5',
        className,
      )}
    >
      {options.map((o) => (
        <button
          key={o.id}
          type="button"
          title={o.title}
          aria-pressed={o.id === value}
          onClick={() => onChange(o.id)}
          className={cn(
            'inline-flex h-7 items-center gap-1.5 rounded-md px-2.5 text-xs font-medium transition-colors',
            o.id === value
              ? 'bg-surface text-text shadow-[var(--shadow-sm)] border border-border'
              : 'text-muted hover:text-text',
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
