import type { ReactNode } from 'react';
import { cn } from '../../lib/utils';

export function Switch({
  checked,
  onChange,
  disabled,
  ariaLabel,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  ariaLabel?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={ariaLabel}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        'relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border transition-colors',
        checked ? 'border-transparent bg-brand' : 'border-border-strong bg-surface-3',
        disabled && 'cursor-not-allowed opacity-50',
      )}
    >
      <span
        aria-hidden
        className={cn(
          'inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform',
          checked ? 'translate-x-[18px]' : 'translate-x-[3px]',
        )}
      />
    </button>
  );
}

export function Progress({
  value,
  max = 100,
  tone = 'accent',
  className,
  label,
}: {
  value: number;
  max?: number;
  tone?: 'accent' | 'ok' | 'warn' | 'bad';
  className?: string;
  label?: string;
}) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100));
  const color =
    tone === 'ok' ? 'bg-ok' : tone === 'warn' ? 'bg-warn' : tone === 'bad' ? 'bg-bad' : 'bg-brand';
  return (
    <div
      role="progressbar"
      aria-valuenow={Math.round(value)}
      aria-valuemin={0}
      aria-valuemax={max}
      aria-label={label}
      className={cn('h-1.5 w-full overflow-hidden rounded-full bg-surface-3', className)}
    >
      <div
        className={cn('h-full rounded-full transition-[width]', color)}
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd className="rounded border border-border bg-surface-2 px-1 py-px font-mono text-[10px] text-muted">
      {children}
    </kbd>
  );
}

export function Code({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <code
      className={cn(
        'rounded border border-border bg-surface-2 px-1 py-px font-mono text-[12px] text-text',
        className,
      )}
    >
      {children}
    </code>
  );
}

export function CodeBlock({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <pre
      className={cn(
        'slim-scroll overflow-x-auto rounded-lg border border-border bg-surface-2 p-3 font-mono text-xs leading-relaxed text-text',
        className,
      )}
    >
      {children}
    </pre>
  );
}

/** Definition-list row used in detail drawers. */
export function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 py-1.5">
      <dt className="shrink-0 text-xs text-muted">{label}</dt>
      <dd className="min-w-0 text-right text-[13px] text-text">{children}</dd>
    </div>
  );
}
