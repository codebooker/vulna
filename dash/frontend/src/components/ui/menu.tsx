import { useEffect, useRef, useState, type ButtonHTMLAttributes, type ReactNode } from 'react';
import { cn } from '../../lib/utils';

/** Lightweight dropdown menu anchored to its trigger. */
export function Menu({
  trigger,
  children,
  align = 'end',
  width = 'w-52',
}: {
  trigger: (props: { open: boolean; toggle: () => void }) => ReactNode;
  children: ReactNode | ((close: () => void) => ReactNode);
  align?: 'start' | 'end';
  width?: string;
}) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const close = () => setOpen(false);

  return (
    <div ref={rootRef} className="relative">
      {trigger({ open, toggle: () => setOpen((o) => !o) })}
      {open && (
        <div
          role="menu"
          className={cn(
            'vd-pop-in absolute z-40 mt-1.5 max-h-80 overflow-y-auto rounded-lg border border-border bg-surface p-1 shadow-[var(--shadow-md)]',
            align === 'end' ? 'right-0' : 'left-0',
            width,
          )}
        >
          {typeof children === 'function' ? children(close) : children}
        </div>
      )}
    </div>
  );
}

export function MenuItem({
  className,
  active,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { active?: boolean }) {
  return (
    <button
      type="button"
      role="menuitem"
      className={cn(
        'flex w-full items-center gap-2 rounded-md px-2.5 py-1.5 text-left text-[13px] text-text',
        'hover:bg-surface-2 disabled:cursor-not-allowed disabled:opacity-50',
        active && 'bg-[var(--accent-tint)] text-accent-strong',
        className,
      )}
      {...props}
    />
  );
}

export function MenuSeparator() {
  return <div role="separator" className="my-1 h-px bg-border" />;
}

export function MenuLabel({ children }: { children: ReactNode }) {
  return (
    <p className="px-2.5 pb-1 pt-1.5 text-[10px] font-semibold uppercase tracking-wider text-faint">
      {children}
    </p>
  );
}

/** Simple hover/focus tooltip. */
export function Tooltip({
  label,
  children,
  className,
}: {
  label: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <span className={cn('group/tt relative inline-flex', className)}>
      {children}
      <span
        role="tooltip"
        className={cn(
          'pointer-events-none absolute bottom-full left-1/2 z-50 mb-1.5 -translate-x-1/2 whitespace-nowrap',
          'rounded-md border border-border bg-surface px-2 py-1 text-[11px] text-text shadow-[var(--shadow-md)]',
          'opacity-0 transition-opacity duration-100 group-hover/tt:opacity-100 group-focus-within/tt:opacity-100',
        )}
      >
        {label}
      </span>
    </span>
  );
}
