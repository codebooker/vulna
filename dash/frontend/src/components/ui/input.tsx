import { forwardRef, type InputHTMLAttributes, type SelectHTMLAttributes } from 'react';
import { Search } from 'lucide-react';
import { cn } from '../../lib/utils';

const FIELD_CLASSES =
  'h-8.5 w-full rounded-lg border border-border bg-surface px-3 text-[13px] text-text ' +
  'placeholder:text-faint transition-colors hover:border-border-strong ' +
  'focus:border-accent focus:outline-none focus:ring-2 focus:ring-[var(--ring)]/40 ' +
  'disabled:cursor-not-allowed disabled:opacity-55 dark:bg-surface-2';

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  function Input({ className, ...props }, ref) {
    return <input ref={ref} className={cn(FIELD_CLASSES, className)} {...props} />;
  },
);

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(
  function Select({ className, children, ...props }, ref) {
    return (
      <select ref={ref} className={cn(FIELD_CLASSES, 'appearance-auto pr-2', className)} {...props}>
        {children}
      </select>
    );
  },
);

export function SearchInput({
  className,
  wrapClassName,
  ...props
}: InputHTMLAttributes<HTMLInputElement> & { wrapClassName?: string }) {
  return (
    <div className={cn('relative', wrapClassName)}>
      <Search
        size={14}
        aria-hidden
        className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-faint"
      />
      <Input type="search" className={cn('pl-8', className)} {...props} />
    </div>
  );
}

export function Field({
  label,
  htmlFor,
  hint,
  children,
  className,
}: {
  label: string;
  htmlFor?: string;
  hint?: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('flex flex-col gap-1.5', className)}>
      <label htmlFor={htmlFor} className="text-xs font-medium text-muted">
        {label}
      </label>
      {children}
      {hint && <p className="text-[11px] text-faint">{hint}</p>}
    </div>
  );
}

export function Textarea({
  className,
  ...props
}: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={cn(FIELD_CLASSES, 'h-auto min-h-20 py-2 leading-relaxed', className)}
      {...props}
    />
  );
}
