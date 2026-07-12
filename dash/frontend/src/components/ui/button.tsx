import { forwardRef, type ButtonHTMLAttributes } from 'react';
import { Loader2 } from 'lucide-react';
import { cn } from '../../lib/utils';

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'destructive' | 'outline';
export type ButtonSize = 'sm' | 'md' | 'icon' | 'icon-sm';

const VARIANTS: Record<ButtonVariant, string> = {
  primary:
    'bg-brand text-white dark:text-[#06252b] font-semibold hover:brightness-110 active:brightness-95 disabled:hover:brightness-100',
  secondary:
    'bg-surface-2 text-text border border-border hover:bg-surface-3 hover:border-border-strong',
  outline: 'border border-border-strong text-text bg-transparent hover:bg-surface-2',
  ghost: 'text-muted hover:bg-surface-2 hover:text-text',
  destructive:
    'bg-bad/10 text-bad border border-bad/30 hover:bg-bad/20 dark:bg-bad/15 dark:hover:bg-bad/25',
};

const SIZES: Record<ButtonSize, string> = {
  sm: 'h-7 px-2.5 text-xs gap-1.5 rounded-md',
  md: 'h-8.5 px-3.5 text-[13px] gap-2 rounded-lg',
  icon: 'h-8.5 w-8.5 rounded-lg justify-center',
  'icon-sm': 'h-7 w-7 rounded-md justify-center',
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { className, variant = 'secondary', size = 'md', loading, disabled, children, ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      type={props.type ?? 'button'}
      disabled={disabled || loading}
      className={cn(
        'inline-flex select-none items-center whitespace-nowrap transition-colors',
        'disabled:cursor-not-allowed disabled:opacity-55',
        VARIANTS[variant],
        SIZES[size],
        className,
      )}
      {...props}
    >
      {loading && <Loader2 size={14} className="animate-spin" aria-hidden />}
      {children}
    </button>
  );
});
