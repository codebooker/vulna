import type { HTMLAttributes } from 'react';
import { cn } from '../../lib/utils';

export type BadgeTone =
  'neutral' | 'accent' | 'ok' | 'warn' | 'bad' | 'critical' | 'high' | 'medium' | 'low' | 'info';

const TONES: Record<BadgeTone, string> = {
  neutral: 'bg-surface-3 text-muted border-transparent',
  accent: 'bg-[var(--accent-tint)] text-accent-strong border-accent/25',
  ok: 'bg-ok/12 text-ok border-ok/25',
  warn: 'bg-warn/12 text-warn border-warn/25',
  bad: 'bg-bad/12 text-bad border-bad/25',
  critical: 'bg-sev-critical/12 text-sev-critical border-sev-critical/30',
  high: 'bg-sev-high/12 text-sev-high border-sev-high/30',
  medium: 'bg-sev-medium/12 text-sev-medium border-sev-medium/30',
  low: 'bg-sev-low/12 text-sev-low border-sev-low/30',
  info: 'bg-sev-info/12 text-sev-info border-sev-info/30',
};

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: BadgeTone;
  dot?: boolean;
}

export function Badge({ tone = 'neutral', dot, className, children, ...props }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border px-1.5 py-px text-[11px] font-medium',
        TONES[tone],
        className,
      )}
      {...props}
    >
      {dot && <span aria-hidden className="h-1.5 w-1.5 rounded-full bg-current" />}
      {children}
    </span>
  );
}
