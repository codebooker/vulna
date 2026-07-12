import type { ReactNode } from 'react';
import { Card, CardHeader } from '../ui/card';
import { CardSkeleton, EmptyState } from '../ui/states';
import { BarChart3 } from 'lucide-react';

/** Standard wrapper for charts: title, optional toolbar, loading/empty states. */
export function ChartContainer({
  title,
  description,
  toolbar,
  loading,
  empty,
  emptyLabel = 'No data to chart yet',
  children,
  height = 240,
  className,
}: {
  title: ReactNode;
  description?: ReactNode;
  toolbar?: ReactNode;
  loading?: boolean;
  empty?: boolean;
  emptyLabel?: string;
  children: ReactNode;
  height?: number;
  className?: string;
}) {
  return (
    <Card className={className}>
      <CardHeader title={title} description={description} actions={toolbar} />
      <div className="px-2 pb-3" style={{ height }}>
        {loading ? (
          <CardSkeleton lines={4} />
        ) : empty ? (
          <EmptyState compact icon={BarChart3} title={emptyLabel} className="h-full" />
        ) : (
          children
        )}
      </div>
    </Card>
  );
}

/** Shared recharts styling helpers (theme-aware via CSS variables). */
export const chartTheme = {
  grid: 'var(--border)',
  axis: 'var(--faint)',
  tooltip: {
    contentStyle: {
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      borderRadius: 8,
      fontSize: 12,
      color: 'var(--text)',
      boxShadow: 'var(--shadow-md)',
    },
    labelStyle: { color: 'var(--muted)', fontWeight: 600 },
    itemStyle: { color: 'var(--text)' },
  },
  severity: {
    critical: 'var(--sev-critical)',
    high: 'var(--sev-high)',
    medium: 'var(--sev-medium)',
    low: 'var(--sev-low)',
    info: 'var(--sev-info)',
  },
} as const;
