import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  BarChart3,
  Building2,
  ClipboardCheck,
  Download,
  FileSpreadsheet,
  FileText,
  Server,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useToast } from '../lib/toast';
import { formatBytes, formatWhenFull } from '../lib/utils';
import { StatusBadge } from '../components/app/badges';
import { DataTable, type ColumnDef } from '../components/app/data-table';
import { PageHeader, SectionHeader } from '../components/app/page-header';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import type { Report } from '../types/report';

const TYPE_LABELS: Record<string, string> = {
  executive_pdf: 'Executive summary (PDF)',
  technical_pdf: 'Technical report (PDF)',
  findings_csv: 'Findings (CSV)',
  assets_csv: 'Assets (CSV)',
  services_csv: 'Services (CSV)',
  cve_exposure_csv: 'CVE exposure (CSV)',
  json_bundle: 'JSON bundle',
};

/** Report templates the platform produces from completed scans. Cards are
 *  informational — generation happens automatically per scan, so there is no
 *  dead "Generate" button here. */
const TEMPLATES: { icon: LucideIcon; title: string; description: string }[] = [
  {
    icon: FileText,
    title: 'Executive summary',
    description: 'Plain-language risk overview for leadership, generated per completed scan.',
  },
  {
    icon: BarChart3,
    title: 'Findings report',
    description: 'Full technical findings with evidence and remediation guidance.',
  },
  {
    icon: Server,
    title: 'Asset report',
    description: 'Inventory export with services and exposure per asset.',
  },
  {
    icon: Building2,
    title: 'Site report',
    description: 'Per-site posture: coverage, findings, and change history.',
  },
  {
    icon: ClipboardCheck,
    title: 'Remediation progress',
    description: 'Fixed vs. outstanding work and verification outcomes.',
  },
  {
    icon: FileSpreadsheet,
    title: 'Historical trends',
    description: 'CSV/JSON series for your own BI tooling.',
  },
];

export function ReportsPage() {
  const { token, logout } = useAuth();
  const { toast } = useToast();
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const page = await api.listReports(token);
      setReports(page.items);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        logout();
        return;
      }
      setError(err instanceof Error ? err.message : 'Failed to load reports.');
    } finally {
      setLoading(false);
    }
  }, [token, logout]);

  useEffect(() => {
    void load();
  }, [load]);

  const download = useCallback(
    async (report: Report) => {
      if (!token) return;
      setDownloading(report.id);
      setError(null);
      try {
        const blob = await api.downloadReport(token, report.id);
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = `${report.report_type}.${report.format}`;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        URL.revokeObjectURL(url);
        toast('success', 'Report downloaded.');
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          logout();
          return;
        }
        setError(err instanceof Error ? err.message : 'Failed to download report.');
      } finally {
        setDownloading(null);
      }
    },
    [token, logout, toast],
  );

  const columns: ColumnDef<Report>[] = useMemo(
    () => [
      {
        id: 'report',
        header: 'Report',
        cell: (r) => (
          <span className="font-medium text-text">
            {TYPE_LABELS[r.report_type] ?? r.report_type}
          </span>
        ),
        sortValue: (r) => TYPE_LABELS[r.report_type] ?? r.report_type,
        csvValue: (r) => r.report_type,
      },
      {
        id: 'format',
        header: 'Format',
        defaultHidden: true,
        cell: (r) => <span className="font-mono text-xs uppercase text-muted">{r.format}</span>,
        sortValue: (r) => r.format,
        csvValue: (r) => r.format,
      },
      {
        id: 'size',
        header: 'Size',
        cell: (r) => (
          <span className="text-xs tabular-nums text-muted">{formatBytes(r.size_bytes)}</span>
        ),
        sortValue: (r) => r.size_bytes,
        csvValue: (r) => String(r.size_bytes),
        align: 'right',
      },
      {
        id: 'status',
        header: 'Status',
        cell: (r) => <StatusBadge status={r.status} />,
        sortValue: (r) => r.status,
        csvValue: (r) => r.status,
      },
      {
        id: 'generated',
        header: 'Generated',
        cell: (r) => <span className="text-xs text-muted">{formatWhenFull(r.generated_at)}</span>,
        sortValue: (r) => r.generated_at ?? '',
        csvValue: (r) => r.generated_at ?? '',
      },
      {
        id: 'actions',
        header: 'Actions',
        align: 'right',
        cell: (r) => (
          <Button
            size="sm"
            variant="outline"
            disabled={r.status !== 'completed' || downloading === r.id}
            onClick={(e) => {
              e.stopPropagation();
              void download(r);
            }}
          >
            <Download size={12} aria-hidden />
            {downloading === r.id ? 'Downloading…' : 'Download'}
          </Button>
        ),
      },
    ],
    [download, downloading],
  );

  return (
    <div aria-label="Reports">
      <PageHeader
        crumbs={[{ label: 'Management' }, { label: 'Reports' }]}
        title="Reports"
        description="Exports produced from completed scans — PDF for people, CSV and JSON for tooling."
      />

      <SectionHeader title="Report templates" />
      <div className="mb-5 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {TEMPLATES.map((t) => (
          <Card key={t.title} className="flex items-start gap-3 p-3.5">
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-[var(--accent-tint)] text-accent">
              <t.icon size={15} aria-hidden />
            </span>
            <div className="min-w-0">
              <p className="text-[13px] font-semibold text-text">{t.title}</p>
              <p className="mt-0.5 text-xs leading-relaxed text-muted">{t.description}</p>
            </div>
          </Card>
        ))}
      </div>

      <SectionHeader title="Generated reports" />
      <DataTable<Report>
        columns={columns}
        rows={reports}
        rowKey={(r) => r.id}
        searchText={(r) => `${TYPE_LABELS[r.report_type] ?? r.report_type} ${r.format}`}
        searchPlaceholder="Search reports…"
        loading={loading}
        error={error}
        onRetry={() => void load()}
        emptyTitle="No reports yet"
        emptyDescription="Reports are generated from completed scans and appear here for download."
        exportName="reports"
        storageKey="vulnadash.reports"
        defaultSort={{ id: 'generated', dir: 'desc' }}
      />
    </div>
  );
}
