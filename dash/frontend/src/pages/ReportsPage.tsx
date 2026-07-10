import { useCallback, useEffect, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
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

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function ReportsPage() {
  const { token, logout } = useAuth();
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
    [token, logout],
  );

  return (
    <div className="card">
      <h2>Reports</h2>
      {loading && <p className="detail">Loading reports…</p>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {!loading && reports.length === 0 && !error && (
        <p className="detail">
          No reports yet — generate one from a completed scan to produce PDF, CSV, and JSON exports.
        </p>
      )}
      {reports.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>Report</th>
              <th>Size</th>
              <th>Generated</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {reports.map((r) => (
              <tr key={r.id}>
                <td>{TYPE_LABELS[r.report_type] ?? r.report_type}</td>
                <td>{formatBytes(r.size_bytes)}</td>
                <td>{r.generated_at ? new Date(r.generated_at).toLocaleString() : '—'}</td>
                <td>
                  <button
                    type="button"
                    className="btn ghost"
                    disabled={r.status !== 'completed' || downloading === r.id}
                    onClick={() => void download(r)}
                  >
                    {downloading === r.id ? 'Downloading…' : 'Download'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
