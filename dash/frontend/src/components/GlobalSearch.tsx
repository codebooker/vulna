import { useEffect, useRef, useState } from 'react';
import { FileText, Building2, Radar, Search, Server, ShieldAlert } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { useNav } from '../lib/nav';
import type { SearchHit, SearchResults } from '../types/dashboard';

const KIND_META: Record<string, { icon: typeof Search; route: string }> = {
  finding: { icon: ShieldAlert, route: 'findings' },
  asset: { icon: Server, route: 'assets' },
  site: { icon: Building2, route: 'sites' },
  scan: { icon: Radar, route: 'scans' },
  report: { icon: FileText, route: 'reports' },
};

const KIND_PARAM: Record<string, string> = {
  finding: 'finding',
  asset: 'asset',
  site: 'site',
  scan: 'job',
  report: 'report',
};

/** Global search across assets, findings, scans, sites, and reports. */
export function GlobalSearch() {
  const { token } = useAuth();
  const { go } = useNav();
  const [q, setQ] = useState('');
  const [results, setResults] = useState<SearchResults | null>(null);
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!token || q.trim().length < 2) {
      setResults(null);
      setOpen(false);
      return;
    }
    const handle = setTimeout(() => {
      void api
        .search(token, q.trim())
        .then((r) => {
          setResults(r);
          setOpen(true);
        })
        .catch(() => setResults(null));
    }, 200);
    return () => clearTimeout(handle);
  }, [q, token]);

  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, []);

  const groups: [string, SearchHit[]][] = results
    ? [
        ['Findings', results.findings],
        ['Assets', results.assets],
        ['Sites', results.sites],
        ['Scans', results.scans],
        ['Reports', results.reports],
      ]
    : [];
  const total = groups.reduce((n, [, hits]) => n + hits.length, 0);

  const pick = (hit: SearchHit) => {
    const meta = KIND_META[hit.kind];
    setOpen(false);
    setQ('');
    const param = KIND_PARAM[hit.kind];
    go(meta?.route ?? 'overview', param ? { [param]: hit.id } : undefined);
  };

  return (
    <div ref={rootRef} className="relative w-full max-w-xs" role="search">
      <label className="visually-hidden" htmlFor="global-search-input">
        Search assets, findings, scans, sites, and reports
      </label>
      <Search
        size={14}
        aria-hidden
        className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-faint"
      />
      <input
        id="global-search-input"
        type="search"
        placeholder="Search…"
        autoComplete="off"
        value={q}
        onChange={(e) => setQ(e.target.value)}
        onFocus={() => results && setOpen(true)}
        aria-expanded={open}
        className="h-8 w-full rounded-lg border border-border bg-surface-2 pl-8 pr-3 text-[13px] text-text placeholder:text-faint transition-colors hover:border-border-strong focus:border-accent focus:outline-none focus:ring-2 focus:ring-[var(--ring)]/40"
      />
      {open && results && (
        <div
          role="listbox"
          aria-label="Search results"
          className="vd-pop-in slim-scroll absolute right-0 top-full z-40 mt-1.5 max-h-96 w-[min(380px,90vw)] overflow-y-auto rounded-lg border border-border bg-surface p-1.5 shadow-[var(--shadow-md)]"
        >
          {total === 0 ? (
            <p className="px-2.5 py-3 text-center text-xs text-muted">No matches.</p>
          ) : (
            groups.map(
              ([label, hits]) =>
                hits.length > 0 && (
                  <div key={label} className="mb-1 last:mb-0">
                    <p className="px-2.5 pb-0.5 pt-1.5 text-[10px] font-semibold uppercase tracking-wider text-faint">
                      {label}
                    </p>
                    <ul>
                      {hits.map((h) => {
                        const Icon = KIND_META[h.kind]?.icon ?? Search;
                        return (
                          <li key={`${h.kind}-${h.id}`}>
                            <button
                              type="button"
                              role="option"
                              aria-selected={false}
                              onClick={() => pick(h)}
                              className="flex w-full items-center gap-2 rounded-md px-2.5 py-1.5 text-left text-[13px] text-text hover:bg-surface-2"
                            >
                              <Icon size={13} aria-hidden className="shrink-0 text-faint" />
                              <span className="truncate">{h.label}</span>
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                ),
            )
          )}
        </div>
      )}
    </div>
  );
}
