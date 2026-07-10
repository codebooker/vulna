import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import type { SearchHit, SearchResults } from '../types/dashboard';

/** Global command/search across assets, findings, scans, sites, and reports. */
export function GlobalSearch() {
  const { token } = useAuth();
  const [q, setQ] = useState('');
  const [results, setResults] = useState<SearchResults | null>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!token || q.trim().length < 2) {
      setResults(null);
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

  return (
    <div className="global-search" role="search">
      <label className="visually-hidden" htmlFor="global-search-input">
        Search assets, findings, scans, sites, and reports
      </label>
      <input
        id="global-search-input"
        type="search"
        placeholder="Search…"
        value={q}
        onChange={(e) => setQ(e.target.value)}
        onFocus={() => results && setOpen(true)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        aria-expanded={open}
      />
      {open && results && (
        <div className="search-results" role="listbox" aria-label="Search results">
          {total === 0 ? (
            <p className="detail">No matches.</p>
          ) : (
            groups.map(
              ([label, hits]) =>
                hits.length > 0 && (
                  <div key={label} className="search-group">
                    <span className="search-group-label">{label}</span>
                    <ul>
                      {hits.map((h) => (
                        <li key={`${h.kind}-${h.id}`} role="option" aria-selected={false}>
                          {h.label}
                        </li>
                      ))}
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
