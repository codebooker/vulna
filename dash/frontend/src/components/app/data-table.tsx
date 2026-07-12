import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Bookmark,
  ChevronLeft,
  ChevronRight,
  Columns3,
  Download,
  FilterX,
} from 'lucide-react';
import { cn, downloadCsv } from '../../lib/utils';
import { Button } from '../ui/button';
import { Card } from '../ui/card';
import { SearchInput, Select } from '../ui/input';
import { Menu, MenuItem, MenuLabel, MenuSeparator } from '../ui/menu';
import { EmptyState, ErrorState, TableSkeleton } from '../ui/states';

export interface ColumnDef<T> {
  id: string;
  header: string;
  cell: (row: T) => ReactNode;
  /** Sortable value; omit to disable sorting for this column. */
  sortValue?: (row: T) => string | number;
  /** Plain-text value for CSV export; falls back to sortValue. */
  csvValue?: (row: T) => string;
  align?: 'left' | 'right';
  /** Hidden by default (can be enabled via column menu). */
  defaultHidden?: boolean;
  headerClassName?: string;
  cellClassName?: string;
}

export interface FilterDef<T> {
  id: string;
  label: string;
  options: { value: string; label: string }[];
  predicate: (row: T, value: string) => boolean;
}

interface SavedView {
  name: string;
  search: string;
  filters: Record<string, string>;
  hidden: string[];
}

export interface DataTableProps<T> {
  columns: ColumnDef<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  /** Fields searched by the free-text box. */
  searchText?: (row: T) => string;
  searchPlaceholder?: string;
  filters?: FilterDef<T>[];
  onRowClick?: (row: T) => void;
  selectable?: boolean;
  /** Toolbar slot rendered next to the search box (e.g. bulk actions). */
  toolbar?: (ctx: { selected: T[]; clearSelection: () => void }) => ReactNode;
  loading?: boolean;
  error?: string | null;
  onRetry?: () => void;
  emptyTitle?: string;
  emptyDescription?: string;
  emptyAction?: ReactNode;
  exportName?: string;
  /** Persist saved views + column visibility under this key. */
  storageKey?: string;
  defaultSort?: { id: string; dir: 'asc' | 'desc' };
  pageSize?: number;
  className?: string;
}

function loadJson<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function saveJson(key: string, value: unknown): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // ignore storage failures
  }
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  searchText,
  searchPlaceholder = 'Search…',
  filters = [],
  onRowClick,
  selectable,
  toolbar,
  loading,
  error,
  onRetry,
  emptyTitle = 'Nothing here yet',
  emptyDescription,
  emptyAction,
  exportName,
  storageKey,
  defaultSort,
  pageSize: initialPageSize = 25,
  className,
}: DataTableProps<T>) {
  const [search, setSearch] = useState('');
  const [filterValues, setFilterValues] = useState<Record<string, string>>({});
  const [sort, setSort] = useState<{ id: string; dir: 'asc' | 'desc' } | null>(defaultSort ?? null);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(initialPageSize);
  const [hidden, setHidden] = useState<string[]>(() =>
    storageKey
      ? loadJson<string[]>(
          `${storageKey}.cols`,
          columns.filter((c) => c.defaultHidden).map((c) => c.id),
        )
      : columns.filter((c) => c.defaultHidden).map((c) => c.id),
  );
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [views, setViews] = useState<SavedView[]>(() =>
    storageKey ? loadJson<SavedView[]>(`${storageKey}.views`, []) : [],
  );
  const headerCheckbox = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (storageKey) saveJson(`${storageKey}.cols`, hidden);
  }, [hidden, storageKey]);

  const visibleColumns = columns.filter((c) => !hidden.includes(c.id));
  const hasActiveFilters = search.trim() !== '' || Object.values(filterValues).some(Boolean);

  const filtered = useMemo(() => {
    let out = rows;
    const q = search.trim().toLowerCase();
    if (q && searchText) out = out.filter((r) => searchText(r).toLowerCase().includes(q));
    for (const f of filters) {
      const v = filterValues[f.id];
      if (v) out = out.filter((r) => f.predicate(r, v));
    }
    return out;
  }, [rows, search, searchText, filters, filterValues]);

  const sorted = useMemo(() => {
    if (!sort) return filtered;
    const col = columns.find((c) => c.id === sort.id);
    if (!col?.sortValue) return filtered;
    const sv = col.sortValue;
    return [...filtered].sort((a, b) => {
      const av = sv(a);
      const bv = sv(b);
      const cmp =
        typeof av === 'number' && typeof bv === 'number'
          ? av - bv
          : String(av).localeCompare(String(bv));
      return sort.dir === 'asc' ? cmp : -cmp;
    });
  }, [filtered, sort, columns]);

  const pageCount = Math.max(1, Math.ceil(sorted.length / pageSize));
  const clampedPage = Math.min(page, pageCount - 1);
  const pageRows = sorted.slice(clampedPage * pageSize, (clampedPage + 1) * pageSize);

  useEffect(() => {
    setPage(0);
  }, [search, filterValues, pageSize]);

  const pageKeys = pageRows.map(rowKey);
  const allPageSelected = pageKeys.length > 0 && pageKeys.every((k) => selected.has(k));
  const somePageSelected = pageKeys.some((k) => selected.has(k));

  useEffect(() => {
    if (headerCheckbox.current) {
      headerCheckbox.current.indeterminate = somePageSelected && !allPageSelected;
    }
  }, [somePageSelected, allPageSelected]);

  const toggleSort = (id: string) => {
    setSort((cur) =>
      cur?.id !== id ? { id, dir: 'asc' } : cur.dir === 'asc' ? { id, dir: 'desc' } : null,
    );
  };

  const toggleRow = (key: string) => {
    setSelected((cur) => {
      const next = new Set(cur);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const togglePage = () => {
    setSelected((cur) => {
      const next = new Set(cur);
      if (allPageSelected) pageKeys.forEach((k) => next.delete(k));
      else pageKeys.forEach((k) => next.add(k));
      return next;
    });
  };

  const selectedRows = useMemo(
    () => rows.filter((r) => selected.has(rowKey(r))),
    [rows, selected, rowKey],
  );

  const exportCsv = () => {
    const cols = visibleColumns;
    const toText = (c: ColumnDef<T>, r: T) => c.csvValue?.(r) ?? String(c.sortValue?.(r) ?? '');
    downloadCsv(
      `${exportName ?? 'export'}.csv`,
      cols.map((c) => c.header),
      sorted.map((r) => cols.map((c) => toText(c, r))),
    );
  };

  const applyView = (v: SavedView) => {
    setSearch(v.search);
    setFilterValues(v.filters);
    setHidden(v.hidden);
  };

  const saveCurrentView = () => {
    const name = window.prompt('Name this view:');
    if (!name) return;
    const next = [
      ...views.filter((v) => v.name !== name),
      { name, search, filters: filterValues, hidden },
    ];
    setViews(next);
    if (storageKey) saveJson(`${storageKey}.views`, next);
  };

  const deleteView = (name: string) => {
    const next = views.filter((v) => v.name !== name);
    setViews(next);
    if (storageKey) saveJson(`${storageKey}.views`, next);
  };

  return (
    <Card className={cn('overflow-hidden', className)}>
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2.5">
        {searchText && (
          <SearchInput
            wrapClassName="w-full sm:w-56"
            placeholder={searchPlaceholder}
            value={search}
            aria-label={searchPlaceholder}
            onChange={(e) => setSearch(e.target.value)}
          />
        )}
        {filters.map((f) => (
          <Select
            key={f.id}
            aria-label={f.label}
            value={filterValues[f.id] ?? ''}
            onChange={(e) => setFilterValues((cur) => ({ ...cur, [f.id]: e.target.value }))}
            className={cn(
              'w-auto min-w-28',
              filterValues[f.id] && 'border-accent text-accent-strong',
            )}
          >
            <option value="">{f.label}: all</option>
            {f.options.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        ))}
        {hasActiveFilters && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSearch('');
              setFilterValues({});
            }}
          >
            <FilterX size={13} aria-hidden /> Clear
          </Button>
        )}
        <div className="ml-auto flex items-center gap-1.5">
          {toolbar?.({ selected: selectedRows, clearSelection: () => setSelected(new Set()) })}
          {storageKey && (
            <Menu
              trigger={({ toggle }) => (
                <Button variant="ghost" size="sm" onClick={toggle} title="Saved views">
                  <Bookmark size={13} aria-hidden /> Views
                </Button>
              )}
            >
              {(close) => (
                <>
                  <MenuLabel>Saved views</MenuLabel>
                  {views.length === 0 && (
                    <p className="px-2.5 pb-1.5 text-xs text-faint">No saved views yet.</p>
                  )}
                  {views.map((v) => (
                    <div key={v.name} className="flex items-center">
                      <MenuItem
                        className="flex-1"
                        onClick={() => {
                          applyView(v);
                          close();
                        }}
                      >
                        {v.name}
                      </MenuItem>
                      <button
                        type="button"
                        aria-label={`Delete view ${v.name}`}
                        className="mr-1 rounded px-1 text-faint hover:text-bad"
                        onClick={() => deleteView(v.name)}
                      >
                        ×
                      </button>
                    </div>
                  ))}
                  <MenuSeparator />
                  <MenuItem
                    onClick={() => {
                      saveCurrentView();
                      close();
                    }}
                  >
                    Save current view…
                  </MenuItem>
                </>
              )}
            </Menu>
          )}
          <Menu
            trigger={({ toggle }) => (
              <Button variant="ghost" size="sm" onClick={toggle} title="Show or hide columns">
                <Columns3 size={13} aria-hidden /> Columns
              </Button>
            )}
          >
            <MenuLabel>Columns</MenuLabel>
            {columns.map((c) => (
              <MenuItem
                key={c.id}
                onClick={() =>
                  setHidden((cur) =>
                    cur.includes(c.id) ? cur.filter((h) => h !== c.id) : [...cur, c.id],
                  )
                }
              >
                <input
                  type="checkbox"
                  readOnly
                  checked={!hidden.includes(c.id)}
                  className="accent-[var(--brand)]"
                  tabIndex={-1}
                />
                {c.header}
              </MenuItem>
            ))}
          </Menu>
          {exportName && (
            <Button variant="ghost" size="sm" onClick={exportCsv} title="Export as CSV">
              <Download size={13} aria-hidden /> Export
            </Button>
          )}
        </div>
      </div>

      {/* Body */}
      {loading ? (
        <TableSkeleton cols={Math.min(visibleColumns.length + (selectable ? 1 : 0), 7)} />
      ) : error ? (
        <ErrorState compact message={error} onRetry={onRetry} />
      ) : sorted.length === 0 ? (
        hasActiveFilters ? (
          <EmptyState
            compact
            title="No matches"
            description="No rows match the current search or filters."
            action={
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setSearch('');
                  setFilterValues({});
                }}
              >
                Clear filters
              </Button>
            }
          />
        ) : (
          <EmptyState title={emptyTitle} description={emptyDescription} action={emptyAction} />
        )
      ) : (
        <div className="slim-scroll overflow-x-auto">
          <table className="w-full border-collapse text-[13px]">
            <thead>
              <tr className="border-b border-border bg-surface-2/60">
                {selectable && (
                  <th className="w-9 px-3 py-2">
                    <input
                      ref={headerCheckbox}
                      type="checkbox"
                      aria-label="Select all rows on this page"
                      checked={allPageSelected}
                      onChange={togglePage}
                      className="accent-[var(--brand)]"
                    />
                  </th>
                )}
                {visibleColumns.map((c) => (
                  <th
                    key={c.id}
                    scope="col"
                    className={cn(
                      'whitespace-nowrap px-3 py-2 text-left text-[11px] font-semibold uppercase tracking-wide text-muted',
                      c.align === 'right' && 'text-right',
                      c.headerClassName,
                    )}
                  >
                    {c.sortValue ? (
                      <button
                        type="button"
                        onClick={() => toggleSort(c.id)}
                        className={cn(
                          'inline-flex items-center gap-1 rounded hover:text-text',
                          sort?.id === c.id && 'text-text',
                        )}
                      >
                        {c.header}
                        {sort?.id === c.id ? (
                          sort.dir === 'asc' ? (
                            <ArrowUp size={11} aria-hidden />
                          ) : (
                            <ArrowDown size={11} aria-hidden />
                          )
                        ) : (
                          <ArrowUpDown size={11} aria-hidden className="opacity-40" />
                        )}
                      </button>
                    ) : (
                      c.header
                    )}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {pageRows.map((r) => {
                const key = rowKey(r);
                const isSelected = selected.has(key);
                return (
                  <tr
                    key={key}
                    onClick={onRowClick ? () => onRowClick(r) : undefined}
                    className={cn(
                      'border-b border-border last:border-b-0',
                      onRowClick && 'cursor-pointer transition-colors hover:bg-surface-2',
                      isSelected && 'bg-[var(--accent-tint)]',
                    )}
                  >
                    {selectable && (
                      <td className="w-9 px-3 py-2" onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          aria-label="Select row"
                          checked={isSelected}
                          onChange={() => toggleRow(key)}
                          className="accent-[var(--brand)]"
                        />
                      </td>
                    )}
                    {visibleColumns.map((c) => (
                      <td
                        key={c.id}
                        className={cn(
                          'px-3 py-2 align-middle text-text',
                          c.align === 'right' && 'text-right',
                          c.cellClassName,
                        )}
                      >
                        {c.cell(r)}
                      </td>
                    ))}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {!loading && !error && sorted.length > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border px-3 py-2">
          <p className="text-xs text-muted">
            {selected.size > 0 && (
              <span className="mr-2 font-medium text-text">{selected.size} selected</span>
            )}
            {sorted.length} row{sorted.length === 1 ? '' : 's'}
            {sorted.length !== rows.length && ` (of ${rows.length})`}
          </p>
          <div className="flex items-center gap-2">
            <Select
              aria-label="Rows per page"
              value={String(pageSize)}
              onChange={(e) => setPageSize(Number(e.target.value))}
              className="h-7 w-auto text-xs"
            >
              {[10, 25, 50, 100].map((n) => (
                <option key={n} value={n}>
                  {n} / page
                </option>
              ))}
            </Select>
            <div className="flex items-center gap-1">
              <Button
                variant="ghost"
                size="icon-sm"
                aria-label="Previous page"
                disabled={clampedPage === 0}
                onClick={() => setPage((p) => Math.max(0, p - 1))}
              >
                <ChevronLeft size={14} />
              </Button>
              <span className="min-w-16 text-center text-xs tabular-nums text-muted">
                {clampedPage + 1} / {pageCount}
              </span>
              <Button
                variant="ghost"
                size="icon-sm"
                aria-label="Next page"
                disabled={clampedPage >= pageCount - 1}
                onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
              >
                <ChevronRight size={14} />
              </Button>
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}
