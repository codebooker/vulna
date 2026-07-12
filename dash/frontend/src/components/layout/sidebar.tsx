import type { LucideIcon } from 'lucide-react';
import { LogOut, PanelLeftClose, PanelLeftOpen } from 'lucide-react';
import { cn } from '../../lib/utils';
import { Tooltip } from '../ui/menu';

export interface NavItemDef {
  id: string;
  label: string;
  icon: LucideIcon;
}

export interface NavSectionDef {
  id: string;
  label: string;
  items: NavItemDef[];
}

export function Sidebar({
  sections,
  currentId,
  onNavigate,
  collapsed,
  onToggleCollapsed,
  mobileOpen,
  onCloseMobile,
  userEmail,
  userRole,
  onLogout,
}: {
  sections: NavSectionDef[];
  currentId: string;
  onNavigate: (id: string) => void;
  collapsed: boolean;
  onToggleCollapsed: () => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
  userEmail: string;
  userRole: string;
  onLogout: () => void;
}) {
  const initial = (userEmail[0] ?? '?').toUpperCase();

  const nav = (
    <div className="flex h-full flex-col">
      {/* Brand */}
      <div
        className={cn(
          'flex h-14 shrink-0 items-center gap-2.5 border-b border-nav-border px-4',
          collapsed && 'justify-center px-0',
        )}
      >
        <img src="/vulna-mark.svg" alt="" width={24} height={24} className="shrink-0" />
        {!collapsed && (
          <span className="truncate text-[15px] font-bold text-nav-text-strong">
            Vulna<span className="text-accent">Dash</span>
          </span>
        )}
      </div>

      {/* Sections */}
      <nav aria-label="Primary" className="slim-scroll flex-1 overflow-y-auto px-2 py-3">
        {sections.map((section) => (
          <div key={section.id} className="mb-4 last:mb-0">
            {!collapsed && (
              <p className="mb-1 px-2 text-[10px] font-semibold uppercase tracking-[0.12em] text-nav-text/60">
                {section.label}
              </p>
            )}
            {collapsed && <div className="mx-2 mb-2 h-px bg-nav-border first:hidden" />}
            <ul className="flex flex-col gap-0.5">
              {section.items.map((item) => {
                const active = item.id === currentId;
                const btn = (
                  <button
                    type="button"
                    aria-current={active ? 'page' : undefined}
                    onClick={() => {
                      onNavigate(item.id);
                      onCloseMobile();
                    }}
                    className={cn(
                      'group flex w-full items-center gap-2.5 rounded-lg px-2 py-1.5 text-[13px] transition-colors',
                      collapsed && 'justify-center px-0 py-2',
                      active
                        ? 'bg-nav-active font-semibold text-nav-text-strong'
                        : 'text-nav-text hover:bg-nav-surface hover:text-nav-text-strong',
                    )}
                  >
                    <item.icon
                      size={16}
                      aria-hidden
                      className={cn(
                        'shrink-0',
                        active ? 'text-accent' : 'text-nav-text/70 group-hover:text-nav-text',
                      )}
                    />
                    {!collapsed && <span className="truncate">{item.label}</span>}
                    {active && !collapsed && (
                      <span aria-hidden className="ml-auto h-1.5 w-1.5 rounded-full bg-accent" />
                    )}
                  </button>
                );
                return (
                  <li key={item.id}>
                    {collapsed ? <Tooltip label={item.label}>{btn}</Tooltip> : btn}
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      {/* Footer: user + collapse */}
      <div className="shrink-0 border-t border-nav-border p-2">
        <div
          className={cn(
            'flex items-center gap-2.5 rounded-lg px-2 py-1.5',
            collapsed && 'justify-center px-0',
          )}
        >
          <span
            aria-hidden
            className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-[var(--accent-tint)] text-xs font-bold text-accent"
          >
            {initial}
          </span>
          {!collapsed && (
            <span className="min-w-0 flex-1">
              <span className="block truncate text-xs font-medium text-nav-text-strong">
                {userEmail}
              </span>
              <span className="block truncate text-[10px] capitalize text-nav-text/60">
                {userRole.replace(/_/g, ' ')}
              </span>
            </span>
          )}
          {!collapsed && (
            <button
              type="button"
              title="Sign out"
              aria-label="Sign out"
              onClick={onLogout}
              className="rounded-md p-1.5 text-nav-text/70 hover:bg-nav-surface hover:text-nav-text-strong"
            >
              <LogOut size={14} />
            </button>
          )}
        </div>
        <button
          type="button"
          onClick={onToggleCollapsed}
          className={cn(
            'mt-1 hidden w-full items-center gap-2 rounded-lg px-2 py-1.5 text-xs text-nav-text/70 hover:bg-nav-surface hover:text-nav-text-strong lg:flex',
            collapsed && 'justify-center px-0',
          )}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? (
            <PanelLeftOpen size={15} aria-hidden />
          ) : (
            <PanelLeftClose size={15} aria-hidden />
          )}
          {!collapsed && 'Collapse'}
        </button>
      </div>
    </div>
  );

  return (
    <>
      {/* Mobile scrim */}
      {mobileOpen && (
        <div
          className="vd-fade-in fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={onCloseMobile}
          aria-hidden
        />
      )}
      {/* Mobile drawer (mounted only while open so nav landmarks stay unique) */}
      {mobileOpen && (
        <aside className="vd-slide-in-right fixed inset-y-0 left-0 z-40 w-64 bg-nav-bg lg:hidden">
          {nav}
        </aside>
      )}
      {/* Desktop sidebar */}
      <aside
        className={cn(
          'sticky top-0 hidden h-screen shrink-0 border-r border-nav-border bg-nav-bg lg:block',
          collapsed ? 'w-14' : 'w-56',
        )}
      >
        {nav}
      </aside>
    </>
  );
}
