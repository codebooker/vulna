import { useCallback, useEffect, useMemo, useState, type ComponentType } from 'react';
import {
  Activity as ActivityIcon,
  Building2,
  ClipboardCheck,
  Crosshair,
  FileText,
  HardDrive,
  History,
  LayoutDashboard,
  Network,
  Radar,
  Rocket,
  Rss,
  Server,
  Settings as SettingsIcon,
  ShieldAlert,
  SlidersHorizontal,
  Webhook,
} from 'lucide-react';
import { api } from './api/client';
import { useAuth } from './auth/useAuth';
import { Sidebar, type NavSectionDef } from './components/layout/sidebar';
import { Topbar } from './components/layout/topbar';
import { NavContext, hashFor, parseHash, type RouteParams } from './lib/nav';
import { AssetsPage } from './pages/AssetsPage';
import { ChangesPage } from './pages/ChangesPage';
import { AppliancesPage } from './pages/AppliancesPage';
import { FeedsPage } from './pages/FeedsPage';
import { FindingsPage } from './pages/FindingsPage';
import { GettingStartedPage } from './pages/GettingStartedPage';
import { HomeDashboard } from './pages/HomeDashboard';
import { LoginScreen } from './pages/LoginPage';
import { NetworksPage } from './pages/NetworksPage';
import { NotificationsPage } from './pages/NotificationsPage';
import { PentestPage } from './pages/PentestPage';
import { PresetsPage } from './pages/PresetsPage';
import { RemediationPage } from './pages/RemediationPage';
import { ReportsPage } from './pages/ReportsPage';
import { ScansPage } from './pages/SchedulesPage';
import { SettingsPage } from './pages/SettingsPage';
import { SitesPage } from './pages/SitesPage';
import { SystemHealthPage } from './pages/SystemHealthPage';
import type { OnboardingState } from './types/onboarding';

interface RouteDef {
  id: string;
  label: string;
  icon: typeof LayoutDashboard;
  Component: ComponentType;
}

interface SectionDef {
  id: string;
  label: string;
  items: RouteDef[];
}

const NAV: SectionDef[] = [
  {
    id: 'operations',
    label: 'Operations',
    items: [
      { id: 'overview', label: 'Overview', icon: LayoutDashboard, Component: HomeDashboard },
      { id: 'assets', label: 'Assets', icon: Server, Component: AssetsPage },
      { id: 'findings', label: 'Findings', icon: ShieldAlert, Component: FindingsPage },
      { id: 'scans', label: 'Scans', icon: Radar, Component: ScansPage },
      { id: 'sites', label: 'Sites', icon: Building2, Component: SitesPage },
      { id: 'changes', label: 'Activity', icon: History, Component: ChangesPage },
    ],
  },
  {
    id: 'management',
    label: 'Management',
    items: [
      { id: 'remediation', label: 'Remediation', icon: ClipboardCheck, Component: RemediationPage },
      { id: 'reports', label: 'Reports', icon: FileText, Component: ReportsPage },
      { id: 'appliances', label: 'Appliances', icon: HardDrive, Component: AppliancesPage },
      { id: 'networks', label: 'Networks', icon: Network, Component: NetworksPage },
      { id: 'presets', label: 'Scan presets', icon: SlidersHorizontal, Component: PresetsPage },
      { id: 'pentest', label: 'Pentest', icon: Crosshair, Component: PentestPage },
    ],
  },
  {
    id: 'administration',
    label: 'Administration',
    items: [
      { id: 'feeds', label: 'CVE feeds', icon: Rss, Component: FeedsPage },
      { id: 'notifications', label: 'Integrations', icon: Webhook, Component: NotificationsPage },
      { id: 'settings', label: 'Settings', icon: SettingsIcon, Component: SettingsPage },
      {
        id: 'system-health',
        label: 'System health',
        icon: ActivityIcon,
        Component: SystemHealthPage,
      },
      {
        id: 'getting-started',
        label: 'Getting started',
        icon: Rocket,
        Component: GettingStartedPage,
      },
    ],
  },
];

const ALL_ITEMS = NAV.flatMap((s) => s.items);

/** Legacy hash ids continue to work and land on the equivalent redesigned view. */
const ALIASES: Record<string, { id: string; params?: RouteParams }> = {
  schedules: { id: 'scans' },
  scouts: { id: 'appliances', params: { tab: 'scouts' } },
  relay: { id: 'appliances', params: { tab: 'relay' } },
  networking: { id: 'settings', params: { section: 'networking' } },
  updates: { id: 'settings', params: { section: 'updates' } },
  backups: { id: 'settings', params: { section: 'backups' } },
  maintenance: { id: 'settings', params: { section: 'maintenance' } },
  privacy: { id: 'settings', params: { section: 'privacy' } },
  help: { id: 'settings', params: { section: 'help' } },
};

function resolveRoute(hash: string): { id: string; params: RouteParams } {
  const { id, params } = parseHash(hash);
  const alias = ALIASES[id];
  if (alias) return { id: alias.id, params: { ...alias.params, ...params } };
  return ALL_ITEMS.some((i) => i.id === id) ? { id, params } : { id: 'overview', params: {} };
}

const SIDEBAR_KEY = 'vulnadash.sidebar-collapsed';

export function App() {
  const { user, token, initializing, logout } = useAuth();
  const [onboarding, setOnboarding] = useState<OnboardingState | null>(null);
  const [route, setRoute] = useState(() => resolveRoute(window.location.hash));
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem(SIDEBAR_KEY) === '1';
    } catch {
      return false;
    }
  });

  const loadOnboarding = useCallback(async () => {
    if (!token) return;
    try {
      setOnboarding(await api.onboardingState(token));
    } catch {
      setOnboarding(null);
    }
  }, [token]);

  useEffect(() => {
    if (user && token) void loadOnboarding();
  }, [user, token, loadOnboarding]);

  useEffect(() => {
    const onHash = () => setRoute(resolveRoute(window.location.hash));
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  const go = useCallback((id: string, params?: RouteParams) => {
    window.location.hash = hashFor(id, params);
    setRoute(resolveRoute(hashFor(id, params)));
    setMobileNavOpen(false);
  }, []);

  const navValue = useMemo(() => ({ current: route, go }), [route, go]);

  const toggleCollapsed = useCallback(() => {
    setCollapsed((c) => {
      try {
        localStorage.setItem(SIDEBAR_KEY, c ? '0' : '1');
      } catch {
        // ignore
      }
      return !c;
    });
  }, []);

  if (initializing) {
    return (
      <div className="flex h-screen items-center justify-center bg-bg">
        <p className="text-sm text-muted">Loading…</p>
      </div>
    );
  }

  if (!user) {
    return <LoginScreen />;
  }

  const incomplete = onboarding !== null && onboarding.completed_at === null;
  const section = NAV.find((s) => s.items.some((i) => i.id === route.id)) ?? NAV[0];
  const active = ALL_ITEMS.find((i) => i.id === route.id) ?? ALL_ITEMS[0];
  const ActivePage = active.Component;

  const sections: NavSectionDef[] = NAV.map((s) => ({
    id: s.id,
    label: s.label,
    // Hide "Getting started" from the sidebar once setup is complete;
    // the route itself keeps working.
    items: s.items
      .filter((i) => i.id !== 'getting-started' || incomplete)
      .map(({ id, label, icon }) => ({ id, label, icon })),
  }));

  return (
    <NavContext.Provider value={navValue}>
      <div className="flex min-h-screen bg-bg text-text">
        <Sidebar
          sections={sections}
          currentId={active.id}
          onNavigate={go}
          collapsed={collapsed}
          onToggleCollapsed={toggleCollapsed}
          mobileOpen={mobileNavOpen}
          onCloseMobile={() => setMobileNavOpen(false)}
          userEmail={user.email}
          userRole={user.role}
          onLogout={logout}
        />
        <div className="flex min-w-0 flex-1 flex-col">
          <Topbar
            sectionLabel={section.label}
            pageLabel={active.label}
            onOpenMobileNav={() => setMobileNavOpen(true)}
            showResumeSetup={incomplete && active.id !== 'getting-started'}
            onResumeSetup={() => go('getting-started')}
          />
          <main className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-4 sm:px-6 sm:py-5">
            <div key={`${active.id}`} className="vd-fade-in">
              <ActivePage />
            </div>
          </main>
        </div>
      </div>
    </NavContext.Provider>
  );
}
