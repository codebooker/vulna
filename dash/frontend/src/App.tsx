import { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from './api/client';
import { useAuth } from './auth/useAuth';
import { Sidebar, type NavSectionDef } from './components/layout/sidebar';
import { Topbar } from './components/layout/topbar';
import { NavContext, hashFor, parseHash, type RouteParams } from './lib/nav';
import { ALL_ROUTES, ROUTE_CATALOGUE } from './lib/route-catalogue';
import { AccountSetupScreen } from './pages/AccountSetupPage';
import { LoginScreen } from './pages/LoginPage';
import type { Experience } from './types/experience';
import type { OnboardingState } from './types/onboarding';

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
  return ALL_ROUTES.some((i) => i.id === id) ? { id, params } : { id: 'overview', params: {} };
}

const SIDEBAR_KEY = 'vulnadash.sidebar-collapsed';

export function App() {
  const { user, token, initializing, logout } = useAuth();
  const [onboarding, setOnboarding] = useState<OnboardingState | null>(null);
  const [experience, setExperience] = useState<Experience | null>(null);
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

  const loadExperience = useCallback(async () => {
    if (!token) return;
    try {
      setExperience(await api.experience(token));
    } catch {
      // Fail open for discoverability: authorization still lives in the API.
      setExperience(null);
    }
  }, [token]);

  useEffect(() => {
    if (user && token) {
      void loadOnboarding();
      void loadExperience();
    }
  }, [user, token, loadOnboarding, loadExperience]);

  useEffect(() => {
    window.addEventListener('vulna-experience-changed', loadExperience);
    return () => window.removeEventListener('vulna-experience-changed', loadExperience);
  }, [loadExperience]);

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

  const publicRoute = parseHash(window.location.hash);
  if (publicRoute.id === 'accept-invitation') {
    return <AccountSetupScreen mode="invitation" token={publicRoute.params.token ?? null} />;
  }
  if (publicRoute.id === 'reset-password') {
    return <AccountSetupScreen mode="password-reset" token={publicRoute.params.token ?? null} />;
  }

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
  const section =
    ROUTE_CATALOGUE.find((item) => item.items.some((routeItem) => routeItem.id === route.id)) ??
    ROUTE_CATALOGUE[0];
  const active = ALL_ROUTES.find((item) => item.id === route.id) ?? ALL_ROUTES[0];
  const ActivePage = active.Component;
  const routeAllows = (item: (typeof ALL_ROUTES)[number]) => {
    if (user.permissions) {
      return !item.permission || user.permissions.includes(item.permission);
    }
    return !item.roles || item.roles.includes(user.role);
  };
  const isSmallBusiness = experience?.experience_profile === 'small_business';
  const regularSections: NavSectionDef[] = ROUTE_CATALOGUE.map((catalogueSection) => ({
    id: catalogueSection.id,
    label: catalogueSection.label,
    items: catalogueSection.items
      .filter(routeAllows)
      .filter((item) => item.id !== 'getting-started' || incomplete)
      .filter((item) => {
        if (item.id === 'getting-started' || !experience) return true;
        return experience.route_visibility[item.visibilityKey] !== false;
      })
      .map(({ id, label, icon }) => ({ id, label, icon })),
  })).filter((catalogueSection) => catalogueSection.items.length > 0);

  const advancedItems = isSmallBusiness
    ? ALL_ROUTES.filter(routeAllows)
        .filter((item) => item.id !== 'getting-started')
        .filter((item) => experience?.route_visibility[item.visibilityKey] === false)
        .map(({ id, label, icon }) => ({ id, label, icon }))
    : [];
  const sections: NavSectionDef[] = [
    ...regularSections,
    ...(advancedItems.length > 0
      ? [{ id: 'advanced', label: 'Advanced', items: advancedItems, collapsible: true }]
      : []),
  ];

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
          userEmail={user.email ?? user.full_name ?? 'Service account'}
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
