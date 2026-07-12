import { useCallback, useEffect, useState, type ComponentType } from 'react';
import { api } from './api/client';
import { useAuth } from './auth/useAuth';
import { GlobalSearch } from './components/GlobalSearch';
import { Icon } from './components/Icon';
import { AddScoutPage } from './pages/AddScoutPage';
import { BackupCenterPage } from './pages/BackupCenterPage';
import { ChangesPage } from './pages/ChangesPage';
import { FeedsPage } from './pages/FeedsPage';
import { FindingsPage } from './pages/FindingsPage';
import { HealthPage } from './pages/HealthPage';
import { HelpPage } from './pages/HelpPage';
import { HomeDashboard } from './pages/HomeDashboard';
import { LoginPage } from './pages/LoginPage';
import { MaintenancePage } from './pages/MaintenancePage';
import { NetworkingPage } from './pages/NetworkingPage';
import { NetworksPage } from './pages/NetworksPage';
import { PentestPage } from './pages/PentestPage';
import { SchedulesPage } from './pages/SchedulesPage';
import { NotificationsPage } from './pages/NotificationsPage';
import { PrivacyPage } from './pages/PrivacyPage';
import { RelayPage } from './pages/RelayPage';
import { OnboardingWizard } from './pages/OnboardingWizard';
import { PresetsPage } from './pages/PresetsPage';
import { ReportsPage } from './pages/ReportsPage';
import { SitesPage } from './pages/SitesPage';
import { SystemHealthPage } from './pages/SystemHealthPage';
import { UpdateCenterPage } from './pages/UpdateCenterPage';
import type { OnboardingState } from './types/onboarding';

type NavItem = {
  id: string;
  label: string;
  sub: string;
  icon: string;
  Component: ComponentType;
};

const NAV: { group: string; items: NavItem[] }[] = [
  {
    group: 'Overview',
    items: [
      {
        id: 'overview',
        label: 'Overview',
        sub: 'What needs attention right now',
        icon: 'overview',
        Component: HomeDashboard,
      },
    ],
  },
  {
    group: 'Assessment',
    items: [
      {
        id: 'findings',
        label: 'Findings',
        sub: 'Tracked vulnerabilities across your assets',
        icon: 'findings',
        Component: FindingsPage,
      },
      {
        id: 'sites',
        label: 'Sites',
        sub: 'Locations and their network scopes',
        icon: 'sites',
        Component: SitesPage,
      },
      {
        id: 'networks',
        label: 'Networks',
        sub: 'Approved network ranges and scopes',
        icon: 'networks',
        Component: NetworksPage,
      },
      {
        id: 'schedules',
        label: 'Schedules',
        sub: 'Recurring scans',
        icon: 'schedules',
        Component: SchedulesPage,
      },
      {
        id: 'presets',
        label: 'Scan presets',
        sub: 'Scanner profiles and intensity',
        icon: 'presets',
        Component: PresetsPage,
      },
      {
        id: 'pentest',
        label: 'Pentest',
        sub: 'Controlled, approval-gated testing',
        icon: 'pentest',
        Component: PentestPage,
      },
    ],
  },
  {
    group: 'Fleet',
    items: [
      {
        id: 'scouts',
        label: 'Scouts',
        sub: 'Enroll and manage probes',
        icon: 'scouts',
        Component: AddScoutPage,
      },
      {
        id: 'relay',
        label: 'Relay',
        sub: 'Scanner-free egress endpoints',
        icon: 'relay',
        Component: RelayPage,
      },
      {
        id: 'networking',
        label: 'Networking',
        sub: 'Connectivity and interfaces',
        icon: 'networking',
        Component: NetworkingPage,
      },
    ],
  },
  {
    group: 'Intelligence',
    items: [
      {
        id: 'feeds',
        label: 'CVE feeds',
        sub: 'NVD, CISA KEV, and EPSS sync health',
        icon: 'feeds',
        Component: FeedsPage,
      },
      {
        id: 'reports',
        label: 'Reports',
        sub: 'Export findings and evidence',
        icon: 'reports',
        Component: ReportsPage,
      },
      {
        id: 'changes',
        label: 'Activity',
        sub: 'What changed and when',
        icon: 'changes',
        Component: ChangesPage,
      },
    ],
  },
  {
    group: 'System',
    items: [
      {
        id: 'system-health',
        label: 'System health',
        sub: 'Component and service status',
        icon: 'system-health',
        Component: SystemHealthPage,
      },
      {
        id: 'updates',
        label: 'Updates',
        sub: 'Version and upgrade center',
        icon: 'updates',
        Component: UpdateCenterPage,
      },
      {
        id: 'backups',
        label: 'Backups',
        sub: 'Snapshots and restore',
        icon: 'backups',
        Component: BackupCenterPage,
      },
      {
        id: 'notifications',
        label: 'Notifications',
        sub: 'Channels and delivery',
        icon: 'notifications',
        Component: NotificationsPage,
      },
      {
        id: 'maintenance',
        label: 'Maintenance',
        sub: 'Cleanup, retention, diagnostics',
        icon: 'maintenance',
        Component: MaintenancePage,
      },
      {
        id: 'privacy',
        label: 'Privacy',
        sub: 'Outbound data and secrets',
        icon: 'privacy',
        Component: PrivacyPage,
      },
      {
        id: 'help',
        label: 'Help',
        sub: 'Topics and exposure checklist',
        icon: 'help',
        Component: HelpPage,
      },
    ],
  },
];

const ALL_ITEMS = NAV.flatMap((g) => g.items);

function currentViewFromHash(): string {
  const id = window.location.hash.replace(/^#/, '');
  return ALL_ITEMS.some((i) => i.id === id) ? id : 'overview';
}

export function App() {
  const { user, token, initializing, logout } = useAuth();
  const [onboarding, setOnboarding] = useState<OnboardingState | null>(null);
  const [resume, setResume] = useState(false);
  const [view, setView] = useState<string>(currentViewFromHash());
  const [navOpen, setNavOpen] = useState(false);

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
    const onHash = () => setView(currentViewFromHash());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  const go = useCallback((id: string) => {
    window.location.hash = id;
    setView(id);
    setNavOpen(false);
  }, []);

  const incomplete = onboarding !== null && onboarding.completed_at === null;
  const showWizard = incomplete && (!onboarding?.dismissed || resume);

  if (initializing) {
    return (
      <div className="login-screen">
        <p className="detail">Loading…</p>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="login-screen">
        <div className="login-box">
          <div className="brand">
            <img src="/vulna-mark.svg" alt="" width={34} height={34} />
            <h1>
              Vulna<b>Dash</b>
            </h1>
          </div>
          <LoginPage />
          <div style={{ marginTop: '1.1rem' }}>
            <HealthPage />
          </div>
          <span className="tag">Self-hosted security assessment across every site.</span>
        </div>
      </div>
    );
  }

  const active = ALL_ITEMS.find((i) => i.id === view) ?? ALL_ITEMS[0];
  const ActivePage = active.Component;
  const initial = (user.email?.[0] ?? '?').toUpperCase();

  return (
    <div className={`app-shell${navOpen ? ' nav-open' : ''}`}>
      {navOpen && <div className="scrim" onClick={() => setNavOpen(false)} />}

      <aside className="sidebar">
        <div className="sidebar-brand">
          <img src="/vulna-mark.svg" alt="" width={26} height={26} />
          <span className="word">
            Vulna<b>Dash</b>
          </span>
        </div>

        <nav className="sidebar-nav" aria-label="Primary">
          {NAV.map((group) => (
            <div className="nav-group" key={group.group}>
              <div className="nav-group-label">{group.group}</div>
              {group.items.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  className={`nav-item${view === item.id ? ' active' : ''}`}
                  aria-current={view === item.id ? 'page' : undefined}
                  onClick={() => go(item.id)}
                >
                  <Icon name={item.icon} />
                  <span>{item.label}</span>
                </button>
              ))}
            </div>
          ))}
        </nav>

        <div className="sidebar-foot">
          <div className="avatar" aria-hidden="true">
            {initial}
          </div>
          <div className="who">
            <span className="email">{user.email}</span>
            <span className="role">{user.role}</span>
          </div>
          <button
            type="button"
            className="icon-btn"
            title="Sign out"
            aria-label="Sign out"
            onClick={logout}
          >
            <Icon name="logout" />
          </button>
        </div>
      </aside>

      <div className="main-col">
        <header className="topbar">
          <button
            type="button"
            className="icon-btn menu-btn"
            aria-label="Menu"
            onClick={() => setNavOpen((o) => !o)}
          >
            <Icon name="menu" />
          </button>
          <div className="crumb">
            <span className="crumb-title">{active.label}</span>
            <span className="sub">{active.sub}</span>
          </div>
          <div className="spacer" />
          {incomplete && onboarding?.dismissed && !resume && (
            <button type="button" className="btn ghost" onClick={() => setResume(true)}>
              Resume setup
            </button>
          )}
          <GlobalSearch />
        </header>

        <div className="content">
          <div className="content-inner">
            {showWizard && view === 'overview' && (
              <OnboardingWizard
                onFinished={() => {
                  setResume(false);
                  void loadOnboarding();
                }}
              />
            )}
            <ActivePage />
          </div>
        </div>
      </div>
    </div>
  );
}
