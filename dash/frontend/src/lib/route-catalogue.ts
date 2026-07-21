import { lazy, type ComponentType } from 'react';
import {
  Activity as ActivityIcon,
  Building2,
  ClipboardCheck,
  Crosshair,
  FileText,
  HardDrive,
  HelpCircle,
  History,
  LayoutDashboard,
  ListChecks,
  Network,
  PackageSearch,
  DatabaseZap,
  TimerReset,
  Radar,
  Rocket,
  Rss,
  Server,
  Smartphone,
  Settings as SettingsIcon,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  UserRoundCog,
  KeyRound,
  UserRoundPlus,
  Webhook,
  type LucideIcon,
} from 'lucide-react';
import type { Role } from '../types/auth';

const AppliancesPage = lazy(() =>
  import('../pages/AppliancesPage').then((module) => ({ default: module.AppliancesPage })),
);
const AssetsPage = lazy(() =>
  import('../pages/AssetsPage').then((module) => ({ default: module.AssetsPage })),
);
const ChangesPage = lazy(() =>
  import('../pages/ChangesPage').then((module) => ({ default: module.ChangesPage })),
);
const FeedsPage = lazy(() =>
  import('../pages/FeedsPage').then((module) => ({ default: module.FeedsPage })),
);
const FindingsPage = lazy(() =>
  import('../pages/FindingsPage').then((module) => ({ default: module.FindingsPage })),
);
const GettingStartedPage = lazy(() =>
  import('../pages/GettingStartedPage').then((module) => ({ default: module.GettingStartedPage })),
);
const HomeDashboard = lazy(() =>
  import('../pages/HomeDashboard').then((module) => ({ default: module.HomeDashboard })),
);
const NetworksPage = lazy(() =>
  import('../pages/NetworksPage').then((module) => ({ default: module.NetworksPage })),
);
const NotificationsPage = lazy(() =>
  import('../pages/NotificationsPage').then((module) => ({ default: module.NotificationsPage })),
);
const PentestPage = lazy(() =>
  import('../pages/PentestPage').then((module) => ({ default: module.PentestPage })),
);
const PresetsPage = lazy(() =>
  import('../pages/PresetsPage').then((module) => ({ default: module.PresetsPage })),
);
const RemediationPage = lazy(() =>
  import('../pages/RemediationPage').then((module) => ({ default: module.RemediationPage })),
);
const ReportsPage = lazy(() =>
  import('../pages/ReportsPage').then((module) => ({ default: module.ReportsPage })),
);
const ScansPage = lazy(() =>
  import('../pages/SchedulesPage').then((module) => ({ default: module.ScansPage })),
);
const SessionManagementPage = lazy(() =>
  import('../pages/SessionManagementPage').then((module) => ({
    default: module.SessionManagementPage,
  })),
);
const SecurityPage = lazy(() =>
  import('../pages/SecurityPage').then((module) => ({ default: module.SecurityPage })),
);
const SettingsPage = lazy(() =>
  import('../pages/SettingsPage').then((module) => ({ default: module.SettingsPage })),
);
const SitesPage = lazy(() =>
  import('../pages/SitesPage').then((module) => ({ default: module.SitesPage })),
);
const SystemHealthPage = lazy(() =>
  import('../pages/SystemHealthPage').then((module) => ({ default: module.SystemHealthPage })),
);
const UsersPage = lazy(() =>
  import('../pages/UsersPage').then((module) => ({ default: module.UsersPage })),
);
const IdentityProvidersPage = lazy(() =>
  import('../pages/IdentityProvidersPage').then((module) => ({
    default: module.IdentityProvidersPage,
  })),
);
const ScimProvisioningPage = lazy(() =>
  import('../pages/ScimProvisioningPage').then((module) => ({
    default: module.ScimProvisioningPage,
  })),
);
const AuthorizationPage = lazy(() =>
  import('../pages/AuthorizationPage').then((module) => ({ default: module.AuthorizationPage })),
);
const TaskOperationsPage = lazy(() =>
  import('../pages/TaskOperationsPage').then((module) => ({ default: module.TaskOperationsPage })),
);
const AuthenticatedInventoryPage = lazy(() =>
  import('../pages/AuthenticatedInventoryPage').then((module) => ({
    default: module.AuthenticatedInventoryPage,
  })),
);
const SlaTicketingPage = lazy(() =>
  import('../pages/SlaTicketingPage').then((module) => ({ default: module.SlaTicketingPage })),
);
const PassiveInventoryPage = lazy(() =>
  import('../pages/PassiveInventoryPage').then((module) => ({
    default: module.PassiveInventoryPage,
  })),
);
const HelpPage = lazy(() =>
  import('../pages/HelpPage').then((module) => ({ default: module.HelpPage })),
);

export interface RouteDef {
  id: string;
  visibilityKey: string;
  label: string;
  icon: LucideIcon;
  Component: ComponentType;
  permission?: string;
  roles?: Role[];
}

export interface RouteSection {
  id: string;
  label: string;
  items: RouteDef[];
}

export const ROUTE_CATALOGUE: RouteSection[] = [
  {
    id: 'operations',
    label: 'Operations',
    items: [
      {
        id: 'overview',
        visibilityKey: 'overview',
        label: 'Overview',
        icon: LayoutDashboard,
        Component: HomeDashboard,
        permission: 'assets.read',
      },
      {
        id: 'assets',
        visibilityKey: 'assets',
        label: 'Assets',
        icon: Server,
        Component: AssetsPage,
        permission: 'assets.read',
      },
      {
        id: 'findings',
        visibilityKey: 'findings',
        label: 'Findings',
        icon: ShieldAlert,
        Component: FindingsPage,
        permission: 'findings.read',
      },
      {
        id: 'scans',
        visibilityKey: 'scans',
        label: 'Scans',
        icon: Radar,
        Component: ScansPage,
        permission: 'jobs.read',
      },
      {
        id: 'sites',
        visibilityKey: 'sites',
        label: 'Sites',
        icon: Building2,
        Component: SitesPage,
        permission: 'sites.read',
      },
      {
        id: 'changes',
        visibilityKey: 'changes',
        label: 'Activity',
        icon: History,
        Component: ChangesPage,
        permission: 'assets.read',
      },
    ],
  },
  {
    id: 'management',
    label: 'Management',
    items: [
      {
        id: 'remediation',
        visibilityKey: 'remediation',
        label: 'Remediation',
        icon: ClipboardCheck,
        Component: RemediationPage,
        permission: 'remediation.read',
      },
      {
        id: 'reports',
        visibilityKey: 'reports',
        label: 'Reports',
        icon: FileText,
        Component: ReportsPage,
        permission: 'reports.read',
      },
      {
        id: 'appliances',
        visibilityKey: 'appliances',
        label: 'Appliances',
        icon: HardDrive,
        Component: AppliancesPage,
        permission: 'scouts.read',
      },
      {
        id: 'authenticated-inventory',
        visibilityKey: 'authenticated_inventory',
        label: 'Authenticated inventory',
        icon: PackageSearch,
        Component: AuthenticatedInventoryPage,
        permission: 'credentials.read',
      },
      {
        id: 'inventory-intelligence',
        visibilityKey: 'passive_inventory',
        label: 'Inventory intelligence',
        icon: DatabaseZap,
        Component: PassiveInventoryPage,
        permission: 'analytics.read',
      },
      {
        id: 'sla-ticketing',
        visibilityKey: 'ticketing',
        label: 'SLAs & ticketing',
        icon: TimerReset,
        Component: SlaTicketingPage,
        permission: 'sla.read',
      },
      {
        id: 'networks',
        visibilityKey: 'networks',
        label: 'Networks',
        icon: Network,
        Component: NetworksPage,
        permission: 'networks.read',
      },
      {
        id: 'presets',
        visibilityKey: 'presets',
        label: 'Scan presets',
        icon: SlidersHorizontal,
        Component: PresetsPage,
        permission: 'presets.read',
      },
      {
        id: 'pentest',
        visibilityKey: 'pentest',
        label: 'Pentest',
        icon: Crosshair,
        Component: PentestPage,
        permission: 'pentest.read',
      },
    ],
  },
  {
    id: 'administration',
    label: 'Administration',
    items: [
      {
        id: 'users',
        visibilityKey: 'users',
        label: 'Users',
        icon: UserRoundCog,
        Component: UsersPage,
        permission: 'users.read',
        roles: ['administrator'],
      },
      {
        id: 'identity',
        visibilityKey: 'identity',
        label: 'Identity & SSO',
        icon: KeyRound,
        Component: IdentityProvidersPage,
        permission: 'identity.manage',
        roles: ['administrator'],
      },
      {
        id: 'provisioning',
        visibilityKey: 'provisioning',
        label: 'Provisioning',
        icon: UserRoundPlus,
        Component: ScimProvisioningPage,
        permission: 'scim.manage',
        roles: ['administrator'],
      },
      {
        id: 'authorization',
        visibilityKey: 'authorization',
        label: 'Authorization',
        icon: ShieldCheck,
        Component: AuthorizationPage,
        permission: 'roles.manage',
        roles: ['administrator'],
      },
      {
        id: 'sessions',
        visibilityKey: 'settings',
        label: 'Sessions',
        icon: Smartphone,
        Component: SessionManagementPage,
        permission: 'sessions.self',
      },
      {
        id: 'security',
        visibilityKey: 'settings',
        label: 'Security',
        icon: ShieldCheck,
        Component: SecurityPage,
        permission: 'identity.self',
      },
      {
        id: 'feeds',
        visibilityKey: 'feeds',
        label: 'CVE feeds',
        icon: Rss,
        Component: FeedsPage,
        permission: 'feeds.read',
      },
      {
        id: 'notifications',
        visibilityKey: 'notifications',
        label: 'Integrations',
        icon: Webhook,
        Component: NotificationsPage,
        permission: 'notifications.read',
      },
      {
        id: 'settings',
        visibilityKey: 'settings',
        label: 'Settings',
        icon: SettingsIcon,
        Component: SettingsPage,
        permission: 'organization.manage',
      },
      {
        id: 'system-health',
        visibilityKey: 'system_health',
        label: 'System health',
        icon: ActivityIcon,
        Component: SystemHealthPage,
        permission: 'system.read',
      },
      {
        id: 'tasks',
        visibilityKey: 'tasks',
        label: 'Task operations',
        icon: ListChecks,
        Component: TaskOperationsPage,
        permission: 'tasks.read',
        roles: ['administrator'],
      },
      {
        id: 'getting-started',
        visibilityKey: 'getting_started',
        label: 'Getting started',
        icon: Rocket,
        Component: GettingStartedPage,
        permission: 'onboarding.read',
      },
      {
        id: 'help',
        visibilityKey: 'help',
        label: 'Help',
        icon: HelpCircle,
        Component: HelpPage,
      },
    ],
  },
];

export const ALL_ROUTES = ROUTE_CATALOGUE.flatMap((section) => section.items);
