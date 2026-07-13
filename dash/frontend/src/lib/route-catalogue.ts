import type { ComponentType } from 'react';
import {
  Activity as ActivityIcon,
  Building2,
  ClipboardCheck,
  Crosshair,
  FileText,
  HardDrive,
  History,
  LayoutDashboard,
  ListChecks,
  Network,
  PackageSearch,
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
import { AppliancesPage } from '../pages/AppliancesPage';
import { AssetsPage } from '../pages/AssetsPage';
import { ChangesPage } from '../pages/ChangesPage';
import { FeedsPage } from '../pages/FeedsPage';
import { FindingsPage } from '../pages/FindingsPage';
import { GettingStartedPage } from '../pages/GettingStartedPage';
import { HomeDashboard } from '../pages/HomeDashboard';
import { NetworksPage } from '../pages/NetworksPage';
import { NotificationsPage } from '../pages/NotificationsPage';
import { PentestPage } from '../pages/PentestPage';
import { PresetsPage } from '../pages/PresetsPage';
import { RemediationPage } from '../pages/RemediationPage';
import { ReportsPage } from '../pages/ReportsPage';
import { ScansPage } from '../pages/SchedulesPage';
import { SessionManagementPage } from '../pages/SessionManagementPage';
import { SecurityPage } from '../pages/SecurityPage';
import { SettingsPage } from '../pages/SettingsPage';
import { SitesPage } from '../pages/SitesPage';
import { SystemHealthPage } from '../pages/SystemHealthPage';
import { UsersPage } from '../pages/UsersPage';
import { IdentityProvidersPage } from '../pages/IdentityProvidersPage';
import { ScimProvisioningPage } from '../pages/ScimProvisioningPage';
import { AuthorizationPage } from '../pages/AuthorizationPage';
import { TaskOperationsPage } from '../pages/TaskOperationsPage';
import { AuthenticatedInventoryPage } from '../pages/AuthenticatedInventoryPage';
import { SlaTicketingPage } from '../pages/SlaTicketingPage';
import type { Role } from '../types/auth';

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
    ],
  },
];

export const ALL_ROUTES = ROUTE_CATALOGUE.flatMap((section) => section.items);
