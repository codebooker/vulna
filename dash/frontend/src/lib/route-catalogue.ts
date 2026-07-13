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
  Network,
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
import type { Role } from '../types/auth';

export interface RouteDef {
  id: string;
  visibilityKey: string;
  label: string;
  icon: LucideIcon;
  Component: ComponentType;
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
      },
      {
        id: 'assets',
        visibilityKey: 'assets',
        label: 'Assets',
        icon: Server,
        Component: AssetsPage,
      },
      {
        id: 'findings',
        visibilityKey: 'findings',
        label: 'Findings',
        icon: ShieldAlert,
        Component: FindingsPage,
      },
      { id: 'scans', visibilityKey: 'scans', label: 'Scans', icon: Radar, Component: ScansPage },
      {
        id: 'sites',
        visibilityKey: 'sites',
        label: 'Sites',
        icon: Building2,
        Component: SitesPage,
      },
      {
        id: 'changes',
        visibilityKey: 'changes',
        label: 'Activity',
        icon: History,
        Component: ChangesPage,
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
      },
      {
        id: 'reports',
        visibilityKey: 'reports',
        label: 'Reports',
        icon: FileText,
        Component: ReportsPage,
      },
      {
        id: 'appliances',
        visibilityKey: 'appliances',
        label: 'Appliances',
        icon: HardDrive,
        Component: AppliancesPage,
      },
      {
        id: 'networks',
        visibilityKey: 'networks',
        label: 'Networks',
        icon: Network,
        Component: NetworksPage,
      },
      {
        id: 'presets',
        visibilityKey: 'presets',
        label: 'Scan presets',
        icon: SlidersHorizontal,
        Component: PresetsPage,
      },
      {
        id: 'pentest',
        visibilityKey: 'pentest',
        label: 'Pentest',
        icon: Crosshair,
        Component: PentestPage,
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
        roles: ['administrator'],
      },
      {
        id: 'identity',
        visibilityKey: 'identity',
        label: 'Identity & SSO',
        icon: KeyRound,
        Component: IdentityProvidersPage,
        roles: ['administrator'],
      },
      {
        id: 'provisioning',
        visibilityKey: 'provisioning',
        label: 'Provisioning',
        icon: UserRoundPlus,
        Component: ScimProvisioningPage,
        roles: ['administrator'],
      },
      {
        id: 'sessions',
        visibilityKey: 'settings',
        label: 'Sessions',
        icon: Smartphone,
        Component: SessionManagementPage,
      },
      {
        id: 'security',
        visibilityKey: 'settings',
        label: 'Security',
        icon: ShieldCheck,
        Component: SecurityPage,
      },
      { id: 'feeds', visibilityKey: 'feeds', label: 'CVE feeds', icon: Rss, Component: FeedsPage },
      {
        id: 'notifications',
        visibilityKey: 'notifications',
        label: 'Integrations',
        icon: Webhook,
        Component: NotificationsPage,
      },
      {
        id: 'settings',
        visibilityKey: 'settings',
        label: 'Settings',
        icon: SettingsIcon,
        Component: SettingsPage,
      },
      {
        id: 'system-health',
        visibilityKey: 'system_health',
        label: 'System health',
        icon: ActivityIcon,
        Component: SystemHealthPage,
      },
      {
        id: 'getting-started',
        visibilityKey: 'getting_started',
        label: 'Getting started',
        icon: Rocket,
        Component: GettingStartedPage,
      },
    ],
  },
];

export const ALL_ROUTES = ROUTE_CATALOGUE.flatMap((section) => section.items);
