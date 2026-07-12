import { useEffect, useState } from 'react';
import {
  Archive,
  DownloadCloud,
  Eraser,
  Globe,
  HelpCircle,
  Lock,
  type LucideIcon,
} from 'lucide-react';
import { useNav } from '../lib/nav';
import { cn } from '../lib/utils';
import { PageHeader } from '../components/app/page-header';
import { Select } from '../components/ui/input';
import { BackupCenterPage } from './BackupCenterPage';
import { HelpPage } from './HelpPage';
import { MaintenancePage } from './MaintenancePage';
import { NetworkingPage } from './NetworkingPage';
import { PrivacyPage } from './PrivacyPage';
import { UpdateCenterPage } from './UpdateCenterPage';

interface SettingsSection {
  id: string;
  label: string;
  icon: LucideIcon;
  Component: React.ComponentType;
}

const SECTIONS: SettingsSection[] = [
  { id: 'networking', label: 'Networking & access', icon: Globe, Component: NetworkingPage },
  { id: 'updates', label: 'Updates', icon: DownloadCloud, Component: UpdateCenterPage },
  { id: 'backups', label: 'Backups', icon: Archive, Component: BackupCenterPage },
  { id: 'maintenance', label: 'Data retention', icon: Eraser, Component: MaintenancePage },
  { id: 'privacy', label: 'Privacy', icon: Lock, Component: PrivacyPage },
  { id: 'help', label: 'Help & demo', icon: HelpCircle, Component: HelpPage },
];

/** Settings hub: a vertical section menu instead of one long page. Legacy
 *  hashes (#networking, #updates, #backups, #maintenance, #privacy, #help)
 *  land here with the matching section active. */
export function SettingsPage() {
  const { current, go } = useNav();
  const requested = current.params.section;
  const [active, setActive] = useState(
    SECTIONS.some((s) => s.id === requested) ? (requested as string) : 'networking',
  );

  useEffect(() => {
    if (requested && SECTIONS.some((s) => s.id === requested)) setActive(requested);
  }, [requested]);

  const section = SECTIONS.find((s) => s.id === active) ?? SECTIONS[0];
  const Active = section.Component;

  const select = (id: string) => {
    setActive(id);
    go('settings', { section: id });
  };

  return (
    <div aria-label="Settings">
      <PageHeader
        crumbs={[{ label: 'Administration' }, { label: 'Settings' }, { label: section.label }]}
        title="Settings"
        description="System configuration, grouped so nothing lives on one endless page."
      />

      {/* Mobile: dropdown selector */}
      <div className="mb-4 lg:hidden">
        <Select
          aria-label="Settings section"
          value={active}
          onChange={(e) => select(e.target.value)}
        >
          {SECTIONS.map((s) => (
            <option key={s.id} value={s.id}>
              {s.label}
            </option>
          ))}
        </Select>
      </div>

      <div className="flex gap-6">
        {/* Desktop: vertical menu */}
        <nav aria-label="Settings sections" className="hidden w-52 shrink-0 lg:block">
          <ul className="sticky top-20 flex flex-col gap-0.5">
            {SECTIONS.map((s) => (
              <li key={s.id}>
                <button
                  type="button"
                  aria-current={s.id === active ? 'page' : undefined}
                  onClick={() => select(s.id)}
                  className={cn(
                    'flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-[13px] transition-colors',
                    s.id === active
                      ? 'bg-[var(--accent-tint)] font-semibold text-accent-strong'
                      : 'text-muted hover:bg-surface-2 hover:text-text',
                  )}
                >
                  <s.icon size={15} aria-hidden className="shrink-0" />
                  {s.label}
                </button>
              </li>
            ))}
          </ul>
        </nav>

        <div className="min-w-0 flex-1">
          <div key={active} className="vd-fade-in">
            <Active />
          </div>
        </div>
      </div>
    </div>
  );
}
