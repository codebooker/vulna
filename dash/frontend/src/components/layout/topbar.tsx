import { ChevronRight, Menu as MenuIcon, Moon, Rocket, Sun } from 'lucide-react';
import { useTheme } from '../../lib/theme';
import { Button } from '../ui/button';
import { Tooltip } from '../ui/menu';
import { GlobalSearch } from '../GlobalSearch';

export function Topbar({
  sectionLabel,
  pageLabel,
  onOpenMobileNav,
  showResumeSetup,
  onResumeSetup,
}: {
  sectionLabel: string;
  pageLabel: string;
  onOpenMobileNav: () => void;
  showResumeSetup: boolean;
  onResumeSetup: () => void;
}) {
  const { theme, toggle } = useTheme();
  return (
    <header className="sticky top-0 z-30 flex h-14 shrink-0 items-center gap-3 border-b border-border bg-surface/90 px-4 backdrop-blur">
      <Button
        variant="ghost"
        size="icon"
        aria-label="Open navigation"
        className="lg:hidden"
        onClick={onOpenMobileNav}
      >
        <MenuIcon size={17} />
      </Button>

      <nav
        aria-label="Breadcrumb"
        className="hidden min-w-0 items-center gap-1 text-[13px] sm:flex"
      >
        <span className="text-faint">{sectionLabel}</span>
        <ChevronRight size={13} aria-hidden className="text-faint" />
        <span className="truncate font-semibold text-text">{pageLabel}</span>
      </nav>
      <span className="truncate text-sm font-semibold text-text sm:hidden">{pageLabel}</span>

      <div className="ml-auto flex items-center gap-2">
        {showResumeSetup && (
          <Button variant="outline" size="sm" onClick={onResumeSetup}>
            <Rocket size={13} aria-hidden />
            <span className="hidden sm:inline">Resume setup</span>
          </Button>
        )}
        <div className="hidden md:block">
          <GlobalSearch />
        </div>
        <Tooltip label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}>
          <Button variant="ghost" size="icon" aria-label="Toggle theme" onClick={toggle}>
            {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
          </Button>
        </Tooltip>
      </div>
    </header>
  );
}
