/** Inline stroke icons (Lucide-style, currentColor). No icon dependency: this is
 *  a self-hosted appliance UI that must build and run offline. */
import type { JSX } from 'react';

const P: Record<string, JSX.Element> = {
  overview: (
    <>
      <rect x="3" y="3" width="7" height="9" rx="1" />
      <rect x="14" y="3" width="7" height="5" rx="1" />
      <rect x="14" y="12" width="7" height="9" rx="1" />
      <rect x="3" y="16" width="7" height="5" rx="1" />
    </>
  ),
  findings: (
    <>
      <path d="M12 3l8 4v5c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V7z" />
      <path d="M12 8v4" />
      <path d="M12 15.5v.01" />
    </>
  ),
  sites: (
    <>
      <path d="M4 21V7l6-4 6 4v14" />
      <path d="M16 11h4v10H4" />
      <path d="M9 9v.01M9 13v.01M9 17v.01" />
    </>
  ),
  networks: (
    <>
      <circle cx="12" cy="5" r="2.4" />
      <circle cx="5" cy="19" r="2.4" />
      <circle cx="19" cy="19" r="2.4" />
      <path d="M12 7.4v4.6M12 12l-5 4.8M12 12l5 4.8" />
    </>
  ),
  schedules: (
    <>
      <rect x="3" y="4.5" width="18" height="16" rx="2" />
      <path d="M3 9h18M8 3v3M16 3v3" />
      <path d="M12 12.5v3l2 1" />
    </>
  ),
  presets: (
    <>
      <path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M18 18h2" />
      <circle cx="16" cy="6" r="2" />
      <circle cx="10" cy="12" r="2" />
      <circle cx="16" cy="18" r="2" />
    </>
  ),
  pentest: (
    <>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="2.5" />
      <path d="M12 2v3M12 19v3M2 12h3M19 12h3" />
    </>
  ),
  scouts: (
    <>
      <path d="M4.5 15a9 9 0 0 1 15 0" />
      <path d="M7.5 15a5.5 5.5 0 0 1 9 0" />
      <circle cx="12" cy="15" r="1.6" />
      <path d="M4 20h16" />
    </>
  ),
  relay: (
    <>
      <circle cx="6" cy="6" r="2.4" />
      <circle cx="18" cy="18" r="2.4" />
      <path d="M8.4 6H14a3.5 3.5 0 0 1 3.5 3.5v6" />
      <path d="M6 8.4V18" />
    </>
  ),
  networking: (
    <>
      <path d="M3 12h4l2 5 4-14 2 9h6" />
    </>
  ),
  feeds: (
    <>
      <path d="M4 11a9 9 0 0 1 9 9" />
      <path d="M4 4a16 16 0 0 1 16 16" />
      <circle cx="5" cy="19" r="1.4" />
    </>
  ),
  reports: (
    <>
      <path d="M6 3h8l4 4v14H6z" />
      <path d="M14 3v4h4" />
      <path d="M9 13h6M9 17h6M9 9h2" />
    </>
  ),
  changes: (
    <>
      <path d="M3 12a9 9 0 1 0 3-6.7L3 8" />
      <path d="M3 4v4h4" />
      <path d="M12 8v4l3 2" />
    </>
  ),
  'system-health': (
    <>
      <path d="M3 12h4l2-5 3 10 2-6 2 3h5" />
    </>
  ),
  updates: (
    <>
      <path d="M12 4v10" />
      <path d="M8 10l4 4 4-4" />
      <path d="M5 20h14" />
    </>
  ),
  backups: (
    <>
      <rect x="3" y="4" width="18" height="5" rx="1.5" />
      <path d="M5 9v10h14V9" />
      <path d="M10 13h4" />
    </>
  ),
  notifications: (
    <>
      <path d="M6 9a6 6 0 0 1 12 0c0 5 2 6 2 6H4s2-1 2-6" />
      <path d="M10.5 20a2 2 0 0 0 3 0" />
    </>
  ),
  maintenance: (
    <>
      <path d="M14.5 6.5a3.5 3.5 0 0 0-4.6 4.6l-5.4 5.4a1.6 1.6 0 0 0 2.3 2.3l5.4-5.4a3.5 3.5 0 0 0 4.6-4.6l-2.2 2.2-2-2z" />
    </>
  ),
  privacy: (
    <>
      <rect x="5" y="10.5" width="14" height="9.5" rx="2" />
      <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" />
      <path d="M12 14v2.5" />
    </>
  ),
  help: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M9.5 9.5a2.5 2.5 0 0 1 4.5 1.5c0 1.7-2 2-2 3.2" />
      <path d="M12 17.5v.01" />
    </>
  ),
  logout: (
    <>
      <path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3" />
      <path d="M10 12h10M17 9l3 3-3 3" />
    </>
  ),
  menu: (
    <>
      <path d="M4 6h16M4 12h16M4 18h16" />
    </>
  ),
};

export function Icon({ name, className }: { name: string; className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.9}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {P[name] ?? P.overview}
    </svg>
  );
}
