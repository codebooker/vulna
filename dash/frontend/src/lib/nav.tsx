import { createContext, useContext } from 'react';

export interface RouteParams {
  [key: string]: string;
}

export interface CurrentRoute {
  id: string;
  params: RouteParams;
}

/** Parse `#view?key=value` hashes. Unknown ids are resolved by the caller. */
export function parseHash(hash: string): CurrentRoute {
  const raw = hash.replace(/^#/, '');
  const [id, query = ''] = raw.split('?');
  const params: RouteParams = {};
  for (const pair of query.split('&')) {
    if (!pair) continue;
    const [k, v = ''] = pair.split('=');
    params[decodeURIComponent(k)] = decodeURIComponent(v);
  }
  return { id, params };
}

export function hashFor(id: string, params?: RouteParams): string {
  const query = params
    ? Object.entries(params)
        .filter(([, v]) => v !== '')
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
        .join('&')
    : '';
  return query ? `${id}?${query}` : id;
}

export interface NavContextValue {
  current: CurrentRoute;
  go: (id: string, params?: RouteParams) => void;
}

export const NavContext = createContext<NavContextValue | null>(null);

/** Fallback (used when a page renders outside the app shell, e.g. in tests):
 *  navigation still works through the location hash. */
const FALLBACK_NAV: NavContextValue = {
  current: { id: 'overview', params: {} },
  go: (id, params) => {
    window.location.hash = hashFor(id, params);
  },
};

export function useNav(): NavContextValue {
  return useContext(NavContext) ?? FALLBACK_NAV;
}
