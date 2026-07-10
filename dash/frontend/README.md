# VulnaDash Frontend

React + TypeScript + Vite single-page app for the Vulna platform.

**Current scope (through Phase 1):** an authenticated shell with a login page,
a JWT-backed auth context (token persisted in `localStorage`, session restore on
reload), a sites list with an admin-only create form, sign-out, and the health
page that verifies backend connectivity. Scans, assets, findings, and the other
pages arrive in later phases.

## Development

```bash
# From dash/frontend/
npm install
npm run dev        # Vite dev server on http://localhost:5173 (proxies /api → :8000)

npm run build      # type-check + production build
npm run lint       # ESLint
npm run test       # Vitest
npm run format     # Prettier
```

Set `VITE_API_TARGET` to point the dev proxy at a non-default backend, or
`VITE_API_BASE_URL` to call an absolute API base at build time.
