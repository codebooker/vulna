# VulnaDash Frontend

React + TypeScript + Vite single-page app for the Vulna platform.

**Phase 0 scope:** application shell with a health page that verifies backend
connectivity by calling `/health` and `/api/v1/system/info`. Full dashboard,
sites, scans, assets, findings, and other pages arrive in later phases.

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
