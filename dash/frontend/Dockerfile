# syntax=docker/dockerfile:1

# ---- Build ----
FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS build
WORKDIR /app
COPY package.json package-lock.json* ./
# Use npm ci when a lockfile is present, otherwise fall back to install.
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY . .
RUN npm run build

# ---- Runtime (unprivileged nginx, non-root, port 8080) ----
FROM nginxinc/nginx-unprivileged:1.27-alpine@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0 AS runtime
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080
# Use 127.0.0.1, not localhost: busybox wget resolves localhost to ::1 first,
# but nginx listens IPv4-only, so "localhost" would always fail the check.
HEALTHCHECK --interval=30s --timeout=5s --retries=5 \
    CMD wget -qO- http://127.0.0.1:8080/health || exit 1
