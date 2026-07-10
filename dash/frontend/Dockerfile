# syntax=docker/dockerfile:1

# ---- Build ----
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
# Use npm ci when a lockfile is present, otherwise fall back to install.
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY . .
RUN npm run build

# ---- Runtime (unprivileged nginx, non-root, port 8080) ----
FROM nginxinc/nginx-unprivileged:1.27-alpine AS runtime
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=5 \
    CMD wget -qO- http://localhost:8080/health || exit 1
