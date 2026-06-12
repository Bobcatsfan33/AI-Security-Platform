# frontend/Dockerfile — Next.js standalone (multi-stage, non-root).
# Requires next.config.ts: output: "standalone".
#
# Build context is frontend/, e.g.:
#   docker build -f frontend/Dockerfile frontend/
FROM node:22.13.0-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:22.13.0-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM node:22.13.0-alpine AS runtime
RUN addgroup -g 10001 app && adduser -u 10001 -G app -s /sbin/nologin -D app
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1
# The standalone server + its traced runtime files; static assets and public/
# are copied alongside it (Next does not bundle them into standalone).
COPY --from=build --chown=app:app /app/.next/standalone ./
COPY --from=build --chown=app:app /app/.next/static ./.next/static
COPY --from=build --chown=app:app /app/public ./public
USER 10001:10001
EXPOSE 3000
CMD ["node", "server.js"]
