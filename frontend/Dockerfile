# =============================================================================
#  NetShield-ISP — Next.js dashboard image
#
#  Targets:
#    deps         node_modules only, cached independently of the source tree
#    development  Next dev server with Fast Refresh
#    builder      produces the standalone production bundle
#    production   minimal runtime containing only the standalone output
# =============================================================================

ARG NODE_VERSION=22

# -----------------------------------------------------------------------------
FROM node:${NODE_VERSION}-alpine AS deps
# -----------------------------------------------------------------------------

# libc6-compat backs the glibc-linked native addons some Next.js builds pull in.
RUN apk add --no-cache libc6-compat

WORKDIR /app

# `npm ci` is used when a lockfile is committed, which is the reproducible path.
# The fallback keeps a clean checkout buildable before the first lockfile exists.
COPY package.json package-lock.json* ./
RUN set -eux; \
    if [ -f package-lock.json ]; then \
        npm ci --no-audit --no-fund; \
    else \
        npm install --no-audit --no-fund; \
    fi

# -----------------------------------------------------------------------------
FROM node:${NODE_VERSION}-alpine AS development
# -----------------------------------------------------------------------------

RUN apk add --no-cache libc6-compat

ENV NODE_ENV=development \
    NEXT_TELEMETRY_DISABLED=1 \
    # Bind-mounted source on some hosts does not deliver inotify events.
    WATCHPACK_POLLING=true

WORKDIR /app

COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node . .

USER node
EXPOSE 3000

CMD ["npm", "run", "dev"]

# -----------------------------------------------------------------------------
FROM node:${NODE_VERSION}-alpine AS builder
# -----------------------------------------------------------------------------

RUN apk add --no-cache libc6-compat

WORKDIR /app

# NEXT_PUBLIC_* values are inlined into the client bundle at build time, so the
# API URL has to be known here rather than at container start.
ARG NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
ARG NEXT_PUBLIC_APP_NAME=NetShield-ISP

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    NEXT_PUBLIC_API_BASE_URL=${NEXT_PUBLIC_API_BASE_URL} \
    NEXT_PUBLIC_APP_NAME=${NEXT_PUBLIC_APP_NAME}

COPY --from=deps /app/node_modules ./node_modules
COPY . .

RUN npm run build

# -----------------------------------------------------------------------------
FROM node:${NODE_VERSION}-alpine AS production
# -----------------------------------------------------------------------------

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

WORKDIR /app

# `output: "standalone"` emits a server bundle with only the modules actually
# reached at runtime. Copying just that keeps the final image small and leaves
# no build toolchain or dev dependency behind for an attacker to reuse.
COPY --from=builder --chown=node:node /app/public ./public
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static

USER node
EXPOSE 3000

CMD ["node", "server.js"]
