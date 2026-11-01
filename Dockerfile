# SteemAuthenticator relay - minimal production image.
# The relay is a single Node process (one `ws` dependency). STORE=sqlite
# needs Node >= 22 (node:sqlite); mount a volume at /data for durability.
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./server.d.ts ./server.js bin.js ./

# Non-root (Alpine already has `node` user, uid 1000)
USER node
EXPOSE 8787
VOLUME /data

# Health check hits the /healthz route the server exposes.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${PORT:-8787}/healthz" || exit 1

CMD ["node", "bin.js"]
