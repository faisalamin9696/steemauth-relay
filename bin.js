#!/usr/bin/env node
/**
 * CLI entry: PORT=8787 STORE=sqlite RELAY_DB=/data/relay.db node bin.js
 *
 * Optional env:
 *   PORT                listen port (default 8787)
 *   STORE               memory | sqlite (default memory)
 *   RELAY_DB            sqlite file (default ./relay.db when STORE=sqlite)
 *   ALLOWED_ORIGINS     comma-separated browser Origin allowlist
 *   MAX_ROOMS, ROOM_IDLE_MS, MESSAGES_PER_SECOND  …see DEFAULTS in server.js
 *   SUPABASE_URL        Supabase project URL for revocation watch
 *   SUPABASE_KEY        Supabase anon/service key (never leaves the relay)
 *   SUPABASE_TABLE      Supabase table name (default steemauth_sessions)
 *   REVOCATION_POLL_MS  Revocation poll interval (default 5000, 0=disabled)
 */
import { createRelayServer } from './server.js';

const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean)
  : null;

const opts = { allowedOrigins };
if (process.env.STORE === 'sqlite') {
  opts.store = 'sqlite';
  opts.dbPath = process.env.RELAY_DB ?? './relay.db';
}
if (process.env.MAX_ROOMS) opts.maxRooms = Number(process.env.MAX_ROOMS);
if (process.env.ROOM_IDLE_MS) opts.roomIdleMs = Number(process.env.ROOM_IDLE_MS);
if (process.env.MESSAGES_PER_SECOND) opts.messagesPerSecond = Number(process.env.MESSAGES_PER_SECOND);
if (process.env.SUPABASE_URL) opts.supabaseUrl = process.env.SUPABASE_URL;
if (process.env.SUPABASE_KEY) opts.supabaseKey = process.env.SUPABASE_KEY;
if (process.env.SUPABASE_TABLE) opts.supabaseTable = process.env.SUPABASE_TABLE;
if (process.env.REVOCATION_POLL_MS) opts.revocationPollMs = Number(process.env.REVOCATION_POLL_MS);

const relay = createRelayServer(opts);

const port = await relay.listen(Number(process.env.PORT ?? 8787));
console.log(
  `steemauth-relay v3 listening on :${port} (store: ${process.env.STORE === 'sqlite' ? opts.dbPath : 'memory'})`,
);

async function shutdown() {
  console.log('\nshutting down…');
  await relay.close();
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
