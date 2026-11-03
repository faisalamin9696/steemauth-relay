/**
 * SteemAuthenticator relay (protocol v3) — the durable message plane.
 *
 * The relay is the ONLY public endpoint clients ever need (`wss://…`). It
 * replaces the Supabase transport: rooms are sequenced logs with replay, so
 * durability (backgrounded phones, page refreshes, network handoffs) is kept
 * without shipping any database credential to a client, ever.
 *
 * Security model:
 *
 *   - **E2E encryption**: payloads are `{ c, m }` envelopes — AES ciphertext
 *     plus an HMAC-SHA256 tag both peers derive from the QR key `k`. The
 *     relay CAN NOT read messages and CAN NOT inject one that survives
 *     client verification (encrypt-then-MAC).
 *   - **Token auth, hashed at rest**: a room is registered with sha256
 *     hashes of two secrets (app token + phone token, both generated on the
 *     CLIENT). Joins present the plaintext token over wss; the relay hashes
 *     and compares in constant time. Plaintext tokens are never stored or
 *     logged. Only the app token may rotate the phone token or close a room.
 *   - **Unguessable rooms**: `rm_` + 22 random bytes base64url (~176 bits).
 *   - **Abuse limits**: per-connection token bucket, per-IP create/join
 *     limits, auth-failure bans, frame/row/room caps, slow-consumer cuts.
 *   - **Data minimisation**: no credential endpoint (only `/healthz`),
 *     no payload logging, rooms + rows expire and are deleted by a sweeper.
 *
 * Wire protocol (JSON text frames, all responses `t`-tagged):
 *
 *   client → relay  { t:"create", room, toks:[appHash, phoneHash], ttlMs? }
 *   relay  → client { t:"ok", cursor }                      (connection is now the app member)
 *   client → relay  { t:"join",  room, tok }
 *   relay  → client { t:"ok", cursor }                      (phone member; cursor = current seq)
 *   client → relay  { t:"pull",  cursor }
 *   relay  → client { t:"rows",  rows:[[seq, payload], …] } (replay seq > cursor)
 *   client → relay  { t:"msg",   payload:{ c, m } }
 *   relay  → client { t:"ack",   seq }                      (to sender)
 *   relay  → room   { t:"msg",   seq, payload }             (to other members; no sender echo)
 *   client → relay  { t:"rotate" }                          (app token only → new phone token)
 *   client → relay  { t:"close" }                           (app token only → room + rows deleted)
 *   client → relay  { t:"ping" } → { t:"pong" }
 *   relay  → client { t:"err", code }                       (see ERR codes below)
 *
 * Close codes: 4000 room expired/closed · 4003 origin not allowed ·
 * 4004 binary frame · 4010 too many auth failures · 4011 slow consumer ·
 * 4012 banned · 1001 shutting down.
 */
import { createServer } from 'node:http';
import { createHash, timingSafeEqual, randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { WebSocketServer } from 'ws';

// node:sqlite is only available via require() in current Node releases; load
// lazily inside SqliteStore so memory-only relays still run on Node 18.
const require = createRequire(import.meta.url);

/** Format gates — anything else never reaches the store. */
const ROOM_RE = /^rm_[A-Za-z0-9_-]{16,64}$/;
const TOK_RE = /^tok_[A-Za-z0-9_-]{32,128}$/;
const HASH_RE = /^[0-9a-f]{64}$/;
const MAC_RE = /^[0-9a-f]{64}$/;
/** Session id shape (UUID v4) — the relay validates before any Supabase query. */
const SID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const DEFAULTS = {
  maxPeersPerRoom: 4,
  /** stored envelope budget: ciphertext + tag */
  maxEnvelopeBytes: 64 * 1024,
  maxFrameBytes: 70 * 1024,
  /** hard room lifetime from create (sliding idle expiry is shorter) */
  roomTtlMs: 60 * 60 * 1000,
  /** sliding expiry: room dies this long after the last member activity */
  roomIdleMs: 15 * 60 * 1000,
  maxRowsPerRoom: 1000,
  maxRooms: 100_000,
  messagesPerSecond: 20,
  createsPerMinute: 10,
  joinsPerMinute: 30,
  /** auth failures per IP before a temporary ban */
  authFailBanThreshold: 10,
  authFailBanMs: 10 * 60 * 1000,
  sweepIntervalMs: 30_000,
  /** slow-consumer cut-off (buffered bytes) */
  maxBufferedBytes: 1024 * 1024,
  /** How often to poll Supabase for revocations (ms). 0 = disabled. */
  revocationPollMs: 5_000,
};

function sha256Hex(input) {
  return createHash('sha256').update(input).digest('hex');
}
function hashEqual(hexA, hexB) {
  const a = Buffer.from(String(hexA), 'utf8');
  const b = Buffer.from(String(hexB), 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Token shape the CLIENTS generate (the relay only ever sees hashes). */
export function generateToken() {
  return `tok_${randomBytes(32).toString('base64url')}`;
}
export function generateRoom() {
  return `rm_${randomBytes(22).toString('base64url')}`;
}

// ---------------------------------------------------------------------------
// Stores — the durability requirement lives here. Two implementations behind
// one interface; the store is the relay's PRIVATE business (no client ever
// learns which one runs, and no credential for it ever leaves the process).
// ---------------------------------------------------------------------------

export class MemoryStore {
  constructor(limits = DEFAULTS) {
    this.limits = limits;
    /** @type {Map<string, any>} */
    this.rooms = new Map();
  }

  create(room, appHash, phoneHash, now, ttlMs) {
    const existing = this.rooms.get(room);
    if (existing) {
      if (existing.exp > now && hashEqual(existing.appHash, appHash) && hashEqual(existing.phoneHash, phoneHash)) {
        return { ok: true, already: true };
      }
      return { ok: false, reason: 'room_exists' };
    }
    if (this.rooms.size >= this.limits.maxRooms) return { ok: false, reason: 'too_many_rooms' };
    this.rooms.set(room, {
      appHash,
      phoneHash,
      created: now,
      exp: now + ttlMs,
      last: now,
      nextSeq: 0,
      rows: [],
    });
    return { ok: true };
  }

  room(room) {
    return this.rooms.get(room) ?? null;
  }

  touch(room, now) {
    const r = this.rooms.get(room);
    if (r) r.last = now;
  }

  setPhoneHash(room, phoneHash) {
    const r = this.rooms.get(room);
    if (!r) return false;
    r.phoneHash = phoneHash;
    return true;
  }

  append(room, payload) {
    const r = this.rooms.get(room);
    if (!r) return null;
    if (r.rows.length >= this.limits.maxRowsPerRoom) return 'full';
    r.nextSeq += 1;
    r.rows.push([r.nextSeq, payload]);
    return r.nextSeq;
  }

  rows(room, after, limit) {
    const r = this.rooms.get(room);
    if (!r) return [];
    return r.rows.filter(([seq]) => seq > after).slice(0, limit);
  }

  deleteRoom(room) {
    return this.rooms.delete(room);
  }

  sweep(now) {
    const expired = [];
    for (const [room, r] of this.rooms) {
      if (now >= r.exp || now - r.last >= this.limits.roomIdleMs) expired.push(room);
    }
    for (const room of expired) this.rooms.delete(room);
    return expired;
  }

  get size() {
    return this.rooms.size;
  }
}

/** Durable store backed by node:sqlite (Node >= 22). Zero dependencies. */
export class SqliteStore {
  constructor(limits = DEFAULTS, dbPath = ':memory:') {
    this.limits = limits;
    this.dbPath = dbPath;
    // Lazy: only loads node:sqlite when actually used (keeps Node 18 able to
    // run the memory-store relay).
    const { DatabaseSync } = require('node:sqlite');
    this.db = new DatabaseSync(dbPath);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS rooms (
        room       TEXT PRIMARY KEY,
        app_hash   TEXT NOT NULL,
        phone_hash TEXT NOT NULL,
        created    INTEGER NOT NULL,
        exp        INTEGER NOT NULL,
        last       INTEGER NOT NULL,
        next_seq   INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS rows (
        room    TEXT NOT NULL,
        seq     INTEGER NOT NULL,
        payload TEXT NOT NULL,
        PRIMARY KEY (room, seq)
      );
    `);
    this.stmt = {
      get: this.db.prepare('SELECT * FROM rooms WHERE room = ?'),
      insert: this.db.prepare(
        'INSERT INTO rooms (room, app_hash, phone_hash, created, exp, last, next_seq) VALUES (?, ?, ?, ?, ?, ?, 0)',
      ),
      touch: this.db.prepare('UPDATE rooms SET last = ? WHERE room = ?'),
      setPhone: this.db.prepare('UPDATE rooms SET phone_hash = ? WHERE room = ?'),
      del: this.db.prepare('DELETE FROM rooms WHERE room = ?'),
      count: this.db.prepare('SELECT COUNT(*) AS n FROM rooms'),
      expired: this.db.prepare(
        'SELECT room FROM rooms WHERE exp <= ? OR last <= ?',
      ),
      append: this.db.prepare('UPDATE rooms SET next_seq = next_seq + 1 WHERE room = ?'),
      nextSeq: this.db.prepare('SELECT next_seq AS n FROM rooms WHERE room = ?'),
      insertRow: this.db.prepare('INSERT INTO rows (room, seq, payload) VALUES (?, ?, ?)'),
      rows: this.db.prepare('SELECT seq, payload FROM rows WHERE room = ? AND seq > ? ORDER BY seq LIMIT ?'),
      delRows: this.db.prepare('DELETE FROM rows WHERE room = ?'),
      roomRows: this.db.prepare('SELECT COUNT(*) AS n FROM rows WHERE room = ?'),
    };
  }

  create(room, appHash, phoneHash, now, ttlMs) {
    const existing = this.stmt.get.get(room);
    if (existing) {
      if (
        existing.exp > now &&
        hashEqual(existing.app_hash, appHash) &&
        hashEqual(existing.phone_hash, phoneHash)
      ) {
        return { ok: true, already: true };
      }
      return { ok: false, reason: 'room_exists' };
    }
    if (this.stmt.count.get().n >= this.limits.maxRooms) {
      return { ok: false, reason: 'too_many_rooms' };
    }
    this.stmt.insert.run(room, appHash, phoneHash, now, now + ttlMs, now);
    return { ok: true };
  }

  room(room) {
    const r = this.stmt.get.get(room);
    return r ? { appHash: r.app_hash, phoneHash: r.phone_hash, created: r.created, exp: r.exp, last: r.last, nextSeq: r.next_seq } : null;
  }

  touch(room, now) {
    this.stmt.touch.run(now, room);
  }

  setPhoneHash(room, phoneHash) {
    return this.stmt.setPhone.run(phoneHash, room).changes > 0;
  }

  append(room, payload) {
    if (!this.room(room)) return null;
    if (this.stmt.roomRows.get(room).n >= this.limits.maxRowsPerRoom) return 'full';
    this.stmt.append.run(room);
    const seq = this.stmt.nextSeq.get(room).n;
    this.stmt.insertRow.run(room, seq, JSON.stringify(payload));
    return seq;
  }

  rows(room, after, limit) {
    return this.stmt.rows
      .all(room, after, limit)
      .map((r) => [r.seq, JSON.parse(r.payload)]);
  }

  deleteRoom(room) {
    this.stmt.delRows.run(room);
    return this.stmt.del.run(room).changes > 0;
  }

  sweep(now) {
    const expired = this.stmt.expired.all(now, now - this.limits.roomIdleMs).map((r) => r.room);
    for (const room of expired) this.deleteRoom(room);
    return expired;
  }

  get size() {
    return this.stmt.count.get().n;
  }

  close() {
    this.db.close();
  }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/**
 * Create (but do not start) a v3 relay.
 *
 * @param {object} [opts]
 * @param {'memory'|'sqlite'|object} [opts.store] store kind or a Store instance
 * @param {string} [opts.dbPath] sqlite file path (STORE=sqlite)
 * …plus every field of DEFAULTS as overrides.
 */
export function createRelayServer(opts = {}) {
  const limits = { ...DEFAULTS, ...stripKnown(opts) };
  let store = opts.store ?? 'memory';
  if (store === 'memory') store = new MemoryStore(limits);
  else if (store === 'sqlite') store = new SqliteStore(limits, opts.dbPath ?? process.env.RELAY_DB ?? ':memory:');
  const allowedOrigins = opts.allowedOrigins ?? null;

  // Supabase revocation watch — the relay holds sids for connected clients
  // and polls for revoked_at changes. Supabase credentials NEVER leave this
  // process (no endpoint exposes them, no frame carries them).
  const supabaseUrl = opts.supabaseUrl ?? process.env.SUPABASE_URL ?? null;
  const supabaseKey = opts.supabaseKey ?? process.env.SUPABASE_KEY ?? null;
  const supabaseTable = opts.supabaseTable ?? process.env.SUPABASE_TABLE ?? 'steemauth_sessions';
  const revocationPollMs = opts.revocationPollMs ?? Number(process.env.REVOCATION_POLL_MS ?? 5_000);
  const supabaseEnabled = Boolean(supabaseUrl && supabaseKey && revocationPollMs > 0);

  /** sid → Set<ws> — which websockets are watching which sid for revocation. */
  const watchers = new Map();
  let revocationPoll = null;
  let supabaseWarned = false;

  function addWatcher(sid, ws) {
    let set = watchers.get(sid);
    if (!set) watchers.set(sid, (set = new Set()));
    set.add(ws);
    ws.__watchSid = sid;
    if (!revocationPoll && supabaseEnabled) startRevocationPoll();
  }

  function removeWatcher(ws) {
    const sid = ws.__watchSid;
    if (!sid) return;
    ws.__watchSid = null;
    const set = watchers.get(sid);
    if (set) {
      set.delete(ws);
      if (set.size === 0) watchers.delete(sid);
    }
    if (watchers.size === 0) stopRevocationPoll();
  }

  function startRevocationPoll() {
    revocationPoll = setInterval(pollRevocations, revocationPollMs);
    revocationPoll.unref?.();
  }

  function stopRevocationPoll() {
    if (revocationPoll) {
      clearInterval(revocationPoll);
      revocationPoll = null;
    }
  }

  async function pollRevocations() {
    if (watchers.size === 0) return;
    const sids = [...watchers.keys()];
    const sidParam = sids.join(',');
    const url = `${supabaseUrl}/rest/v1/${supabaseTable}?sid=in.(${sidParam})&revoked_at=not.is.null&select=sid,revoked_reason`;
    try {
      const res = await fetch(url, {
        headers: {
          'apikey': supabaseKey,
          'Authorization': `Bearer ${supabaseKey}`,
        },
      });
      if (!res.ok) {
        if (!supabaseWarned) {
          console.error(`[revocation] Supabase query failed: ${res.status} ${res.statusText}`);
          supabaseWarned = true;
        }
        return;
      }
      supabaseWarned = false;
      const rows = await res.json();
      for (const row of rows) {
        const sid = row.sid;
        const reason = row.revoked_reason || 'Access was revoked in the authenticator.';
        const set = watchers.get(sid);
        if (!set) continue;
        for (const ws of set) {
          send(ws, { t: 'revoked', sid, reason });
          ws.__watchSid = null;
        }
        watchers.delete(sid);
      }
      if (watchers.size === 0) stopRevocationPoll();
    } catch (e) {
      if (!supabaseWarned) {
        console.error(`[revocation] Supabase unreachable: ${e.message}`);
        supabaseWarned = true;
      }
    }
  }

  /** Per-IP bookkeeping for create/join limits + auth-failure bans. */
  const ipState = new Map(); // ip -> { creates, createsAt, joins, joinsAt, fails, bannedUntil }
  const ipOf = (req) => req.socket.remoteAddress ?? 'unknown';
  const ipRec = (ip) => {
    let r = ipState.get(ip);
    if (!r) {
      r = { creates: 0, createsAt: 0, joins: 0, joinsAt: 0, fails: 0, bannedUntil: 0 };
      ipState.set(ip, r);
    }
    return r;
  };

  const httpServer = createServer((req, res) => {
    // Data minimisation: health only. No config, no credentials, no stats.
    if (req.url === '/healthz') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, supabase: supabaseEnabled }));
      return;
    }
    res.writeHead(404);
    res.end();
  });

  // Every accepted socket is tracked so shutdown can never hang on a
  // lingering (possibly non-member) connection.
  const sockets = new Set();
  httpServer.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  const wss = new WebSocketServer({ server: httpServer, maxPayload: limits.maxFrameBytes });

  function send(ws, obj) {
    if (ws.readyState === 1) ws.send(JSON.stringify(obj));
  }

  /** Members of a room (bound sockets). */
  const members = new Map(); // room -> Set<ws>
  function addMember(room, ws, role) {
    ws.__room = room;
    ws.__role = role;
    let set = members.get(room);
    if (!set) members.set(room, (set = new Set()));
    set.add(ws);
  }
  function removeMember(ws) {
    if (!ws.__room) return;
    const set = members.get(ws.__room);
    if (set) {
      set.delete(ws);
      if (set.size === 0) members.delete(ws.__room);
    }
    ws.__room = null;
    ws.__role = null;
  }

  function closeRoom(room, code = 4000, reason = 'room closed') {
    const set = members.get(room);
    if (set) {
      for (const peer of set) {
        removeMember(peer);
        try {
          peer.close(code, reason);
        } catch {
          /* already gone */
        }
      }
      members.delete(room);
    }
    store.deleteRoom(room);
  }

  wss.on('connection', (ws, req) => {
    const ip = ipOf(req);
    const rec = ipRec(ip);
    const origin = req.headers.origin ?? null;

    if (rec.bannedUntil > Date.now()) {
      ws.close(4012, 'banned');
      return;
    }
    if (allowedOrigins) {
      if (origin && !allowedOrigins.includes(origin)) {
        ws.close(4003, 'origin not allowed');
        return;
      }
    }

    let tokens = limits.messagesPerSecond;
    let lastRefill = Date.now();
    let joinFails = 0;

    const failAuth = (code) => {
      send(ws, { t: 'err', code });
      rec.fails += 1;
      joinFails += 1;
      if (rec.fails >= limits.authFailBanThreshold || joinFails >= 5) {
        rec.bannedUntil = Date.now() + limits.authFailBanMs;
        ws.close(4010, 'too many auth failures');
      }
    };

    ws.on('message', (raw, isBinary) => {
      if (isBinary) {
        ws.close(4004, 'binary frames not allowed');
        return;
      }
      // Per-connection token bucket.
      const now = Date.now();
      tokens = Math.min(limits.messagesPerSecond, tokens + ((now - lastRefill) / 1000) * limits.messagesPerSecond);
      lastRefill = now;
      if (tokens < 1) {
        send(ws, { t: 'err', code: 'rate_limited' });
        return;
      }
      tokens -= 1;

      let msg;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        send(ws, { t: 'err', code: 'bad_shape' });
        return;
      }
      if (!msg || typeof msg !== 'object' || typeof msg.t !== 'string') {
        send(ws, { t: 'err', code: 'bad_shape' });
        return;
      }

      switch (msg.t) {
        case 'create': {
          const room = String(msg.room ?? '');
          const toks = Array.isArray(msg.toks) ? msg.toks : [];
          const ttlMs = Number(msg.ttlMs);
          if (
            !ROOM_RE.test(room) ||
            toks.length !== 2 ||
            !toks.every((h) => HASH_RE.test(String(h)))
          ) {
            send(ws, { t: 'err', code: 'bad_shape' });
            return;
          }
          // Per-IP create limit (room-flood guard).
          if (now - rec.createsAt > 60_000) {
            rec.createsAt = now;
            rec.creates = 0;
          }
          if (rec.creates >= limits.createsPerMinute) {
            send(ws, { t: 'err', code: 'rate_limited' });
            return;
          }
          rec.creates += 1;
          const ttl = Number.isFinite(ttlMs) ? Math.min(Math.max(ttlMs, 30_000), limits.roomTtlMs) : limits.roomTtlMs;
          const result = store.create(room, String(toks[0]), String(toks[1]), now, ttl);
          if (!result.ok) {
            send(ws, { t: 'err', code: result.reason });
            return;
          }
          if (ws.__room) removeMember(ws);
          addMember(room, ws, 'app');
          send(ws, { t: 'ok', cursor: store.room(room)?.nextSeq ?? 0 });
          break;
        }
        case 'join': {
          const room = String(msg.room ?? '');
          const tok = String(msg.tok ?? '');
          if (!ROOM_RE.test(room) || !TOK_RE.test(tok)) {
            send(ws, { t: 'err', code: 'bad_shape' });
            return;
          }
          if (now - rec.joinsAt > 60_000) {
            rec.joinsAt = now;
            rec.joins = 0;
          }
          if (rec.joins >= limits.joinsPerMinute) {
            send(ws, { t: 'err', code: 'rate_limited' });
            return;
          }
          rec.joins += 1;
          const r = store.room(room);
          if (!r || now >= r.exp) {
            send(ws, { t: 'err', code: 'room_expired' });
            return;
          }
          const hash = sha256Hex(tok);
          const isApp = hashEqual(hash, r.appHash);
          const isPhone = hashEqual(hash, r.phoneHash);
          if (!isApp && !isPhone) {
            failAuth('bad_token');
            return;
          }
          const set = members.get(room);
          if (set && set.size >= limits.maxPeersPerRoom) {
            send(ws, { t: 'err', code: 'room_full' });
            return;
          }
          if (ws.__room) removeMember(ws);
          store.touch(room, now);
          addMember(room, ws, isApp ? 'app' : 'phone');
          send(ws, { t: 'ok', cursor: r.nextSeq });
          break;
        }
        case 'pull': {
          if (!ws.__room) {
            send(ws, { t: 'err', code: 'not_member' });
            return;
          }
          const after = Number(msg.cursor);
          if (!Number.isInteger(after) || after < 0) {
            send(ws, { t: 'err', code: 'bad_shape' });
            return;
          }
          store.touch(ws.__room, now);
          send(ws, { t: 'rows', rows: store.rows(ws.__room, after, limits.maxRowsPerRoom) });
          break;
        }
        case 'msg': {
          if (!ws.__room) {
            send(ws, { t: 'err', code: 'not_member' });
            return;
          }
          const payload = msg.payload;
          // Strict envelope shape: { c: ciphertext ≤ cap, m: 64-hex tag }.
          // The relay cannot verify the HMAC (it never sees `k`) but it will
          // not store or forward anything that isn't a well-formed envelope.
          const keys = payload && typeof payload === 'object' ? Object.keys(payload) : [];
          const c = payload?.c;
          const m = payload?.m;
          if (
            keys.length === 0 ||
            keys.some((k) => k !== 'c' && k !== 'm') ||
            typeof c !== 'string' ||
            typeof m !== 'string' ||
            !MAC_RE.test(m) ||
            c.length > limits.maxEnvelopeBytes
          ) {
            send(ws, { t: 'err', code: 'bad_shape' });
            return;
          }
          store.touch(ws.__room, now);
          const seq = store.append(ws.__room, { c, m });
          if (seq === 'full') {
            send(ws, { t: 'err', code: 'room_log_full' });
            return;
          }
          if (seq === null) {
            send(ws, { t: 'err', code: 'room_expired' });
            return;
          }
          send(ws, { t: 'ack', seq });
          const out = JSON.stringify({ t: 'msg', seq, payload: { c, m } });
          const set = members.get(ws.__room);
          if (set) {
            for (const peer of set) {
              if (peer === ws || peer.readyState !== 1) continue;
              if (peer.bufferedAmount > limits.maxBufferedBytes) {
                peer.close(4011, 'slow consumer');
                removeMember(peer);
                continue;
              }
              peer.send(out);
            }
          }
          break;
        }
        case 'rotate': {
          if (!ws.__room || ws.__role !== 'app') {
            send(ws, { t: 'err', code: 'not_app' });
            return;
          }
          const tok = generateToken();
          if (!store.setPhoneHash(ws.__room, sha256Hex(tok))) {
            send(ws, { t: 'err', code: 'room_expired' });
            return;
          }
          send(ws, { t: 'ok', tok });
          break;
        }
        case 'close': {
          if (!ws.__room || ws.__role !== 'app') {
            send(ws, { t: 'err', code: 'not_app' });
            return;
          }
          closeRoom(ws.__room);
          break;
        }
        case 'ping':
          send(ws, { t: 'pong' });
          break;
        case 'leave':
          removeMember(ws);
          send(ws, { t: 'left' });
          break;
        case 'watch': {
          const sid = String(msg.sid ?? '');
          if (!SID_RE.test(sid)) {
            send(ws, { t: 'err', code: 'bad_shape' });
            return;
          }
          if (!supabaseEnabled) {
            send(ws, { t: 'err', code: 'bad_shape' });
            return;
          }
          if (ws.__watchSid && ws.__watchSid !== sid) removeWatcher(ws);
          addWatcher(sid, ws);
          send(ws, { t: 'watched' });
          break;
        }
        default:
          send(ws, { t: 'err', code: 'bad_shape' });
      }
    });

    const cleanup = () => {
      removeMember(ws);
      removeWatcher(ws);
    };
    ws.on('close', cleanup);
    ws.on('error', cleanup);
  });

  // Sweeper: expired rooms lose their sockets and their rows. Nothing leaks.
  const sweeper = setInterval(() => {
    for (const room of store.sweep(Date.now())) {
      const set = members.get(room);
      if (set) {
        for (const peer of set) {
          removeMember(peer);
          try {
            peer.close(4000, 'room expired');
          } catch {
            /* already gone */
          }
        }
        members.delete(room);
      }
    }
  }, limits.sweepIntervalMs);
  sweeper.unref?.();

  return {
    httpServer,
    store,
    /** Start listening. Pass 0 for an ephemeral port (tests). Resolves with the port. */
    listen(port = 0, host = '0.0.0.0') {
      return new Promise((resolve, reject) => {
        httpServer.once('error', reject);
        httpServer.listen(port, host, () => {
          const addr = httpServer.address();
          resolve(typeof addr === 'object' && addr ? addr.port : port);
        });
      });
    },
    /** Stop listening. DURABILITY FIRST: sockets close but rooms + rows are
     *  kept — a restart resumes exactly where it left off. Only the app's
     *  `close` frame and the idle sweeper ever delete data. */
    async close() {
      clearInterval(sweeper);
      stopRevocationPoll();
      watchers.clear();
      for (const set of members.values()) {
        for (const peer of set) {
          try {
            peer.close(1001, 'server shutting down');
          } catch {
            /* already gone */
          }
        }
      }
      members.clear();
      ipState.clear();
      store.close?.();
      for (const socket of sockets) socket.destroy();
      sockets.clear();
      await new Promise((resolve) => wss.close(() => httpServer.close(() => resolve())));
    },
    get roomCount() {
      return store.size;
    },
  };
}

function stripKnown(opts) {
  const { store, dbPath, allowedOrigins, supabaseUrl, supabaseKey, supabaseTable, ...limits } = opts;
  return limits;
}
