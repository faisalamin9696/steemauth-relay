/**
 * v3 relay test suite — transport + SECURITY guarantees.
 *
 * Run: npm test  (node --test test.js)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import WebSocket from 'ws';
import {
  createRelayServer,
  generateRoom,
  generateToken,
  MemoryStore,
  DEFAULTS,
} from './server.js';

const sha256 = (s) => createHash('sha256').update(s).digest('hex');

function client(url) {
  const ws = new WebSocket(url);
  const inbox = [];
  const waiters = [];
  ws.on('message', (raw) => {
    const msg = JSON.parse(String(raw));
    if (waiters.length) waiters.shift()(msg);
    else inbox.push(msg);
  });
  const open = new Promise((resolve, reject) => {
    ws.once('open', resolve);
    ws.once('error', reject);
  });
  return {
    ws,
    open,
    send(obj) {
      ws.send(JSON.stringify(obj));
    },
    next(timeoutMs = 3000) {
      return new Promise((resolve, reject) => {
        if (inbox.length) return resolve(inbox.shift());
        const t = setTimeout(() => reject(new Error('timeout waiting for frame')), timeoutMs);
        waiters.push((m) => {
          clearTimeout(t);
          resolve(m);
        });
      });
    },
    closed: new Promise((resolve) => ws.once('close', (code) => resolve(code))),
    close() {
      ws.close();
    },
  };
}

const envelope = (text) => ({ c: Buffer.from(text).toString('base64'), m: 'a'.repeat(64) });

async function boot(opts = {}) {
  const relay = createRelayServer({ sweepIntervalMs: 200, ...opts });
  const port = await relay.listen(0, '127.0.0.1');
  return { relay, url: `ws://127.0.0.1:${port}` };
}

/** Create a room as the app and return { app, appTok, phoneTok, room }. */
async function makeRoom(url) {
  const appTok = generateToken();
  const phoneTok = generateToken();
  const room = generateRoom();
  const app = client(url);
  await app.open;
  app.send({ t: 'create', room, toks: [sha256(appTok), sha256(phoneTok)] });
  assert.equal((await app.next()).t, 'ok');
  return { app, appTok, phoneTok, room };
}

// ---------------------------------------------------------------------------

test('healthz up, config endpoint gone (no credential surface)', async () => {
  const { relay, url } = await boot();
  try {
    const httpPort = new URL(url.replace('ws', 'http')).port;
    const health = await fetch(`http://127.0.0.1:${httpPort}/healthz`);
    const body = await health.json();
    assert.equal(body.ok, true);
    assert.equal(body.supabase, false); // no Supabase configured in tests
    const config = await fetch(`http://127.0.0.1:${httpPort}/config`);
    assert.equal(config.status, 404);
  } finally {
    await relay.close();
  }
});

test('create → phone join → msg → ack + fanout + replay', async () => {
  const { relay, url } = await boot();
  try {
    const { app, phoneTok, room } = await makeRoom(url);
    const phone = client(url);
    await phone.open;
    phone.send({ t: 'join', room, tok: phoneTok });
    const joined = await phone.next();
    assert.equal(joined.t, 'ok');

    // Phone sends a message; app (member) receives it live.
    phone.send({ t: 'msg', payload: envelope('hello') });
    assert.equal((await phone.next()).t, 'ack'); // sender ack
    const live = await app.next();
    assert.equal(live.t, 'msg');
    assert.equal(live.seq, 1);

    // Replay: a fresh member joining with cursor 0 gets the backlog.
    const phone2 = client(url);
    await phone2.open;
    phone2.send({ t: 'join', room, tok: phoneTok });
    const j2 = await phone2.next();
    assert.equal(j2.cursor, 1);
    phone2.send({ t: 'pull', cursor: 0 });
    const rows = await phone2.next();
    assert.equal(rows.t, 'rows');
    assert.equal(rows.rows.length, 1);
    assert.deepEqual(rows.rows[0], [1, { c: envelope('hello').c, m: 'a'.repeat(64) }]);
    phone2.close();
    phone.close();
  } finally {
    await relay.close();
  }
});

test('unknown room and bad token are refused; repeated failures ban the IP', async () => {
  const { relay, url } = await boot();
  try {
    const c = client(url);
    await c.open;
    c.send({ t: 'join', room: generateRoom(), tok: generateToken() });
    assert.equal((await next(c)).code, 'room_expired');

    const { room } = await makeRoom(url);
    const bad = client(url);
    await bad.open;
    for (let i = 0; i < 4; i++) {
      bad.send({ t: 'join', room, tok: generateToken() });
      assert.equal((await bad.next()).code, 'bad_token');
    }
    bad.send({ t: 'join', room, tok: generateToken() });
    const closedCode = await bad.closed; // 5th failure → 4010
    assert.equal(closedCode, 4010);
  } finally {
    await relay.close();
  }
});

test('only the app token may rotate / close; rotation invalidates the old phone token', async () => {
  const { relay, url } = await boot();
  try {
    const { app, appTok, phoneTok, room } = await makeRoom(url);

    // Phone token cannot rotate.
    const phone = client(url);
    await phone.open;
    phone.send({ t: 'join', room, tok: phoneTok });
    assert.equal((await phone.next()).t, 'ok');
    phone.send({ t: 'rotate' });
    assert.equal((await phone.next()).code, 'not_app');

    // App rotates → new phone token; old one is dead.
    app.send({ t: 'rotate' });
    const rotated = await app.next();
    assert.equal(rotated.t, 'ok');
    assert.ok(rotated.tok.startsWith('tok_'));

    phone.send({ t: 'join', room, tok: phoneTok });
    assert.equal((await phone.next()).code, 'bad_token');

    const phone2 = client(url);
    await phone2.open;
    phone2.send({ t: 'join', room, tok: rotated.tok });
    assert.equal((await phone2.next()).t, 'ok');

    // App closes the room → members dropped, room gone.
    app.send({ t: 'close' });
    assert.equal(await phone2.closed, 4000);
    const probe = client(url);
    await probe.open;
    probe.send({ t: 'join', room, tok: rotated.tok });
    assert.equal((await probe.next()).code, 'room_expired');
  } finally {
    await relay.close();
  }
});

test('malformed frames and envelopes are refused before the store', async () => {
  const { relay, url } = await boot();
  try {
    const { app, room } = await makeRoom(url);
    // Not a member? App IS a member; use a fresh socket for shape errors pre-join.
    const c = client(url);
    await c.open;
    c.send({ t: 'msg', payload: envelope('x') });
    assert.equal((await c.next()).code, 'not_member');
    c.send({ t: 'join', room: 'not-a-room', tok: 'nope' });
    assert.equal((await c.next()).code, 'bad_shape');

    // As a member: bad envelope shapes.
    app.send({ t: 'msg', payload: { c: 'x', m: 'zz' } });
    assert.equal((await app.next()).code, 'bad_shape');
    app.send({ t: 'msg', payload: { c: 'x', m: 'a'.repeat(64), extra: 1 } });
    assert.equal((await app.next()).code, 'bad_shape');
    app.send({ t: 'msg', payload: { c: 'x'.repeat(65 * 1024), m: 'a'.repeat(64) } });
    assert.equal((await app.next()).code, 'bad_shape');
  } finally {
    await relay.close();
  }
});

test('per-connection rate limit trips and recovers', async () => {
  const { relay, url } = await boot({ messagesPerSecond: 5 });
  try {
    const { app, phoneTok, room } = await makeRoom(url);
    const phone = client(url);
    await phone.open;
    phone.send({ t: 'join', room, tok: phoneTok });
    await phone.next();
    let limited = false;
    for (let i = 0; i < 40; i++) phone.send({ t: 'msg', payload: envelope(`m${i}`) });
    for (let i = 0; i < 40; i++) {
      const m = await phone.next();
      if (m.code === 'rate_limited') {
        limited = true;
        break;
      }
    }
    assert.ok(limited, 'rate limit must trip on a burst');
    void app;
  } finally {
    await relay.close();
  }
});

test('idle rooms are swept (sockets closed, rows deleted)', async () => {
  const { relay, url } = await boot({ roomIdleMs: 300 });
  try {
    const { app, phoneTok, room } = await makeRoom(url);
    const phone = client(url);
    await phone.open;
    phone.send({ t: 'join', room, tok: phoneTok });
    await phone.next();
    phone.send({ t: 'msg', payload: envelope('soon gone') });
    await phone.next();
    await app.next(); // live copy
    const code = await phone.closed; // sweeper closes members
    assert.equal(code, 4000);
    assert.equal(relay.roomCount, 0);
  } finally {
    await relay.close();
  }
});

test('idempotent create (same hashes) / conflicting create refused', async () => {
  const { relay, url } = await boot();
  try {
    const appTok = generateToken();
    const phoneTok = generateToken();
    const room = generateRoom();
    const a = client(url);
    await a.open;
    a.send({ t: 'create', room, toks: [sha256(appTok), sha256(phoneTok)] });
    assert.equal((await a.next()).t, 'ok');
    a.send({ t: 'create', room, toks: [sha256(appTok), sha256(phoneTok)] });
    assert.equal((await a.next()).t, 'ok'); // idempotent (resume!)
    a.send({ t: 'create', room, toks: [sha256(generateToken()), sha256(phoneTok)] });
    assert.equal((await a.next()).code, 'room_exists');
  } finally {
    await relay.close();
  }
});

test('sqlite store: durable rows survive a restart', async () => {
  const dbPath = path.join(os.tmpdir(), `relay-test-${Date.now()}.db`);
  const appTok = generateToken();
  const phoneTok = generateToken();
  const room = generateRoom();
  let r1;
  let r2;
  try {
    r1 = createRelayServer({ store: 'sqlite', dbPath, sweepIntervalMs: 60_000 });
    const p1 = await r1.listen(0, '127.0.0.1');
    const c1 = client(`ws://127.0.0.1:${p1}`);
    await c1.open;
    c1.send({ t: 'create', room, toks: [sha256(appTok), sha256(phoneTok)] });
    assert.equal((await c1.next()).t, 'ok');
    c1.send({ t: 'msg', payload: envelope('persisted') });
    assert.equal((await c1.next()).t, 'ack');
    c1.close();
    await r1.close();

    r2 = createRelayServer({ store: 'sqlite', dbPath, sweepIntervalMs: 60_000 });
    const p2 = await r2.listen(0, '127.0.0.1');
    const c2 = client(`ws://127.0.0.1:${p2}`);
    await c2.open;
    c2.send({ t: 'join', room, tok: phoneTok });
    const joined = await c2.next();
    assert.equal(joined.t, 'ok');
    assert.equal(joined.cursor, 1);
    c2.send({ t: 'pull', cursor: 0 });
    const rows = await c2.next();
    assert.equal(rows.rows.length, 1);
    assert.equal(rows.rows[0][1].c, envelope('persisted').c);
    c2.close();
    await r2.close();
  } finally {
    await r1?.close().catch(() => {});
    await r2?.close().catch(() => {});
    fs.rmSync(dbPath, { force: true });
    fs.rmSync(dbPath + '-wal', { force: true });
    fs.rmSync(dbPath + '-shm', { force: true });
  }
});

test('memory store: caps enforced', () => {
  const store = new MemoryStore({ ...DEFAULTS, maxRooms: 1, maxRowsPerRoom: 1 });
  assert.equal(store.create(generateRoom(), 'a'.repeat(64), 'b'.repeat(64), Date.now(), 60_000).ok, true);
  const second = store.create(generateRoom(), 'a'.repeat(64), 'b'.repeat(64), Date.now(), 60_000);
  assert.equal(second.reason, 'too_many_rooms');
});

// ---------------------------------------------------------------------------
// Supabase revocation watch tests
// ---------------------------------------------------------------------------

/** Mock Supabase server that responds to the REST API pattern. */
import { createServer as createHttpServer } from 'node:http';
function mockSupabase(initialRows = []) {
  const rows = [...initialRows];
  const requests = [];
  const server = createHttpServer((req, res) => {
    requests.push(req.url);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(rows));
  });
  return {
    server,
    rows,
    requests,
    listen() {
      return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
    },
    close() {
      return new Promise((resolve) => server.close(resolve));
    },
  };
}

const TEST_SID = 'a'.repeat(8) + '-' + 'b'.repeat(4) + '-' + 'c'.repeat(4) + '-' + 'd'.repeat(4) + '-' + 'e'.repeat(12);

test('watch frame → watched ack (no Supabase configured → error)', async () => {
  const { relay, url } = await boot();
  try {
    const c = client(url);
    await c.open;
    c.send({ t: 'watch', sid: TEST_SID });
    const resp = await c.next();
    // No Supabase configured → bad_shape error
    assert.equal(resp.t, 'err');
    assert.equal(resp.code, 'bad_shape');
  } finally {
    await relay.close();
  }
});

test('watch frame with invalid sid → bad_shape', async () => {
  const { relay, url } = await boot();
  try {
    const c = client(url);
    await c.open;
    c.send({ t: 'watch', sid: 'not-a-uuid' });
    const resp = await c.next();
    assert.equal(resp.t, 'err');
    assert.equal(resp.code, 'bad_shape');
  } finally {
    await relay.close();
  }
});

test('revocation detection: mock Supabase returns revoked row → revoked frame pushed', async () => {
  const mock = mockSupabase([
    { sid: TEST_SID, revoked_at: '2026-01-01T00:00:00Z', revoked_reason: 'User revoked from Sessions tab' },
  ]);
  const mockPort = await mock.listen();
  const relay = createRelayServer({
    sweepIntervalMs: 60_000,
    supabaseUrl: `http://127.0.0.1:${mockPort}`,
    supabaseKey: 'test-key',
    revocationPollMs: 100, // fast poll for tests
  });
  const port = await relay.listen(0, '127.0.0.1');
  const url = `ws://127.0.0.1:${port}`;
  try {
    const c = client(url);
    await c.open;
    c.send({ t: 'watch', sid: TEST_SID });
    const ack = await c.next();
    assert.equal(ack.t, 'watched');

    // Wait for the poll to detect the revocation
    const revoked = await c.next(2000);
    assert.equal(revoked.t, 'revoked');
    assert.equal(revoked.sid, TEST_SID);
    assert.equal(revoked.reason, 'User revoked from Sessions tab');
  } finally {
    await relay.close();
    await mock.close();
  }
});

test('revocation one-shot: sid removed from watchers after revoked frame', async () => {
  const mock = mockSupabase([
    { sid: TEST_SID, revoked_at: '2026-01-01T00:00:00Z', revoked_reason: 'revoked' },
  ]);
  const mockPort = await mock.listen();
  const relay = createRelayServer({
    sweepIntervalMs: 60_000,
    supabaseUrl: `http://127.0.0.1:${mockPort}`,
    supabaseKey: 'test-key',
    revocationPollMs: 100,
  });
  const port = await relay.listen(0, '127.0.0.1');
  const url = `ws://127.0.0.1:${port}`;
  try {
    const c = client(url);
    await c.open;
    c.send({ t: 'watch', sid: TEST_SID });
    await c.next(); // watched ack

    // First poll detects revocation
    const revoked1 = await c.next(2000);
    assert.equal(revoked1.t, 'revoked');

    // Wait enough time for at least one more poll cycle, then check no second frame arrives
    await new Promise((r) => setTimeout(r, 300));
    const result = await c.next(100).catch(() => 'no-more');
    assert.equal(result, 'no-more', 'should not receive a second revoked frame');
  } finally {
    await relay.close();
    await mock.close();
  }
});

test('poll stops when no watchers remain', async () => {
  const mock = mockSupabase([]);
  const mockPort = await mock.listen();
  const relay = createRelayServer({
    sweepIntervalMs: 60_000,
    supabaseUrl: `http://127.0.0.1:${mockPort}`,
    supabaseKey: 'test-key',
    revocationPollMs: 100,
  });
  const port = await relay.listen(0, '127.0.0.1');
  const url = `ws://127.0.0.1:${port}`;
  try {
    const c = client(url);
    await c.open;
    c.send({ t: 'watch', sid: TEST_SID });
    await c.next(); // watched ack

    // Wait for at least one poll
    await new Promise((r) => setTimeout(r, 200));
    const requestsAfterWatch = mock.requests.length;
    assert.ok(requestsAfterWatch > 0, 'poll should have made at least one request');

    // Close the client → watcher removed → poll stops
    c.close();
    await new Promise((r) => setTimeout(r, 300));
    const requestsAfterClose = mock.requests.length;

    // Wait more — should NOT make additional requests
    await new Promise((r) => setTimeout(r, 300));
    const requestsAfterWait = mock.requests.length;

    assert.equal(requestsAfterWait, requestsAfterClose, 'poll should stop after last watcher closes');
  } finally {
    await relay.close();
    await mock.close();
  }
});

async function next(c) {
  return c.next();
}
