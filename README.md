# steemauth-relay

**The durable message plane for SteemAuthenticator sessions (protocol v3).**
A single Node process that gives every session a token-authenticated room
with a sequenced log — push for latency, replay for durability — so clients
keep working across refreshes, backgrounded apps and network handoffs
**without any database credential ever reaching a browser or phone**.

```
browser ── wss ──▶ ┌─────────────────────────────┐ ◀── wss ── phone
  create/join/pull  │  steemauth-relay            │   join/pull/msg
  msg → ack        │  rooms · seq · replay · ban │   ready/request/result
                   │  store: memory | sqlite     │
                   └─────────────────────────────┘
```

## Security model

- **E2E encryption** — payloads are `{ c, m }`: AES ciphertext plus an
  HMAC-SHA256 tag both peers derive from the session key `k`. The relay
  can't read messages and can't inject one that survives verification.
- **Token auth, hashed at rest** — the app registers a room with sha256
  hashes of two client-generated secrets (app token + phone token). Joins
  present the token over TLS; the relay compares hashes in constant time.
  Plaintext tokens are never stored or logged. Only the app token may
  rotate the phone token (`rotate`) or close the room (`close`).
- **Unguessable rooms** — `rm_` + 22 random bytes base64url (~176 bits).
- **Abuse limits** — per-connection token bucket (20 msg/s), per-IP
  create/join caps, 5 auth failures → 10-minute IP ban, frame/row/room
  caps, slow-consumer cut (> 1 MB buffered), binary frames refused.
- **Data minimisation** — the entire HTTP API is `GET /healthz` → `ok`.
  No config endpoint, no stats, no payload logging. Rooms and rows expire
  (sliding idle 15 min, hard cap 60 min) and are deleted by the sweeper;
  `close` deletes immediately.
- **Supabase revocation watch** — when `SUPABASE_URL` + `SUPABASE_KEY`
  are configured, connected clients can send `{ t:"watch", sid }` to
  register interest in a session's revocation status. The relay polls
  Supabase for `revoked_at` changes (batched, only while watchers exist)
  and pushes `{ t:"revoked", sid, reason }` to all watching websockets.
  Credentials never leave the relay process. One-shot: once revoked, the
  sid is removed from watchers.

## Run

```bash
npm install -g steemauth-relay     # or: clone && npm ci
PORT=8787 steemauth-relay          # memory store (volatile)

# durable:
STORE=sqlite RELAY_DB=/data/relay.db PORT=8787 steemauth-relay
```

| Env | Default | Meaning |
|---|---|---|
| `PORT` | `8787` | listen port |
| `STORE` | `memory` | `memory` \| `sqlite` (Node ≥ 22) |
| `RELAY_DB` | `./relay.db` | sqlite file when `STORE=sqlite` |
| `ALLOWED_ORIGINS` | *(open)* | comma-separated browser Origin allowlist |
| `MAX_ROOMS` / `ROOM_IDLE_MS` / `MESSAGES_PER_SECOND` | see `DEFAULTS` | limit overrides |
| `SUPABASE_URL` | *(none)* | Supabase project URL for revocation watch |
| `SUPABASE_KEY` | *(none)* | Supabase anon/service key (never leaves the relay) |
| `SUPABASE_TABLE` | `steemauth_sessions` | Supabase table name |
| `REVOCATION_POLL_MS` | `5000` | revocation poll interval (0 = disabled) |

Run behind TLS in production (clients use `wss://`). Docker:
`docker compose up` (mount `/data` for the sqlite store).

## Wire protocol (JSON text frames)

```
client → relay  { t:"create", room, toks:[appHash, phoneHash], ttlMs? }
relay  → client { t:"ok", cursor }              (connection = app member)
client → relay  { t:"join",  room, tok }
relay  → client { t:"ok", cursor }              (phone/app member)
client → relay  { t:"pull",  cursor }
relay  → client { t:"rows",  rows:[[seq, payload], …] }
client → relay  { t:"msg",   payload:{ c, m } }
relay  → client { t:"ack",   seq }              (to sender)
relay  → room   { t:"msg",   seq, payload }     (other members; no echo)
client → relay  { t:"rotate" }  → { t:"ok", tok }   (app token only)
client → relay  { t:"close" }                    (app token only)
client → relay  { t:"ping" }   → { t:"pong" }
client → relay  { t:"watch",  sid }              (Supabase revocation watch)
relay  → client { t:"watched" }                  (ack)
relay  → client { t:"revoked", sid, reason }     (revocation detected)
relay  → client { t:"err", code }   bad_shape · bad_token · room_expired ·
                                    room_exists · too_many_rooms · not_member ·
                                    not_app · rate_limited · room_log_full ·
                                    room_full
```

Close codes: `4000` room expired/closed · `4003` origin not allowed ·
`4004` binary frame · `4010` too many auth failures · `4011` slow consumer ·
`4012` banned · `1001` shutting down.

The full session-level contract (QR fields, envelopes, messages) lives in
the package repo:
[api.md — Protocol](https://github.com/faisalamin9696/steemauth-qr/blob/main/docs/api.md#protocol).

## Programmatic use

```js
import { createRelayServer, generateRoom, generateToken } from 'steemauth-relay';

const relay = createRelayServer({ store: 'sqlite', dbPath: './relay.db' });
const port = await relay.listen(8787);
// … relay.close() on shutdown — rooms + rows SURVIVE (durability first).
```

Tests: `npm test` (node:test — transport, replay, auth, bans, rotation,
sweeper, sqlite durability).

## License

MIT
