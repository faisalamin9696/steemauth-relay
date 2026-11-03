/**
 * Types for the v3 relay server (steemauth-relay).
 */

export interface RelayLimits {
  maxPeersPerRoom?: number;
  maxEnvelopeBytes?: number;
  maxFrameBytes?: number;
  roomTtlMs?: number;
  roomIdleMs?: number;
  maxRowsPerRoom?: number;
  maxRooms?: number;
  messagesPerSecond?: number;
  createsPerMinute?: number;
  joinsPerMinute?: number;
  authFailBanThreshold?: number;
  authFailBanMs?: number;
  sweepIntervalMs?: number;
  maxBufferedBytes?: number;
  /** How often to poll Supabase for revocations (ms). 0 = disabled. */
  revocationPollMs?: number;
}

export interface RoomRecord {
  appHash: string;
  phoneHash: string;
  created: number;
  exp: number;
  last: number;
  nextSeq: number;
}

export interface Store {
  create(
    room: string,
    appHash: string,
    phoneHash: string,
    now: number,
    ttlMs: number,
  ): { ok: boolean; already?: boolean; reason?: string };
  room(room: string): RoomRecord | null;
  touch(room: string, now: number): void;
  setPhoneHash(room: string, phoneHash: string): boolean;
  append(room: string, payload: unknown): number | null | 'full';
  rows(room: string, after: number, limit: number): Array<[number, unknown]>;
  deleteRoom(room: string): boolean;
  sweep(now: number): string[];
  readonly size: number;
  close?(): void;
}

export declare class MemoryStore implements Store {
  constructor(limits?: RelayLimits);
  create(room: string, appHash: string, phoneHash: string, now: number, ttlMs: number): { ok: boolean; already?: boolean; reason?: string };
  room(room: string): RoomRecord | null;
  touch(room: string, now: number): void;
  setPhoneHash(room: string, phoneHash: string): boolean;
  append(room: string, payload: unknown): number | null | 'full';
  rows(room: string, after: number, limit: number): Array<[number, unknown]>;
  deleteRoom(room: string): boolean;
  sweep(now: number): string[];
  readonly size: number;
}

export declare class SqliteStore implements Store {
  constructor(limits?: RelayLimits, dbPath?: string);
  create(room: string, appHash: string, phoneHash: string, now: number, ttlMs: number): { ok: boolean; already?: boolean; reason?: string };
  room(room: string): RoomRecord | null;
  touch(room: string, now: number): void;
  setPhoneHash(room: string, phoneHash: string): boolean;
  append(room: string, payload: unknown): number | null | 'full';
  rows(room: string, after: number, limit: number): Array<[number, unknown]>;
  deleteRoom(room: string): boolean;
  sweep(now: number): string[];
  readonly size: number;
  close(): void;
}

export declare const DEFAULTS: Required<RelayLimits>;

export declare function generateToken(): string;
export declare function generateRoom(): string;

export interface CreateRelayOptions extends RelayLimits {
  store?: 'memory' | 'sqlite' | Store;
  dbPath?: string;
  allowedOrigins?: string[] | null;
  /** Supabase project URL for revocation watch (env: SUPABASE_URL). */
  supabaseUrl?: string;
  /** Supabase anon/service key (env: SUPABASE_KEY). Never leaves the relay. */
  supabaseKey?: string;
  /** Supabase table name (env: SUPABASE_TABLE). Default: steemauth_sessions. */
  supabaseTable?: string;
}

export interface RelayHandle {
  httpServer: import('node:http').Server;
  store: Store;
  listen(port?: number, host?: string): Promise<number>;
  close(): Promise<void>;
  readonly roomCount: number;
}

export declare function createRelayServer(opts?: CreateRelayOptions): RelayHandle;
