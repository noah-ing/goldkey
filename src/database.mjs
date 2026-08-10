import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { ServiceError } from "./errors.mjs";

function tokenHash(value) {
  return createHash("sha256").update(value).digest();
}

function secureEqual(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export class GoldKeyDatabase {
  constructor(filename = ":memory:") {
    if (filename !== ":memory:") mkdirSync(path.dirname(filename), { recursive: true });
    this.db = new DatabaseSync(filename);
    this.db.exec("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
    if (filename !== ":memory:") this.db.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;");
    this.migrate();
  }

  migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS auth_challenges (
        id TEXT PRIMARY KEY,
        wallet TEXT NOT NULL,
        token_id TEXT NOT NULL,
        ownership_epoch TEXT NOT NULL,
        message TEXT NOT NULL,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at INTEGER
      ) STRICT;

      CREATE TABLE IF NOT EXISTS sessions (
        token_hash BLOB PRIMARY KEY,
        wallet TEXT NOT NULL,
        token_id TEXT NOT NULL,
        ownership_epoch TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER,
        last_seen_at INTEGER
      ) STRICT;

      CREATE TABLE IF NOT EXISTS access_keys (
        id TEXT PRIMARY KEY,
        secret_hash BLOB NOT NULL,
        label TEXT NOT NULL,
        issuer_wallet TEXT NOT NULL,
        token_id TEXT NOT NULL,
        term_number TEXT NOT NULL,
        ownership_epoch TEXT NOT NULL,
        allowed_tools_json TEXT NOT NULL,
        max_calls INTEGER NOT NULL,
        used_calls INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER,
        CHECK (max_calls > 0),
        CHECK (used_calls >= 0 AND used_calls <= max_calls)
      ) STRICT;

      CREATE TABLE IF NOT EXISTS usage_terms (
        token_id TEXT NOT NULL,
        term_number TEXT NOT NULL,
        allowance INTEGER NOT NULL,
        used_calls INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (token_id, term_number),
        CHECK (allowance >= 0),
        CHECK (used_calls >= 0 AND used_calls <= allowance)
      ) STRICT, WITHOUT ROWID;

      CREATE TABLE IF NOT EXISTS usage_dedupe (
        token_id TEXT NOT NULL,
        term_number TEXT NOT NULL,
        principal_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        request_hash TEXT NOT NULL,
        tool TEXT NOT NULL,
        response_json TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (token_id, term_number, principal_id, idempotency_key)
      ) STRICT, WITHOUT ROWID;

      CREATE TABLE IF NOT EXISTS usage_daily (
        token_id TEXT NOT NULL,
        term_number TEXT NOT NULL,
        day TEXT NOT NULL,
        tool TEXT NOT NULL,
        calls INTEGER NOT NULL,
        PRIMARY KEY (token_id, term_number, day, tool)
      ) STRICT, WITHOUT ROWID;

      CREATE INDEX IF NOT EXISTS session_expiry_idx ON sessions(expires_at);
      CREATE INDEX IF NOT EXISTS access_key_token_idx ON access_keys(token_id, term_number);
    `);
  }

  close() {
    this.db.close();
  }

  healthCheck() {
    return this.db.prepare("SELECT 1 AS ok").get()?.ok === 1;
  }

  insertChallenge(challenge) {
    const retentionCutoff = challenge.issuedAt - 86_400_000;
    this.db.prepare("DELETE FROM auth_challenges WHERE expires_at < ?").run(retentionCutoff);
    this.db.prepare("DELETE FROM sessions WHERE expires_at < ?").run(retentionCutoff);
    this.db.prepare(`
      INSERT INTO auth_challenges(id, wallet, token_id, ownership_epoch, message, issued_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(challenge.id, challenge.wallet, challenge.tokenId, challenge.ownershipEpoch, challenge.message, challenge.issuedAt, challenge.expiresAt);
  }

  getChallenge(id) {
    return this.db.prepare("SELECT * FROM auth_challenges WHERE id = ?").get(id);
  }

  consumeChallengeAndCreateSession(id, rawToken, session) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const changed = this.db.prepare(`
        UPDATE auth_challenges SET used_at = ?
        WHERE id = ? AND used_at IS NULL AND expires_at > ?
      `).run(session.createdAt, id, session.createdAt).changes;
      if (changed !== 1) throw new ServiceError(409, "challenge_unavailable", "Challenge is expired or already used");
      this.db.prepare(`
        INSERT INTO sessions(token_hash, wallet, token_id, ownership_epoch, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(tokenHash(rawToken), session.wallet, session.tokenId, session.ownershipEpoch, session.createdAt, session.expiresAt);
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  getSession(rawToken, now = Date.now()) {
    const row = this.db.prepare(`
      SELECT wallet, token_id, ownership_epoch, created_at, expires_at, last_seen_at
      FROM sessions
      WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?
    `).get(tokenHash(rawToken), now);
    if (row && (row.last_seen_at === null || row.last_seen_at < now - 60_000)) {
      this.db.prepare("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?").run(now, tokenHash(rawToken));
    }
    return row;
  }

  issueAccessKey({ label, issuerWallet, tokenId, termNumber, ownershipEpoch, allowedTools, maxCalls, expiresAt }) {
    const id = randomBytes(8).toString("hex");
    const rawKey = `gk_${id}.${randomBytes(24).toString("base64url")}`;
    const now = Date.now();
    this.db.prepare(`
      INSERT INTO access_keys(
        id, secret_hash, label, issuer_wallet, token_id, term_number, ownership_epoch,
        allowed_tools_json, max_calls, created_at, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, tokenHash(rawKey), label, issuerWallet, tokenId, termNumber, ownershipEpoch, JSON.stringify(allowedTools), maxCalls, now, expiresAt);
    return { id, rawKey, createdAt: now };
  }

  authenticateAccessKey(rawKey, now = Date.now()) {
    const match = /^gk_([0-9a-f]{16})\./.exec(rawKey);
    if (!match) return undefined;
    const row = this.db.prepare("SELECT * FROM access_keys WHERE id = ?").get(match[1]);
    if (!row || row.revoked_at !== null || row.expires_at <= now || !secureEqual(row.secret_hash, tokenHash(rawKey))) return undefined;
    return { ...row, allowed_tools: JSON.parse(row.allowed_tools_json) };
  }

  listAccessKeys(tokenId, issuerWallet) {
    return this.db.prepare(`
      SELECT id, label, token_id, term_number, ownership_epoch, allowed_tools_json, max_calls,
             used_calls, created_at, expires_at, revoked_at
      FROM access_keys WHERE token_id = ? AND issuer_wallet = ? ORDER BY created_at DESC
    `).all(tokenId, issuerWallet).map((row) => ({ ...row, allowed_tools: JSON.parse(row.allowed_tools_json), allowed_tools_json: undefined }));
  }

  revokeAccessKey(id, tokenId, issuerWallet, now = Date.now()) {
    return this.db.prepare(`
      UPDATE access_keys SET revoked_at = ?
      WHERE id = ? AND token_id = ? AND issuer_wallet = ? AND revoked_at IS NULL
    `).run(now, id, tokenId, issuerWallet).changes === 1;
  }

  countActiveAccessKeys(tokenId, termNumber, ownershipEpoch, issuerWallet, now = Date.now()) {
    const row = this.db.prepare(`
      SELECT COUNT(*) AS count FROM access_keys
      WHERE token_id = ? AND term_number = ? AND ownership_epoch = ? AND issuer_wallet = ?
        AND revoked_at IS NULL AND expires_at > ?
    `).get(tokenId, termNumber, ownershipEpoch, issuerWallet, now);
    return Number(row.count);
  }

  revokeAllAccessKeys(tokenId, termNumber, ownershipEpoch, issuerWallet, now = Date.now()) {
    return Number(this.db.prepare(`
      UPDATE access_keys SET revoked_at = ?
      WHERE token_id = ? AND term_number = ? AND ownership_epoch = ? AND issuer_wallet = ?
        AND revoked_at IS NULL
    `).run(now, tokenId, termNumber, ownershipEpoch, issuerWallet).changes);
  }

  quota(tokenId, termNumber, allowance) {
    const row = this.db.prepare("SELECT used_calls FROM usage_terms WHERE token_id = ? AND term_number = ?").get(tokenId, termNumber);
    const used = row?.used_calls ?? 0;
    return { allowance, used, remaining: Math.max(0, allowance - used) };
  }

  preflight({ tokenId, termNumber, ownershipEpoch, principalId, allowance, idempotencyKey, requestHash, accessKeyId, now = Date.now() }) {
    const replay = this.db.prepare(`
      SELECT request_hash FROM usage_dedupe
      WHERE token_id = ? AND term_number = ? AND principal_id = ? AND idempotency_key = ?
    `).get(tokenId, termNumber, principalId, idempotencyKey);
    if (replay) {
      if (requestHash !== undefined && replay.request_hash !== requestHash) {
        throw new ServiceError(409, "idempotency_conflict", "Idempotency-Key was already used with different input");
      }
      return { replay: true };
    }

    if (accessKeyId) {
      const key = this.db.prepare(`
        SELECT used_calls, max_calls FROM access_keys
        WHERE id = ? AND token_id = ? AND term_number = ? AND ownership_epoch = ?
          AND revoked_at IS NULL AND expires_at > ?
      `).get(accessKeyId, tokenId, termNumber, ownershipEpoch, now);
      if (!key || key.used_calls >= key.max_calls) {
        throw new ServiceError(402, "delegated_key_quota_exhausted", "Delegated key quota is exhausted or inactive");
      }
    }
    const term = this.db.prepare(`
      SELECT used_calls FROM usage_terms WHERE token_id = ? AND term_number = ?
    `).get(tokenId, termNumber);
    if ((term?.used_calls ?? 0) >= allowance) {
      throw new ServiceError(402, "goldkey_quota_exhausted", "GoldKey term quota is exhausted");
    }
    return { replay: false };
  }

  consume({ tokenId, termNumber, ownershipEpoch, principalId, allowance, idempotencyKey, requestHash, tool, baseResponse, accessKeyId }) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const previous = this.db.prepare(`
        SELECT request_hash, response_json FROM usage_dedupe
        WHERE token_id = ? AND term_number = ? AND principal_id = ? AND idempotency_key = ?
      `).get(tokenId, termNumber, principalId, idempotencyKey);
      if (previous) {
        if (previous.request_hash !== requestHash) {
          throw new ServiceError(409, "idempotency_conflict", "Idempotency-Key was already used with different input");
        }
        this.db.exec("COMMIT");
        return { ...baseResponse, ...JSON.parse(previous.response_json), idempotent_replay: true };
      }

      if (accessKeyId) {
        const keyUpdate = this.db.prepare(`
          UPDATE access_keys SET used_calls = used_calls + 1
          WHERE id = ? AND token_id = ? AND term_number = ? AND ownership_epoch = ?
            AND revoked_at IS NULL AND expires_at > ? AND used_calls < max_calls
          RETURNING used_calls, max_calls
        `).get(accessKeyId, tokenId, termNumber, ownershipEpoch, Date.now());
        if (!keyUpdate) throw new ServiceError(402, "delegated_key_quota_exhausted", "Delegated key quota is exhausted or inactive");
      }

      const now = Date.now();
      this.db.prepare(`
        INSERT INTO usage_terms(token_id, term_number, allowance, used_calls, created_at, updated_at)
        VALUES (?, ?, ?, 0, ?, ?)
        ON CONFLICT(token_id, term_number) DO UPDATE SET allowance = excluded.allowance
      `).run(tokenId, termNumber, allowance, now, now);
      const quotaUpdate = this.db.prepare(`
        UPDATE usage_terms SET used_calls = used_calls + 1, updated_at = ?
        WHERE token_id = ? AND term_number = ? AND used_calls < allowance
        RETURNING used_calls, allowance
      `).get(now, tokenId, termNumber);
      if (!quotaUpdate) throw new ServiceError(402, "goldkey_quota_exhausted", "GoldKey term quota is exhausted");

      const response = {
        ...baseResponse,
        quota: {
          charged: true,
          allowance: quotaUpdate.allowance,
          used: quotaUpdate.used_calls,
          remaining: quotaUpdate.allowance - quotaUpdate.used_calls,
        },
      };
      const replayMetadata = { request_id: response.request_id, quota: response.quota };
      this.db.prepare(`
        INSERT INTO usage_dedupe(token_id, term_number, principal_id, idempotency_key, request_hash, tool, response_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(tokenId, termNumber, principalId, idempotencyKey, requestHash, tool, JSON.stringify(replayMetadata), now);
      const day = new Date(now).toISOString().slice(0, 10);
      this.db.prepare(`
        INSERT INTO usage_daily(token_id, term_number, day, tool, calls)
        VALUES (?, ?, ?, ?, 1)
        ON CONFLICT(token_id, term_number, day, tool) DO UPDATE SET calls = calls + 1
      `).run(tokenId, termNumber, day, tool);
      this.db.exec("COMMIT");
      return response;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }
}

export async function createGoldKeyDatabase(config) {
  if (config.databaseUrl) {
    const { PostgresGoldKeyDatabase } = await import("./database-postgres.mjs");
    return PostgresGoldKeyDatabase.connect({
      connectionString: config.databaseUrl,
      poolMax: config.databasePoolMax,
    });
  }
  return new GoldKeyDatabase(config.databasePath);
}

export { tokenHash };
