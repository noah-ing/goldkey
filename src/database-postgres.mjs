import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { ServiceError } from "./errors.mjs";

const MIGRATION_LOCK_ID = 1_704_011_823;
const MILLIS_FIELDS = new Set([
  "issued_at",
  "expires_at",
  "used_at",
  "created_at",
  "revoked_at",
  "last_seen_at",
  "updated_at",
]);

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS auth_challenges (
    id TEXT PRIMARY KEY,
    wallet TEXT NOT NULL,
    token_id TEXT NOT NULL,
    ownership_epoch TEXT NOT NULL,
    message TEXT NOT NULL,
    issued_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    used_at BIGINT
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash BYTEA PRIMARY KEY,
    wallet TEXT NOT NULL,
    token_id TEXT NOT NULL,
    ownership_epoch TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT,
    last_seen_at BIGINT
  );

  CREATE TABLE IF NOT EXISTS access_keys (
    id TEXT PRIMARY KEY,
    secret_hash BYTEA NOT NULL,
    label TEXT NOT NULL,
    issuer_wallet TEXT NOT NULL,
    token_id TEXT NOT NULL,
    term_number TEXT NOT NULL,
    ownership_epoch TEXT NOT NULL,
    allowed_tools_json TEXT NOT NULL,
    max_calls INTEGER NOT NULL,
    used_calls INTEGER NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT,
    CHECK (max_calls > 0),
    CHECK (used_calls >= 0 AND used_calls <= max_calls)
  );

  CREATE TABLE IF NOT EXISTS usage_terms (
    token_id TEXT NOT NULL,
    term_number TEXT NOT NULL,
    allowance INTEGER NOT NULL,
    used_calls INTEGER NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (token_id, term_number),
    CHECK (allowance >= 0),
    CHECK (used_calls >= 0 AND used_calls <= allowance)
  );

  CREATE TABLE IF NOT EXISTS usage_dedupe (
    token_id TEXT NOT NULL,
    term_number TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    tool TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (token_id, term_number, principal_id, idempotency_key)
  );

  CREATE TABLE IF NOT EXISTS usage_daily (
    token_id TEXT NOT NULL,
    term_number TEXT NOT NULL,
    day TEXT NOT NULL,
    tool TEXT NOT NULL,
    calls INTEGER NOT NULL,
    PRIMARY KEY (token_id, term_number, day, tool)
  );

  CREATE INDEX IF NOT EXISTS session_expiry_idx ON sessions(expires_at);
  CREATE INDEX IF NOT EXISTS access_key_token_idx ON access_keys(token_id, term_number);
`;

function tokenHash(value) {
  return createHash("sha256").update(value).digest();
}

function secureEqual(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function normalizeRow(row) {
  if (!row) return row;
  const normalized = { ...row };
  for (const field of MILLIS_FIELDS) {
    if (normalized[field] !== null && normalized[field] !== undefined) {
      normalized[field] = Number(normalized[field]);
    }
  }
  return normalized;
}

function idempotencyLockKey({ tokenId, termNumber, principalId, idempotencyKey }) {
  return JSON.stringify([tokenId, termNumber, principalId, idempotencyKey]);
}

export class PostgresGoldKeyDatabase {
  constructor({ pool, ownsPool = false } = {}) {
    if (!pool) throw new Error("Postgres pool is required");
    this.ownsPool = ownsPool;
    this.pool = pool;
    this.pool.on?.("error", (error) => {
      console.error(JSON.stringify({ level: "error", event: "postgres_idle_client_error", message: error.message }));
    });
  }

  static async connect({ connectionString, pool, poolMax = 5 } = {}) {
    let databasePool = pool;
    let ownsPool = false;
    if (!databasePool) {
      if (!connectionString) throw new Error("Postgres connectionString is required");
      const pgModule = await import("pg");
      const Pool = pgModule.Pool ?? pgModule.default?.Pool;
      if (!Pool) throw new Error("The pg package does not export Pool");
      databasePool = new Pool({
        connectionString,
        max: poolMax,
        idleTimeoutMillis: 30_000,
        connectionTimeoutMillis: 15_000,
        query_timeout: 20_000,
        statement_timeout: 15_000,
        allowExitOnIdle: true,
        application_name: "goldkey-api",
        enableChannelBinding: true,
      });
      ownsPool = true;
    }
    const database = new PostgresGoldKeyDatabase({ pool: databasePool, ownsPool });
    try {
      await database.migrate();
      return database;
    } catch (error) {
      await database.close().catch(() => {});
      throw error;
    }
  }

  async migrate() {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock($1)", [MIGRATION_LOCK_ID]);
      await client.query(SCHEMA);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async close() {
    if (this.ownsPool) await this.pool.end();
  }

  async healthCheck() {
    const result = await this.pool.query("SELECT 1 AS ok");
    return result.rows[0]?.ok === 1;
  }

  async insertChallenge(challenge) {
    const retentionCutoff = challenge.issuedAt - 86_400_000;
    await this.pool.query("DELETE FROM auth_challenges WHERE expires_at < $1", [retentionCutoff]);
    await this.pool.query("DELETE FROM sessions WHERE expires_at < $1", [retentionCutoff]);
    await this.pool.query(`
      INSERT INTO auth_challenges(id, wallet, token_id, ownership_epoch, message, issued_at, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, [challenge.id, challenge.wallet, challenge.tokenId, challenge.ownershipEpoch, challenge.message, challenge.issuedAt, challenge.expiresAt]);
  }

  async getChallenge(id) {
    const result = await this.pool.query("SELECT * FROM auth_challenges WHERE id = $1", [id]);
    return normalizeRow(result.rows[0]);
  }

  async consumeChallengeAndCreateSession(id, rawToken, session) {
    return this.#transaction(async (client) => {
      const consumed = await client.query(`
        UPDATE auth_challenges SET used_at = $1
        WHERE id = $2 AND used_at IS NULL AND expires_at > $1
        RETURNING id
      `, [session.createdAt, id]);
      if (consumed.rowCount !== 1) throw new ServiceError(409, "challenge_unavailable", "Challenge is expired or already used");
      await client.query(`
        INSERT INTO sessions(token_hash, wallet, token_id, ownership_epoch, created_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
      `, [tokenHash(rawToken), session.wallet, session.tokenId, session.ownershipEpoch, session.createdAt, session.expiresAt]);
    });
  }

  async getSession(rawToken, now = Date.now()) {
    const hash = tokenHash(rawToken);
    const result = await this.pool.query(`
      SELECT wallet, token_id, ownership_epoch, created_at, expires_at, last_seen_at
      FROM sessions
      WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2
    `, [hash, now]);
    const row = normalizeRow(result.rows[0]);
    if (row && (row.last_seen_at === null || row.last_seen_at < now - 60_000)) {
      await this.pool.query("UPDATE sessions SET last_seen_at = $1 WHERE token_hash = $2", [now, hash]);
    }
    return row;
  }

  async issueAccessKey({ label, issuerWallet, tokenId, termNumber, ownershipEpoch, allowedTools, maxCalls, expiresAt }) {
    const id = randomBytes(8).toString("hex");
    const rawKey = `gk_${id}.${randomBytes(24).toString("base64url")}`;
    const now = Date.now();
    await this.pool.query(`
      INSERT INTO access_keys(
        id, secret_hash, label, issuer_wallet, token_id, term_number, ownership_epoch,
        allowed_tools_json, max_calls, created_at, expires_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    `, [id, tokenHash(rawKey), label, issuerWallet, tokenId, termNumber, ownershipEpoch, JSON.stringify(allowedTools), maxCalls, now, expiresAt]);
    return { id, rawKey, createdAt: now };
  }

  async authenticateAccessKey(rawKey, now = Date.now()) {
    const match = /^gk_([0-9a-f]{16})\./.exec(rawKey);
    if (!match) return undefined;
    const result = await this.pool.query("SELECT * FROM access_keys WHERE id = $1", [match[1]]);
    const row = normalizeRow(result.rows[0]);
    if (!row || row.revoked_at !== null || row.expires_at <= now || !secureEqual(row.secret_hash, tokenHash(rawKey))) return undefined;
    return { ...row, allowed_tools: JSON.parse(row.allowed_tools_json) };
  }

  async listAccessKeys(tokenId, issuerWallet) {
    const result = await this.pool.query(`
      SELECT id, label, token_id, term_number, ownership_epoch, allowed_tools_json, max_calls,
             used_calls, created_at, expires_at, revoked_at
      FROM access_keys WHERE token_id = $1 AND issuer_wallet = $2 ORDER BY created_at DESC
    `, [tokenId, issuerWallet]);
    return result.rows.map((value) => {
      const row = normalizeRow(value);
      return { ...row, allowed_tools: JSON.parse(row.allowed_tools_json), allowed_tools_json: undefined };
    });
  }

  async revokeAccessKey(id, tokenId, issuerWallet, now = Date.now()) {
    const result = await this.pool.query(`
      UPDATE access_keys SET revoked_at = $1
      WHERE id = $2 AND token_id = $3 AND issuer_wallet = $4 AND revoked_at IS NULL
    `, [now, id, tokenId, issuerWallet]);
    return result.rowCount === 1;
  }

  async countActiveAccessKeys(tokenId, termNumber, ownershipEpoch, issuerWallet, now = Date.now()) {
    const result = await this.pool.query(`
      SELECT COUNT(*) AS count FROM access_keys
      WHERE token_id = $1 AND term_number = $2 AND ownership_epoch = $3 AND issuer_wallet = $4
        AND revoked_at IS NULL AND expires_at > $5
    `, [tokenId, termNumber, ownershipEpoch, issuerWallet, now]);
    return Number(result.rows[0].count);
  }

  async revokeAllAccessKeys(tokenId, termNumber, ownershipEpoch, issuerWallet, now = Date.now()) {
    const result = await this.pool.query(`
      UPDATE access_keys SET revoked_at = $1
      WHERE token_id = $2 AND term_number = $3 AND ownership_epoch = $4 AND issuer_wallet = $5
        AND revoked_at IS NULL
    `, [now, tokenId, termNumber, ownershipEpoch, issuerWallet]);
    return Number(result.rowCount);
  }

  async quota(tokenId, termNumber, allowance) {
    const result = await this.pool.query("SELECT used_calls FROM usage_terms WHERE token_id = $1 AND term_number = $2", [tokenId, termNumber]);
    const used = Number(result.rows[0]?.used_calls ?? 0);
    return { allowance, used, remaining: Math.max(0, allowance - used) };
  }

  async preflight({ tokenId, termNumber, ownershipEpoch, principalId, allowance, idempotencyKey, requestHash, accessKeyId, now = Date.now() }) {
    const replayResult = await this.pool.query(`
      SELECT request_hash FROM usage_dedupe
      WHERE token_id = $1 AND term_number = $2 AND principal_id = $3 AND idempotency_key = $4
    `, [tokenId, termNumber, principalId, idempotencyKey]);
    const replay = replayResult.rows[0];
    if (replay) {
      if (requestHash !== undefined && replay.request_hash !== requestHash) {
        throw new ServiceError(409, "idempotency_conflict", "Idempotency-Key was already used with different input");
      }
      return { replay: true };
    }

    if (accessKeyId) {
      const keyResult = await this.pool.query(`
        SELECT used_calls, max_calls FROM access_keys
        WHERE id = $1 AND token_id = $2 AND term_number = $3 AND ownership_epoch = $4
          AND revoked_at IS NULL AND expires_at > $5
      `, [accessKeyId, tokenId, termNumber, ownershipEpoch, now]);
      const key = keyResult.rows[0];
      if (!key || key.used_calls >= key.max_calls) {
        throw new ServiceError(402, "delegated_key_quota_exhausted", "Delegated key quota is exhausted or inactive");
      }
    }
    const termResult = await this.pool.query(`
      SELECT used_calls FROM usage_terms WHERE token_id = $1 AND term_number = $2
    `, [tokenId, termNumber]);
    if (Number(termResult.rows[0]?.used_calls ?? 0) >= allowance) {
      throw new ServiceError(402, "goldkey_quota_exhausted", "GoldKey term quota is exhausted");
    }
    return { replay: false };
  }

  async consume({ tokenId, termNumber, ownershipEpoch, principalId, allowance, idempotencyKey, requestHash, tool, baseResponse, accessKeyId }) {
    return this.#transaction(async (client) => {
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0::bigint))", [
        idempotencyLockKey({ tokenId, termNumber, principalId, idempotencyKey }),
      ]);
      const previousResult = await client.query(`
        SELECT request_hash, response_json FROM usage_dedupe
        WHERE token_id = $1 AND term_number = $2 AND principal_id = $3 AND idempotency_key = $4
      `, [tokenId, termNumber, principalId, idempotencyKey]);
      const previous = previousResult.rows[0];
      if (previous) {
        if (previous.request_hash !== requestHash) {
          throw new ServiceError(409, "idempotency_conflict", "Idempotency-Key was already used with different input");
        }
        return { ...baseResponse, ...JSON.parse(previous.response_json), idempotent_replay: true };
      }

      const now = Date.now();
      if (accessKeyId) {
        const keyUpdate = await client.query(`
          UPDATE access_keys SET used_calls = used_calls + 1
          WHERE id = $1 AND token_id = $2 AND term_number = $3 AND ownership_epoch = $4
            AND revoked_at IS NULL AND expires_at > $5 AND used_calls < max_calls
          RETURNING used_calls, max_calls
        `, [accessKeyId, tokenId, termNumber, ownershipEpoch, now]);
        if (keyUpdate.rowCount !== 1) throw new ServiceError(402, "delegated_key_quota_exhausted", "Delegated key quota is exhausted or inactive");
      }

      await client.query(`
        INSERT INTO usage_terms(token_id, term_number, allowance, used_calls, created_at, updated_at)
        VALUES ($1, $2, $3, 0, $4, $4)
        ON CONFLICT(token_id, term_number) DO UPDATE SET allowance = EXCLUDED.allowance
      `, [tokenId, termNumber, allowance, now]);
      const quotaUpdate = await client.query(`
        UPDATE usage_terms SET used_calls = used_calls + 1, updated_at = $1
        WHERE token_id = $2 AND term_number = $3 AND used_calls < allowance
        RETURNING used_calls, allowance
      `, [now, tokenId, termNumber]);
      if (quotaUpdate.rowCount !== 1) throw new ServiceError(402, "goldkey_quota_exhausted", "GoldKey term quota is exhausted");

      const used = Number(quotaUpdate.rows[0].used_calls);
      const effectiveAllowance = Number(quotaUpdate.rows[0].allowance);
      const response = {
        ...baseResponse,
        quota: {
          charged: true,
          allowance: effectiveAllowance,
          used,
          remaining: effectiveAllowance - used,
        },
      };
      const replayMetadata = { request_id: response.request_id, quota: response.quota };
      await client.query(`
        INSERT INTO usage_dedupe(token_id, term_number, principal_id, idempotency_key, request_hash, tool, response_json, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      `, [tokenId, termNumber, principalId, idempotencyKey, requestHash, tool, JSON.stringify(replayMetadata), now]);
      const day = new Date(now).toISOString().slice(0, 10);
      await client.query(`
        INSERT INTO usage_daily(token_id, term_number, day, tool, calls)
        VALUES ($1, $2, $3, $4, 1)
        ON CONFLICT(token_id, term_number, day, tool) DO UPDATE SET calls = usage_daily.calls + 1
      `, [tokenId, termNumber, day, tool]);
      return response;
    });
  }

  async #transaction(operation) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const result = await operation(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }
}

export { SCHEMA as POSTGRES_SCHEMA };
