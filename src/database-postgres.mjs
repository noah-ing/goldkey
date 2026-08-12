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
  "completed_at",
  "committed_at",
  "expired_at",
  "settlement_started_at",
  "payment_settled_at",
  "reviewed_at",
  "retention_expires_at",
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

  CREATE TABLE IF NOT EXISTS pilot_applications (
    id TEXT PRIMARY KEY,
    idempotency_hash TEXT NOT NULL UNIQUE,
    request_hash TEXT NOT NULL,
    source_fingerprint TEXT NOT NULL,
    contact_fingerprint TEXT NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    company TEXT,
    agent_stack TEXT NOT NULL,
    connector TEXT NOT NULL,
    action_text TEXT NOT NULL,
    timeline TEXT,
    budget_confirmed BOOLEAN NOT NULL,
    status TEXT NOT NULL DEFAULT 'received',
    admin_note TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    reviewed_at BIGINT,
    retention_expires_at BIGINT NOT NULL,
    CHECK (idempotency_hash ~ '^[0-9a-f]{64}$'),
    CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    CHECK (source_fingerprint ~ '^[0-9a-f]{64}$'),
    CHECK (contact_fingerprint ~ '^[0-9a-f]{64}$'),
    CHECK (budget_confirmed),
    CHECK (status IN ('received', 'reviewing', 'accepted', 'declined', 'closed')),
    CHECK (updated_at >= created_at),
    CHECK (reviewed_at IS NULL OR reviewed_at >= created_at),
    CHECK (retention_expires_at > created_at)
  );

  CREATE TABLE IF NOT EXISTS guard_policy_versions (
    policy_id TEXT NOT NULL,
    version TEXT NOT NULL,
    policy_hash TEXT NOT NULL UNIQUE,
    policy_json TEXT NOT NULL,
    operator_wallet TEXT NOT NULL,
    operator_signature TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT,
    PRIMARY KEY (policy_id, version),
    CHECK (version ~ '^[1-9][0-9]*$'),
    CHECK (policy_hash ~ '^[0-9a-f]{64}$'),
    CHECK (expires_at > created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
  );

  CREATE TABLE IF NOT EXISTS guard_installations (
    id TEXT PRIMARY KEY,
    operator_wallet TEXT NOT NULL,
    policy_hash TEXT NOT NULL REFERENCES guard_policy_versions(policy_hash),
    public_key_jwk_json TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    operator_signature TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT,
    CHECK (expires_at > created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
  );

  CREATE TABLE IF NOT EXISTS guard_spend_periods (
    reservation_key TEXT PRIMARY KEY,
    cap_atomic NUMERIC(78, 0) NOT NULL,
    reserved_atomic NUMERIC(78, 0) NOT NULL DEFAULT 0,
    spent_atomic NUMERIC(78, 0) NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    CHECK (cap_atomic >= 0),
    CHECK (reserved_atomic >= 0),
    CHECK (spent_atomic >= 0),
    CHECK (reserved_atomic + spent_atomic <= cap_atomic)
  );

  CREATE TABLE IF NOT EXISTS guard_executions (
    id TEXT PRIMARY KEY,
    installation_id TEXT NOT NULL REFERENCES guard_installations(id),
    idempotency_key TEXT NOT NULL,
    call_hash TEXT NOT NULL,
    policy_hash TEXT NOT NULL REFERENCES guard_policy_versions(policy_hash),
    decision TEXT NOT NULL,
    status TEXT NOT NULL,
    authorization_receipt_json TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    reservation_key TEXT,
    reservation_amount_atomic NUMERIC(78, 0),
    completion_receipt_json TEXT,
    outcome_status TEXT,
    outcome_hash TEXT,
    spend_disposition TEXT,
    committed_at BIGINT,
    completed_at BIGINT,
    expired_at BIGINT,
    revoked_at BIGINT,
    settlement_started_at BIGINT,
    settlement_claim_id TEXT,
    settlement_payment_hash TEXT,
    settlement_payment_identity_hash TEXT,
    payment_settled_at BIGINT,
    payment_transaction TEXT,
    UNIQUE (installation_id, idempotency_key),
    CHECK (expires_at > created_at),
    CHECK (decision IN ('ALLOW', 'REVIEW', 'BLOCK')),
    CHECK (status IN ('authorized', 'denied', 'review')),
    CHECK (
      (decision = 'ALLOW' AND status = 'authorized')
      OR (decision = 'BLOCK' AND status = 'denied')
      OR (decision = 'REVIEW' AND status = 'review')
    ),
    CHECK (call_hash ~ '^[0-9a-f]{64}$'),
    CHECK (policy_hash ~ '^[0-9a-f]{64}$'),
    CHECK ((reservation_key IS NULL) = (reservation_amount_atomic IS NULL)),
    CHECK (reservation_amount_atomic IS NULL OR reservation_amount_atomic > 0),
    CHECK ((completed_at IS NULL) = (completion_receipt_json IS NULL)),
    CHECK ((completed_at IS NULL) = (outcome_status IS NULL)),
    CHECK ((completed_at IS NULL) = (outcome_hash IS NULL)),
    CHECK (outcome_status IS NULL OR outcome_status IN ('succeeded', 'failed', 'outcome_unknown')),
    CHECK (outcome_hash IS NULL OR outcome_hash ~ '^[0-9a-f]{64}$'),
    CHECK (completed_at IS NULL OR committed_at IS NOT NULL),
    CHECK (committed_at IS NULL OR (committed_at >= created_at AND committed_at < expires_at)),
    CHECK (completed_at IS NULL OR completed_at >= committed_at),
    CHECK (NOT (expired_at IS NOT NULL AND revoked_at IS NOT NULL)),
    CHECK (committed_at IS NULL OR (expired_at IS NULL AND revoked_at IS NULL)),
    CHECK ((settlement_started_at IS NULL) = (settlement_claim_id IS NULL)),
    CHECK ((settlement_payment_hash IS NULL) = (settlement_payment_identity_hash IS NULL)),
    CHECK (settlement_started_at IS NULL OR settlement_payment_hash IS NOT NULL),
    CHECK (settlement_payment_hash IS NULL OR settlement_payment_hash ~ '^[0-9a-f]{64}$'),
    CHECK (settlement_payment_identity_hash IS NULL OR settlement_payment_identity_hash ~ '^[0-9a-f]{64}$'),
    CHECK (
      (committed_at IS NULL AND expired_at IS NULL AND revoked_at IS NULL AND spend_disposition IS NULL)
      OR (committed_at IS NOT NULL AND expired_at IS NULL AND revoked_at IS NULL AND spend_disposition IN ('committed', 'none'))
      OR (committed_at IS NULL AND completed_at IS NULL AND (expired_at IS NOT NULL OR revoked_at IS NOT NULL)
        AND spend_disposition IN ('released', 'none'))
    ),
    CHECK (expired_at IS NULL OR expired_at >= expires_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
  );

  CREATE TABLE IF NOT EXISTS guard_execution_reservations (
    execution_id TEXT NOT NULL REFERENCES guard_executions(id) ON DELETE CASCADE,
    installation_id TEXT NOT NULL,
    reservation_key TEXT NOT NULL,
    amount_atomic NUMERIC(78, 0) NOT NULL,
    cap_atomic NUMERIC(78, 0) NOT NULL,
    disposition TEXT NOT NULL DEFAULT 'reserved',
    PRIMARY KEY (execution_id, reservation_key),
    FOREIGN KEY (reservation_key) REFERENCES guard_spend_periods(reservation_key),
    CHECK (amount_atomic > 0),
    CHECK (cap_atomic >= amount_atomic),
    CHECK (disposition IN ('reserved', 'committed', 'released'))
  );

  CREATE INDEX IF NOT EXISTS session_expiry_idx ON sessions(expires_at);
  CREATE INDEX IF NOT EXISTS access_key_token_idx ON access_keys(token_id, term_number);
  CREATE INDEX IF NOT EXISTS pilot_application_source_idx ON pilot_applications(source_fingerprint, created_at);
  CREATE INDEX IF NOT EXISTS pilot_application_contact_idx ON pilot_applications(contact_fingerprint, created_at);
  CREATE INDEX IF NOT EXISTS pilot_application_review_idx ON pilot_applications(status, created_at DESC, id DESC);
  CREATE INDEX IF NOT EXISTS pilot_application_retention_idx ON pilot_applications(retention_expires_at);
  CREATE INDEX IF NOT EXISTS guard_installation_policy_idx ON guard_installations(policy_hash);
  CREATE INDEX IF NOT EXISTS guard_execution_installation_idx ON guard_executions(installation_id, created_at);
  CREATE INDEX IF NOT EXISTS guard_reservation_period_idx ON guard_execution_reservations(reservation_key, disposition);
  ALTER TABLE guard_executions ADD COLUMN IF NOT EXISTS payment_settled_at BIGINT;
  ALTER TABLE guard_executions ADD COLUMN IF NOT EXISTS settlement_started_at BIGINT;
  ALTER TABLE guard_executions ADD COLUMN IF NOT EXISTS settlement_claim_id TEXT;
  ALTER TABLE guard_executions ADD COLUMN IF NOT EXISTS payment_transaction TEXT;
  ALTER TABLE guard_executions ADD COLUMN IF NOT EXISTS settlement_payment_hash TEXT;
  ALTER TABLE guard_executions ADD COLUMN IF NOT EXISTS settlement_payment_identity_hash TEXT;
  CREATE UNIQUE INDEX IF NOT EXISTS guard_settlement_payment_identity_unique
    ON guard_executions(settlement_payment_identity_hash)
    WHERE settlement_payment_identity_hash IS NOT NULL;
  CREATE UNIQUE INDEX IF NOT EXISTS guard_payment_transaction_unique
    ON guard_executions(payment_transaction)
    WHERE payment_transaction IS NOT NULL;
  INSERT INTO guard_execution_reservations(
    execution_id, installation_id, reservation_key, amount_atomic, cap_atomic, disposition
  )
  SELECT e.id, e.installation_id, e.reservation_key, e.reservation_amount_atomic, p.cap_atomic,
    CASE
      WHEN e.committed_at IS NOT NULL THEN 'committed'
      WHEN e.expired_at IS NOT NULL OR e.revoked_at IS NOT NULL THEN 'released'
      ELSE 'reserved'
    END
  FROM guard_executions e
  JOIN guard_spend_periods p
    ON p.reservation_key = e.reservation_key
  WHERE e.reservation_key IS NOT NULL
  ON CONFLICT DO NOTHING;
`;

function tokenHash(value) {
  return createHash("sha256").update(value).digest();
}

function secureEqual(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function requireNonEmptyString(value, field) {
  if (typeof value !== "string" || value.length === 0) {
    throw new ServiceError(400, "invalid_guard_record", `${field} must be a non-empty string`);
  }
  return value;
}

function requireJsonObjectText(value, field) {
  requireNonEmptyString(value, field);
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new ServiceError(400, "invalid_guard_record", `${field} must contain valid JSON`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new ServiceError(400, "invalid_guard_record", `${field} must contain a JSON object`);
  }
  return parsed;
}

function requirePublicJwk(value) {
  const jwk = requireJsonObjectText(value, "publicKeyJwkJson");
  for (const privateField of ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]) {
    if (Object.hasOwn(jwk, privateField)) {
      throw new ServiceError(400, "private_jwk_forbidden", "publicKeyJwkJson must not contain private or symmetric key material");
    }
  }
  requireNonEmptyString(jwk.kty, "publicKeyJwkJson.kty");
  return jwk;
}

function requireMillis(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new ServiceError(400, "invalid_guard_record", `${field} must be a non-negative millisecond timestamp`);
  }
  return value;
}

function requireAtomic(value, field, { positive = false } = {}) {
  if (typeof value !== "string" || !/^(0|[1-9]\d*)$/.test(value) || value.length > 78) {
    throw new ServiceError(400, "invalid_guard_record", `${field} must be a canonical atomic-unit integer string`);
  }
  if (positive && value === "0") {
    throw new ServiceError(400, "invalid_guard_record", `${field} must be greater than zero`);
  }
  return value;
}

function requireSha256(value, field) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new ServiceError(400, "invalid_guard_record", `${field} must be a lowercase SHA-256 hex digest`);
  }
  return value;
}

function requirePositiveIntegerString(value, field) {
  if (typeof value !== "string" || !/^[1-9]\d*$/.test(value)) {
    throw new ServiceError(400, "invalid_guard_record", `${field} must be a canonical positive integer string`);
  }
  return value;
}

function normalizeGuardReservations({
  reservations,
  reservationKey,
  reservationAmountAtomic,
  spendCapAtomic,
}) {
  const legacyValues = [reservationKey, reservationAmountAtomic, spendCapAtomic];
  const hasLegacy = legacyValues.some((value) => value !== null && value !== undefined);
  if (reservations !== undefined && hasLegacy) {
    throw new ServiceError(400, "invalid_guard_record", "reservations cannot be combined with legacy reservation fields");
  }
  let values;
  if (reservations !== undefined) {
    if (!Array.isArray(reservations) || reservations.length > 8) {
      throw new ServiceError(400, "invalid_guard_record", "reservations must contain at most eight entries");
    }
    values = reservations;
  } else if (hasLegacy) {
    if (legacyValues.some((value) => value === null || value === undefined)) {
      throw new ServiceError(400, "invalid_guard_record", "reservationKey, reservationAmountAtomic, and spendCapAtomic must be supplied together");
    }
    values = [{ reservationKey, reservationAmountAtomic, spendCapAtomic }];
  } else {
    values = [];
  }
  const normalized = values.map((entry, index) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new ServiceError(400, "invalid_guard_record", `reservations[${index}] must be an object`);
    }
    const extras = Object.keys(entry).filter((key) => !new Set(["reservationKey", "reservationAmountAtomic", "spendCapAtomic"]).has(key));
    if (extras.length > 0) throw new ServiceError(400, "invalid_guard_record", `reservations[${index}] contains unsupported fields`);
    requireNonEmptyString(entry.reservationKey, `reservations[${index}].reservationKey`);
    if (entry.reservationKey.length > 512 || /[\r\n\0]/.test(entry.reservationKey)) {
      throw new ServiceError(400, "invalid_guard_record", `reservations[${index}].reservationKey is not bounded`);
    }
    requireAtomic(entry.reservationAmountAtomic, `reservations[${index}].reservationAmountAtomic`, { positive: true });
    requireAtomic(entry.spendCapAtomic, `reservations[${index}].spendCapAtomic`);
    if (BigInt(entry.reservationAmountAtomic) > BigInt(entry.spendCapAtomic)) {
      throw new ServiceError(402, "guard_spend_cap_exceeded", "Spend reservation exceeds the authoritative period cap");
    }
    return {
      reservationKey: entry.reservationKey,
      reservationAmountAtomic: entry.reservationAmountAtomic,
      spendCapAtomic: entry.spendCapAtomic,
    };
  }).sort((left, right) => left.reservationKey.localeCompare(right.reservationKey));
  if (new Set(normalized.map(({ reservationKey: key }) => key)).size !== normalized.length) {
    throw new ServiceError(400, "invalid_guard_record", "reservations must use distinct reservation keys");
  }
  return normalized;
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

function guardExecutionRow(row) {
  const normalized = normalizeRow(row);
  if (!normalized) return normalized;
  return {
    ...normalized,
    lifecycle_status: normalized.revoked_at !== null
      ? "revoked"
      : normalized.completed_at !== null
        ? "completed"
        : normalized.committed_at !== null
          ? "forwarding"
          : normalized.expired_at !== null
            ? "expired"
            : normalized.status,
  };
}

const PILOT_APPLICATION_STATUSES = new Set(["received", "reviewing", "accepted", "declined", "closed"]);

function requirePilotLimit(value, field, maximum = 10_000) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new ServiceError(400, "invalid_pilot_application", `${field} must be a positive bounded integer`);
  }
  return value;
}

function validatePilotCursor(cursor) {
  if (!cursor || typeof cursor !== "object" || Array.isArray(cursor)) {
    throw new ServiceError(400, "invalid_pilot_application_query", "Invalid pilot application cursor");
  }
  requireMillis(cursor.createdAt, "cursor.createdAt");
  requireNonEmptyString(cursor.id, "cursor.id");
  if (Object.keys(cursor).some((key) => key !== "createdAt" && key !== "id")) {
    throw new ServiceError(400, "invalid_pilot_application_query", "Invalid pilot application cursor");
  }
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

  async createPilotApplication({
    id,
    idempotencyHash,
    requestHash,
    sourceFingerprint,
    contactFingerprint,
    name,
    email,
    company = null,
    agentStack,
    connector,
    action,
    timeline = null,
    budgetConfirmed,
    createdAt,
    retentionExpiresAt,
    limits = {},
  }) {
    for (const [value, field] of [
      [id, "id"], [name, "name"], [email, "email"], [agentStack, "agentStack"],
      [connector, "connector"], [action, "action"],
    ]) requireNonEmptyString(value, field);
    for (const [value, field] of [
      [idempotencyHash, "idempotencyHash"], [requestHash, "requestHash"],
      [sourceFingerprint, "sourceFingerprint"], [contactFingerprint, "contactFingerprint"],
    ]) requireSha256(value, field);
    requireMillis(createdAt, "createdAt");
    requireMillis(retentionExpiresAt, "retentionExpiresAt");
    if (retentionExpiresAt <= createdAt || budgetConfirmed !== true) {
      throw new ServiceError(400, "invalid_pilot_application", "Pilot application retention and budget acknowledgement are invalid");
    }
    const sourceHourlyLimit = requirePilotLimit(limits.sourceHourlyLimit ?? 3, "sourceHourlyLimit");
    const sourceDailyLimit = requirePilotLimit(limits.sourceDailyLimit ?? 10, "sourceDailyLimit");
    const contactDailyLimit = requirePilotLimit(limits.contactDailyLimit ?? 3, "contactDailyLimit");

    return this.#transaction(async (client) => {
      await client.query("DELETE FROM pilot_applications WHERE retention_expires_at <= $1", [createdAt]);
      const lockKeys = [
        `pilot:contact:${contactFingerprint}`,
        `pilot:idempotency:${idempotencyHash}`,
        `pilot:source:${sourceFingerprint}`,
      ].sort();
      for (const lockKey of lockKeys) {
        await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [lockKey]);
      }

      const existingResult = await client.query(
        "SELECT * FROM pilot_applications WHERE idempotency_hash = $1",
        [idempotencyHash],
      );
      const existing = normalizeRow(existingResult.rows[0]);
      if (existing) {
        if (existing.request_hash !== requestHash) {
          throw new ServiceError(409, "pilot_idempotency_conflict", "Idempotency key was already used for a different application");
        }
        return { replay: true, application: existing };
      }

      const countsResult = await client.query(`
        SELECT
          COUNT(*) FILTER (WHERE source_fingerprint = $1 AND created_at >= $3)::integer AS source_hourly,
          COUNT(*) FILTER (WHERE source_fingerprint = $1 AND created_at >= $4)::integer AS source_daily,
          COUNT(*) FILTER (WHERE contact_fingerprint = $2 AND created_at >= $4)::integer AS contact_daily
        FROM pilot_applications
        WHERE (source_fingerprint = $1 AND created_at >= $4)
           OR (contact_fingerprint = $2 AND created_at >= $4)
      `, [sourceFingerprint, contactFingerprint, createdAt - 3_600_000, createdAt - 86_400_000]);
      const counts = countsResult.rows[0];
      if (
        Number(counts.source_hourly) >= sourceHourlyLimit
        || Number(counts.source_daily) >= sourceDailyLimit
        || Number(counts.contact_daily) >= contactDailyLimit
      ) {
        throw new ServiceError(429, "pilot_application_rate_limited", "Too many pilot applications; try again later");
      }

      const inserted = await client.query(`
        INSERT INTO pilot_applications(
          id, idempotency_hash, request_hash, source_fingerprint, contact_fingerprint,
          name, email, company, agent_stack, connector, action_text, timeline,
          budget_confirmed, status, created_at, updated_at, retention_expires_at
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
          TRUE, 'received', $13, $13, $14
        ) RETURNING *
      `, [
        id, idempotencyHash, requestHash, sourceFingerprint, contactFingerprint,
        name, email, company, agentStack, connector, action, timeline,
        createdAt, retentionExpiresAt,
      ]);
      return { replay: false, application: normalizeRow(inserted.rows[0]) };
    });
  }

  async listPilotApplications({ status, limit = 50, cursor, now = Date.now() } = {}) {
    requireMillis(now, "now");
    requirePilotLimit(limit, "limit", 100);
    if (status !== undefined && !PILOT_APPLICATION_STATUSES.has(status)) {
      throw new ServiceError(400, "invalid_pilot_application_query", "Unknown pilot application status");
    }
    await this.purgeExpiredPilotApplications(now);
    const where = ["retention_expires_at > $1"];
    const values = [now];
    if (status !== undefined) {
      values.push(status);
      where.push(`status = $${values.length}`);
    }
    if (cursor !== undefined) {
      validatePilotCursor(cursor);
      values.push(cursor.createdAt);
      const createdIndex = values.length;
      values.push(cursor.id);
      const idIndex = values.length;
      where.push(`(created_at < $${createdIndex} OR (created_at = $${createdIndex} AND id < $${idIndex}))`);
    }
    values.push(limit + 1);
    const result = await this.pool.query(`
      SELECT * FROM pilot_applications
      WHERE ${where.join(" AND ")}
      ORDER BY created_at DESC, id DESC
      LIMIT $${values.length}
    `, values);
    const rows = result.rows.map(normalizeRow);
    return { applications: rows.slice(0, limit), hasMore: rows.length > limit };
  }

  async reviewPilotApplication({ applicationId, status, adminNote, adminNoteProvided = false, reviewedAt = Date.now() }) {
    requireNonEmptyString(applicationId, "applicationId");
    requireMillis(reviewedAt, "reviewedAt");
    if (!PILOT_APPLICATION_STATUSES.has(status)) {
      throw new ServiceError(400, "invalid_pilot_application_review", "Unknown pilot application status");
    }
    if (adminNoteProvided && adminNote !== null && typeof adminNote !== "string") {
      throw new ServiceError(400, "invalid_pilot_application_review", "adminNote must be text or null");
    }
    return this.#transaction(async (client) => {
      await client.query("DELETE FROM pilot_applications WHERE retention_expires_at <= $1", [reviewedAt]);
      const currentResult = await client.query(
        "SELECT * FROM pilot_applications WHERE id = $1 FOR UPDATE",
        [applicationId],
      );
      const current = normalizeRow(currentResult.rows[0]);
      if (!current) throw new ServiceError(404, "pilot_application_not_found", "Pilot application does not exist");
      if (reviewedAt < current.created_at) {
        throw new ServiceError(400, "invalid_pilot_application_review", "Review time precedes the application");
      }
      const updated = await client.query(`
        UPDATE pilot_applications
        SET status = $1,
            admin_note = CASE WHEN $2::boolean THEN $3 ELSE admin_note END,
            reviewed_at = $4, updated_at = $4
        WHERE id = $5 RETURNING *
      `, [status, adminNoteProvided, adminNote ?? null, reviewedAt, applicationId]);
      return normalizeRow(updated.rows[0]);
    });
  }

  async pilotApplicationSummary({ now = Date.now() } = {}) {
    requireMillis(now, "now");
    return this.#transaction(async (client) => {
      await client.query("DELETE FROM pilot_applications WHERE retention_expires_at <= $1", [now]);
      const countsResult = await client.query(`
        SELECT status, COUNT(*)::integer AS count FROM pilot_applications
        WHERE retention_expires_at > $1 GROUP BY status
      `, [now]);
      const newestResult = await client.query(`
        SELECT id AS application_id, created_at, status FROM pilot_applications
        WHERE retention_expires_at > $1 ORDER BY created_at DESC, id DESC LIMIT 1
      `, [now]);
      const countsByStatus = Object.fromEntries([...PILOT_APPLICATION_STATUSES].map((value) => [value, 0]));
      for (const row of countsResult.rows) countsByStatus[row.status] = Number(row.count);
      const totalActive = countsResult.rows.reduce((total, row) => total + Number(row.count), 0);
      return { totalActive, countsByStatus, newest: normalizeRow(newestResult.rows[0]) ?? null };
    });
  }

  async purgeExpiredPilotApplications(now = Date.now()) {
    requireMillis(now, "now");
    const result = await this.pool.query("DELETE FROM pilot_applications WHERE retention_expires_at <= $1", [now]);
    return result.rowCount;
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

  async createGuardPolicyVersion({
    policyId,
    version,
    policyHash,
    policyJson,
    operatorWallet,
    operatorSignature,
    createdAt = Date.now(),
    expiresAt,
    revokedAt = null,
  }) {
    requireNonEmptyString(policyId, "policyId");
    requirePositiveIntegerString(version, "version");
    requireSha256(policyHash, "policyHash");
    requireJsonObjectText(policyJson, "policyJson");
    requireNonEmptyString(operatorWallet, "operatorWallet");
    requireNonEmptyString(operatorSignature, "operatorSignature");
    requireMillis(createdAt, "createdAt");
    requireMillis(expiresAt, "expiresAt");
    if (expiresAt <= createdAt) throw new ServiceError(400, "invalid_guard_record", "expiresAt must be after createdAt");
    if (revokedAt !== null) {
      requireMillis(revokedAt, "revokedAt");
      if (revokedAt < createdAt) throw new ServiceError(400, "invalid_guard_record", "revokedAt must not precede createdAt");
    }
    return this.#transaction(async (client) => {
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0::bigint))", [JSON.stringify(["guard-policy", policyId])]);
      const conflict = await client.query(`
        SELECT policy_id, version, policy_hash FROM guard_policy_versions
        WHERE (policy_id = $1 AND version = $2) OR policy_hash = $3
      `, [policyId, version, policyHash]);
      if (conflict.rowCount !== 0) {
        throw new ServiceError(409, "guard_policy_conflict", "Guard policy version or hash already exists", conflict.rows[0]);
      }
      const latest = await client.query(`
        SELECT version, operator_wallet FROM guard_policy_versions
        WHERE policy_id = $1 ORDER BY length(version) DESC, version DESC LIMIT 1
      `, [policyId]);
      if (latest.rows[0] && latest.rows[0].operator_wallet.toLowerCase() !== operatorWallet.toLowerCase()) {
        throw new ServiceError(409, "guard_policy_operator_change_requires_rotation", "A Guard policy ID cannot change operator without an explicit ownership-rotation protocol", {
          current_operator_wallet: latest.rows[0].operator_wallet,
          requested_operator_wallet: operatorWallet,
        });
      }
      if (latest.rows[0] && BigInt(version) <= BigInt(latest.rows[0].version)) {
        throw new ServiceError(409, "guard_policy_version_not_monotonic", "Guard policy version must increase monotonically", {
          latest_version: latest.rows[0].version,
          requested_version: version,
        });
      }
      const result = await client.query(`
        INSERT INTO guard_policy_versions(
          policy_id, version, policy_hash, policy_json, operator_wallet,
          operator_signature, created_at, expires_at, revoked_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *
      `, [policyId, version, policyHash, policyJson, operatorWallet, operatorSignature, createdAt, expiresAt, revokedAt]);
      return normalizeRow(result.rows[0]);
    });
  }

  async getGuardPolicyVersion(policyId, version) {
    const result = await this.pool.query(`
      SELECT * FROM guard_policy_versions WHERE policy_id = $1 AND version = $2
    `, [policyId, version]);
    return normalizeRow(result.rows[0]);
  }

  async getGuardPolicyVersionByHash(policyHash) {
    const result = await this.pool.query("SELECT * FROM guard_policy_versions WHERE policy_hash = $1", [policyHash]);
    return normalizeRow(result.rows[0]);
  }

  async getLatestGuardPolicyVersion(policyId) {
    const result = await this.pool.query(`
      SELECT * FROM guard_policy_versions
      WHERE policy_id = $1 ORDER BY length(version) DESC, version DESC LIMIT 1
    `, [policyId]);
    return normalizeRow(result.rows[0]);
  }

  async revokeGuardPolicyVersion(policyHash, revokedAt = Date.now()) {
    requireSha256(policyHash, "policyHash");
    requireMillis(revokedAt, "revokedAt");
    return this.#transaction(async (client) => {
      const currentResult = await client.query("SELECT * FROM guard_policy_versions WHERE policy_hash = $1 FOR UPDATE", [policyHash]);
      const current = normalizeRow(currentResult.rows[0]);
      if (!current) throw new ServiceError(404, "guard_policy_not_found", "Guard policy version does not exist");
      if (revokedAt < current.created_at) throw new ServiceError(400, "invalid_guard_record", "revokedAt must not precede createdAt");
      if (current.revoked_at !== null) return current;
      await this.#revokePendingGuardExecutions(client, "policy_hash = $1", [policyHash], revokedAt);
      const updated = await client.query(`
        UPDATE guard_policy_versions SET revoked_at = $1 WHERE policy_hash = $2 AND revoked_at IS NULL RETURNING *
      `, [revokedAt, policyHash]);
      return normalizeRow(updated.rows[0]);
    });
  }

  async createGuardInstallation({
    installationId,
    operatorWallet,
    policyHash,
    publicKeyJwkJson,
    bindingJson,
    operatorSignature,
    createdAt = Date.now(),
    expiresAt,
    revokedAt = null,
  }) {
    requireNonEmptyString(installationId, "installationId");
    requireNonEmptyString(operatorWallet, "operatorWallet");
    requireSha256(policyHash, "policyHash");
    requirePublicJwk(publicKeyJwkJson);
    requireJsonObjectText(bindingJson, "bindingJson");
    requireNonEmptyString(operatorSignature, "operatorSignature");
    requireMillis(createdAt, "createdAt");
    requireMillis(expiresAt, "expiresAt");
    if (expiresAt <= createdAt) throw new ServiceError(400, "invalid_guard_record", "expiresAt must be after createdAt");
    if (revokedAt !== null) {
      requireMillis(revokedAt, "revokedAt");
      if (revokedAt < createdAt) throw new ServiceError(400, "invalid_guard_record", "revokedAt must not precede createdAt");
    }
    return this.#transaction(async (client) => {
      const policyResult = await client.query("SELECT * FROM guard_policy_versions WHERE policy_hash = $1 FOR SHARE", [policyHash]);
      const policy = normalizeRow(policyResult.rows[0]);
      if (!policy) throw new ServiceError(404, "guard_policy_not_found", "Guard policy version does not exist");
      if (policy.operator_wallet !== operatorWallet) {
        throw new ServiceError(409, "guard_operator_mismatch", "Installation operator does not match the policy operator");
      }
      if (policy.expires_at <= createdAt || (policy.revoked_at !== null && policy.revoked_at <= createdAt)) {
        throw new ServiceError(403, "guard_policy_inactive", "Guard policy version is expired or revoked");
      }
      if (expiresAt > policy.expires_at) {
        throw new ServiceError(400, "invalid_guard_record", "Installation cannot outlive its pinned policy version");
      }
      const inserted = await client.query(`
        INSERT INTO guard_installations(
          id, operator_wallet, policy_hash, public_key_jwk_json, binding_json,
          operator_signature, created_at, expires_at, revoked_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT DO NOTHING
        RETURNING *
      `, [installationId, operatorWallet, policyHash, publicKeyJwkJson, bindingJson, operatorSignature, createdAt, expiresAt, revokedAt]);
      if (inserted.rowCount !== 1) {
        throw new ServiceError(409, "guard_installation_conflict", "Guard installation already exists");
      }
      return normalizeRow(inserted.rows[0]);
    });
  }

  async getGuardInstallation(installationId) {
    const result = await this.pool.query("SELECT * FROM guard_installations WHERE id = $1", [installationId]);
    return normalizeRow(result.rows[0]);
  }

  async revokeGuardInstallation(installationId, revokedAt = Date.now()) {
    requireNonEmptyString(installationId, "installationId");
    requireMillis(revokedAt, "revokedAt");
    return this.#transaction(async (client) => {
      const currentResult = await client.query("SELECT * FROM guard_installations WHERE id = $1 FOR UPDATE", [installationId]);
      const current = normalizeRow(currentResult.rows[0]);
      if (!current) throw new ServiceError(404, "guard_installation_not_found", "Guard installation does not exist");
      if (revokedAt < current.created_at) throw new ServiceError(400, "invalid_guard_record", "revokedAt must not precede createdAt");
      if (current.revoked_at !== null) return current;
      await this.#revokePendingGuardExecutions(client, "installation_id = $1", [installationId], revokedAt);
      const updated = await client.query(`
        UPDATE guard_installations SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL RETURNING *
      `, [revokedAt, installationId]);
      return normalizeRow(updated.rows[0]);
    });
  }

  async reserveGuardExecution({
    executionId,
    installationId,
    idempotencyKey,
    callHash,
    policyHash,
    decision,
    status,
    authorizationReceiptJson,
    createdAt = Date.now(),
    expiresAt,
    reservationKey = null,
    reservationAmountAtomic = null,
    spendCapAtomic = null,
    reservations,
  }) {
    for (const [value, field] of [
      [executionId, "executionId"],
      [installationId, "installationId"],
      [idempotencyKey, "idempotencyKey"],
      [decision, "decision"],
      [status, "status"],
    ]) requireNonEmptyString(value, field);
    requireSha256(callHash, "callHash");
    requireSha256(policyHash, "policyHash");
    if (!new Set(["ALLOW", "REVIEW", "BLOCK"]).has(decision)) {
      throw new ServiceError(400, "invalid_guard_record", "decision must be ALLOW, REVIEW, or BLOCK");
    }
    const expectedStatus = { ALLOW: "authorized", REVIEW: "review", BLOCK: "denied" }[decision];
    if (status !== expectedStatus) {
      throw new ServiceError(400, "invalid_guard_record", `status must be ${expectedStatus} for decision ${decision}`);
    }
    requireJsonObjectText(authorizationReceiptJson, "authorizationReceiptJson");
    requireMillis(createdAt, "createdAt");
    requireMillis(expiresAt, "expiresAt");
    if (expiresAt <= createdAt) throw new ServiceError(400, "invalid_guard_record", "expiresAt must be after createdAt");

    const reservationList = normalizeGuardReservations({
      reservations,
      reservationKey,
      reservationAmountAtomic,
      spendCapAtomic,
    });
    const hasReservation = reservationList.length > 0;
    if (hasReservation && status !== "authorized") {
      throw new ServiceError(400, "invalid_guard_record", "Only authorized ALLOW executions may reserve spend");
    }

    return this.#transaction(async (client) => {
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0::bigint))", [
        JSON.stringify(["guard-execution", installationId, idempotencyKey]),
      ]);
      const previousResult = await client.query(`
        SELECT * FROM guard_executions WHERE installation_id = $1 AND idempotency_key = $2
      `, [installationId, idempotencyKey]);
      let previous = previousResult.rows[0];
      if (previous) {
        if (previous.call_hash !== callHash) {
          throw new ServiceError(409, "idempotency_conflict", "Idempotency key was already used with a different call hash");
        }
        if (previous.reservation_key !== null && previous.expired_at === null && Number(previous.expires_at) <= createdAt) {
          await this.#releaseExpiredGuardReservations(client, previous.reservation_key, createdAt);
          previous = (await client.query("SELECT * FROM guard_executions WHERE id = $1", [previous.id])).rows[0];
        }
        return { replay: true, execution: guardExecutionRow(previous) };
      }

      const installationResult = await client.query(`
        SELECT i.*, p.expires_at AS policy_expires_at, p.revoked_at AS policy_revoked_at
        FROM guard_installations i
        JOIN guard_policy_versions p ON p.policy_hash = i.policy_hash
        WHERE i.id = $1
        FOR UPDATE OF i, p
      `, [installationId]);
      const installation = normalizeRow(installationResult.rows[0]);
      if (!installation) throw new ServiceError(404, "guard_installation_not_found", "Guard installation does not exist");
      if (installation.policy_hash !== policyHash) {
        throw new ServiceError(409, "guard_policy_mismatch", "Execution policy hash does not match the installation");
      }
      if (installation.expires_at <= createdAt || installation.revoked_at !== null) {
        throw new ServiceError(403, "guard_installation_inactive", "Guard installation is expired or revoked");
      }
      if (installation.policy_expires_at <= createdAt || installation.policy_revoked_at !== null) {
        throw new ServiceError(403, "guard_policy_inactive", "Guard policy version is expired or revoked");
      }
      if (expiresAt > Math.min(installation.expires_at, installation.policy_expires_at)) {
        throw new ServiceError(400, "invalid_guard_record", "Execution cannot outlive its installation or policy version");
      }

      for (const reservation of reservationList) {
        await this.#releaseExpiredGuardReservations(client, reservation.reservationKey, createdAt);
        const periodUpdate = await client.query(`
          INSERT INTO guard_spend_periods(
            reservation_key, cap_atomic, reserved_atomic, spent_atomic, created_at, updated_at
          ) VALUES ($1, $2::numeric, $3::numeric, 0, $4, $4)
          ON CONFLICT (reservation_key) DO UPDATE
          SET reserved_atomic = guard_spend_periods.reserved_atomic + EXCLUDED.reserved_atomic,
              updated_at = EXCLUDED.updated_at
          WHERE guard_spend_periods.cap_atomic = EXCLUDED.cap_atomic
            AND guard_spend_periods.reserved_atomic + guard_spend_periods.spent_atomic + EXCLUDED.reserved_atomic
              <= guard_spend_periods.cap_atomic
          RETURNING *
        `, [
          reservation.reservationKey,
          reservation.spendCapAtomic,
          reservation.reservationAmountAtomic,
          createdAt,
        ]);
        if (periodUpdate.rowCount !== 1) {
          const period = (await client.query(`
            SELECT * FROM guard_spend_periods WHERE reservation_key = $1
          `, [reservation.reservationKey])).rows[0];
          if (period && String(period.cap_atomic) !== reservation.spendCapAtomic) {
            throw new ServiceError(409, "guard_spend_cap_conflict", "Spend period was already created with a different cap");
          }
          throw new ServiceError(402, "guard_spend_cap_exceeded", "Spend reservation exceeds the authoritative period cap", period ? {
            cap_atomic: String(period.cap_atomic),
            reserved_atomic: String(period.reserved_atomic),
            spent_atomic: String(period.spent_atomic),
            requested_atomic: reservation.reservationAmountAtomic,
          } : undefined);
        }
      }

      const primaryReservation = reservationList[0];

      const inserted = await client.query(`
        INSERT INTO guard_executions(
          id, installation_id, idempotency_key, call_hash, policy_hash, decision, status,
          authorization_receipt_json, created_at, expires_at, reservation_key, reservation_amount_atomic
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::numeric)
        ON CONFLICT DO NOTHING
        RETURNING *
      `, [
        executionId,
        installationId,
        idempotencyKey,
        callHash,
        policyHash,
        decision,
        status,
        authorizationReceiptJson,
        createdAt,
        expiresAt,
        primaryReservation?.reservationKey ?? null,
        primaryReservation?.reservationAmountAtomic ?? null,
      ]);
      if (inserted.rowCount !== 1) throw new ServiceError(409, "guard_execution_conflict", "Guard execution identifier already exists");
      for (const reservation of reservationList) {
        const reservationInsert = await client.query(`
          INSERT INTO guard_execution_reservations(
            execution_id, installation_id, reservation_key, amount_atomic, cap_atomic, disposition
          ) VALUES ($1, $2, $3, $4::numeric, $5::numeric, 'reserved')
          ON CONFLICT DO NOTHING
          RETURNING execution_id
        `, [
          executionId,
          installationId,
          reservation.reservationKey,
          reservation.reservationAmountAtomic,
          reservation.spendCapAtomic,
        ]);
        if (reservationInsert.rowCount !== 1) throw new ServiceError(409, "guard_execution_conflict", "Guard execution reservation already exists");
      }
      return { replay: false, execution: guardExecutionRow(inserted.rows[0]) };
    });
  }

  async getGuardExecution(executionId) {
    const result = await this.pool.query("SELECT * FROM guard_executions WHERE id = $1", [executionId]);
    return guardExecutionRow(result.rows[0]);
  }

  async getGuardExecutionByIdempotency(installationId, idempotencyKey) {
    const result = await this.pool.query(`
      SELECT * FROM guard_executions WHERE installation_id = $1 AND idempotency_key = $2
    `, [installationId, idempotencyKey]);
    return guardExecutionRow(result.rows[0]);
  }

  async beginGuardExecutionSettlement({
    installationId,
    idempotencyKey,
    callHash,
    settlementClaimId,
    paymentSha256,
    paymentIdentitySha256,
    startedAt = Date.now(),
  }) {
    requireNonEmptyString(installationId, "installationId");
    requireNonEmptyString(idempotencyKey, "idempotencyKey");
    requireSha256(callHash, "callHash");
    requireNonEmptyString(settlementClaimId, "settlementClaimId");
    if (settlementClaimId.length > 128) throw new ServiceError(400, "invalid_guard_record", "settlementClaimId is too long");
    requireSha256(paymentSha256, "paymentSha256");
    requireSha256(paymentIdentitySha256, "paymentIdentitySha256");
    requireMillis(startedAt, "startedAt");
    return this.#transaction(async (client) => {
      const identity = await client.query(`
        SELECT id, policy_hash FROM guard_executions
        WHERE installation_id = $1 AND idempotency_key = $2
      `, [installationId, idempotencyKey]);
      if (identity.rowCount === 0) throw new ServiceError(404, "guard_execution_not_found", "Guard execution does not exist for settlement");
      const policyResult = await client.query("SELECT * FROM guard_policy_versions WHERE policy_hash = $1 FOR SHARE", [identity.rows[0].policy_hash]);
      const installationResult = await client.query("SELECT * FROM guard_installations WHERE id = $1 FOR SHARE", [installationId]);
      const current = await client.query("SELECT * FROM guard_executions WHERE id = $1 FOR UPDATE", [identity.rows[0].id]);
      const policy = normalizeRow(policyResult.rows[0]);
      const installation = normalizeRow(installationResult.rows[0]);
      const currentExecution = normalizeRow(current.rows[0]);
      const execution = currentExecution && installation && policy ? {
        ...currentExecution,
        installation_expires_at: installation.expires_at,
        installation_revoked_at: installation.revoked_at,
        policy_expires_at: policy.expires_at,
        policy_revoked_at: policy.revoked_at,
      } : undefined;
      if (!execution) throw new ServiceError(404, "guard_execution_not_found", "Guard execution does not exist for settlement");
      if (execution.installation_id !== installationId || execution.policy_hash !== policy.policy_hash || installation.policy_hash !== policy.policy_hash) {
        throw new ServiceError(409, "guard_binding_changed", "Guard settlement binding changed concurrently");
      }
      if (execution.call_hash !== callHash) throw new ServiceError(409, "idempotency_conflict", "Settlement request does not match the stored call hash");
      if (execution.revoked_at !== null || execution.expired_at !== null || execution.committed_at !== null) {
        throw new ServiceError(409, "guard_execution_inactive", "Guard execution is no longer eligible for settlement");
      }
      if (startedAt < execution.created_at || startedAt >= execution.expires_at) {
        throw new ServiceError(409, "guard_execution_expired", "Guard execution expired before settlement began");
      }
      if (execution.installation_revoked_at !== null || execution.installation_expires_at <= startedAt) {
        throw new ServiceError(409, "guard_installation_inactive", "Guard installation is inactive before settlement");
      }
      if (execution.policy_revoked_at !== null || execution.policy_expires_at <= startedAt) {
        throw new ServiceError(409, "guard_policy_inactive", "Guard policy is inactive before settlement");
      }
      if (execution.payment_settled_at !== null) throw new ServiceError(409, "guard_payment_already_settled", "Guard authorization payment is already settled");
      if (execution.settlement_started_at !== null) throw new ServiceError(409, "guard_settlement_in_progress", "A Guard settlement is already in progress");
      if (
        execution.settlement_payment_hash !== null
        && (execution.settlement_payment_hash !== paymentSha256 || execution.settlement_payment_identity_hash !== paymentIdentitySha256)
      ) {
        throw new ServiceError(409, "guard_payment_binding_changed", "Guard execution is already bound to a different payment authorization");
      }
      const reusedIdentity = await client.query(`
        SELECT id FROM guard_executions
        WHERE settlement_payment_identity_hash = $1 AND id <> $2
      `, [paymentIdentitySha256, execution.id]);
      if (reusedIdentity.rowCount > 0) throw new ServiceError(409, "guard_payment_identity_reused", "EIP-3009 payment authorization is already bound to another Guard execution");
      const updated = await client.query(`
        UPDATE guard_executions SET settlement_started_at = $1, settlement_claim_id = $2,
          settlement_payment_hash = $3, settlement_payment_identity_hash = $4
        WHERE id = $5 AND settlement_started_at IS NULL AND payment_settled_at IS NULL
        RETURNING *
      `, [startedAt, settlementClaimId, paymentSha256, paymentIdentitySha256, execution.id]);
      if (updated.rowCount !== 1) throw new ServiceError(409, "guard_settlement_conflict", "Guard settlement claim changed concurrently");
      return { replay: false, execution: guardExecutionRow(updated.rows[0]) };
    }).catch((error) => {
      if (error?.code === "23505" && error?.constraint === "guard_settlement_payment_identity_unique") {
        throw new ServiceError(409, "guard_payment_identity_reused", "EIP-3009 payment authorization is already bound to another Guard execution");
      }
      throw error;
    });
  }

  async cancelGuardExecutionSettlement({ installationId, idempotencyKey, callHash, settlementClaimId, canceledAt = Date.now() }) {
    requireNonEmptyString(installationId, "installationId");
    requireNonEmptyString(idempotencyKey, "idempotencyKey");
    requireSha256(callHash, "callHash");
    requireNonEmptyString(settlementClaimId, "settlementClaimId");
    requireMillis(canceledAt, "canceledAt");
    return this.#transaction(async (client) => {
      const current = await client.query(`
        SELECT * FROM guard_executions
        WHERE installation_id = $1 AND idempotency_key = $2
        FOR UPDATE
      `, [installationId, idempotencyKey]);
      const execution = normalizeRow(current.rows[0]);
      if (!execution) throw new ServiceError(404, "guard_execution_not_found", "Guard execution does not exist for settlement cancellation");
      if (execution.call_hash !== callHash) throw new ServiceError(409, "idempotency_conflict", "Settlement cancellation does not match the stored call hash");
      if (execution.settlement_claim_id !== null && execution.settlement_claim_id !== settlementClaimId) {
        throw new ServiceError(409, "guard_settlement_claim_mismatch", "Settlement cancellation does not own the active claim");
      }
      if (execution.payment_settled_at !== null || execution.settlement_started_at === null) {
        return { replay: true, execution: guardExecutionRow(execution) };
      }
      const updated = await client.query(`
        UPDATE guard_executions SET settlement_started_at = NULL, settlement_claim_id = NULL
        WHERE id = $1 AND payment_settled_at IS NULL
        RETURNING *
      `, [execution.id]);
      if (updated.rowCount !== 1) throw new ServiceError(409, "guard_settlement_conflict", "Guard settlement claim changed concurrently");
      const bindingResult = await client.query(`
        SELECT i.revoked_at AS installation_revoked_at, p.revoked_at AS policy_revoked_at
        FROM guard_installations i JOIN guard_policy_versions p ON p.policy_hash = i.policy_hash
        WHERE i.id = $1 AND p.policy_hash = $2
      `, [execution.installation_id, execution.policy_hash]);
      const binding = normalizeRow(bindingResult.rows[0]);
      if (binding && (binding.installation_revoked_at !== null || binding.policy_revoked_at !== null)) {
        const transitioned = await this.#transitionGuardExecutionReservations(client, execution, "released", canceledAt);
        const revoked = await client.query(`
          UPDATE guard_executions SET revoked_at = $1, spend_disposition = $2
          WHERE id = $3 AND committed_at IS NULL AND completed_at IS NULL AND expired_at IS NULL AND revoked_at IS NULL
          RETURNING *
        `, [canceledAt, transitioned.count > 0 ? "released" : "none", execution.id]);
        if (revoked.rowCount !== 1) throw new ServiceError(409, "guard_execution_finalized", "Guard execution changed while canceling settlement");
        return { replay: false, execution: guardExecutionRow(revoked.rows[0]) };
      }
      return { replay: false, execution: guardExecutionRow(updated.rows[0]) };
    });
  }

  async markGuardExecutionPaymentSettled({
    installationId,
    idempotencyKey,
    callHash,
    settlementClaimId,
    paymentSha256,
    paymentIdentitySha256,
    settledAt = Date.now(),
    transaction = null,
  }) {
    requireNonEmptyString(installationId, "installationId");
    requireNonEmptyString(idempotencyKey, "idempotencyKey");
    requireSha256(callHash, "callHash");
    requireNonEmptyString(settlementClaimId, "settlementClaimId");
    requireSha256(paymentSha256, "paymentSha256");
    requireSha256(paymentIdentitySha256, "paymentIdentitySha256");
    requireMillis(settledAt, "settledAt");
    if (transaction !== null && (typeof transaction !== "string" || transaction.length < 1 || transaction.length > 512)) {
      throw new ServiceError(400, "invalid_guard_record", "transaction must be null or a bounded settlement identifier");
    }
    return this.#transaction(async (client) => {
      const current = await client.query(`
        SELECT * FROM guard_executions
        WHERE installation_id = $1 AND idempotency_key = $2
        FOR UPDATE
      `, [installationId, idempotencyKey]);
      const execution = normalizeRow(current.rows[0]);
      if (!execution) throw new ServiceError(404, "guard_execution_not_found", "Guard execution does not exist for the settled request");
      if (execution.call_hash !== callHash) throw new ServiceError(409, "idempotency_conflict", "Settled request does not match the stored call hash");
      if (execution.settlement_started_at === null) throw new ServiceError(409, "guard_settlement_not_started", "Guard settlement must be claimed before it can be marked successful");
      if (execution.settlement_claim_id !== settlementClaimId) throw new ServiceError(409, "guard_settlement_claim_mismatch", "Settled request does not own the active claim");
      if (execution.settlement_payment_hash !== paymentSha256 || execution.settlement_payment_identity_hash !== paymentIdentitySha256) {
        throw new ServiceError(409, "guard_payment_proof_mismatch", "Settled payment proof does not match the claimed payment authorization");
      }
      if (execution.payment_settled_at !== null) {
        if (transaction !== null && execution.payment_transaction !== transaction) {
          throw new ServiceError(409, "guard_payment_transaction_mismatch", "Guard execution is already bound to a different payment transaction");
        }
        return { replay: true, execution: guardExecutionRow(execution) };
      }
      if (transaction !== null) {
        const reusedTransaction = await client.query(`
          SELECT id FROM guard_executions WHERE payment_transaction = $1 AND id <> $2
        `, [transaction, execution.id]);
        if (reusedTransaction.rowCount > 0) throw new ServiceError(409, "guard_payment_transaction_reused", "Payment transaction is already bound to another Guard execution");
      }
      const updated = await client.query(`
        UPDATE guard_executions SET payment_settled_at = $1, payment_transaction = $2
        WHERE id = $3 AND payment_settled_at IS NULL
        RETURNING *
      `, [settledAt, transaction, execution.id]);
      if (updated.rowCount !== 1) throw new ServiceError(409, "guard_settlement_conflict", "Guard settlement marker changed concurrently");
      return { replay: false, execution: guardExecutionRow(updated.rows[0]) };
    }).catch((error) => {
      if (error?.code === "23505" && error?.constraint === "guard_payment_transaction_unique") {
        throw new ServiceError(409, "guard_payment_transaction_reused", "Payment transaction is already bound to another Guard execution");
      }
      throw error;
    });
  }

  async getGuardSpendPeriod(installationId, reservationKey) {
    requireNonEmptyString(installationId, "installationId");
    requireNonEmptyString(reservationKey, "reservationKey");
    const result = await this.pool.query(`
      SELECT * FROM guard_spend_periods WHERE reservation_key = $1
    `, [reservationKey]);
    return normalizeRow(result.rows[0]);
  }

  async sweepExpiredGuardReservations(installationId, reservationKey, now = Date.now()) {
    requireNonEmptyString(installationId, "installationId");
    requireNonEmptyString(reservationKey, "reservationKey");
    requireMillis(now, "now");
    return this.#transaction((client) => this.#releaseExpiredGuardReservations(client, reservationKey, now));
  }

  async commitGuardExecution({ executionId, committedAt = Date.now(), paymentReconciliation } = {}) {
    requireNonEmptyString(executionId, "executionId");
    requireMillis(committedAt, "committedAt");
    if (paymentReconciliation !== undefined) {
      if (!paymentReconciliation || typeof paymentReconciliation !== "object" || Array.isArray(paymentReconciliation)) {
        throw new ServiceError(400, "invalid_guard_record", "paymentReconciliation must be an object");
      }
      requireSha256(paymentReconciliation.paymentSha256, "paymentReconciliation.paymentSha256");
      requireSha256(paymentReconciliation.paymentIdentitySha256, "paymentReconciliation.paymentIdentitySha256");
      requireMillis(paymentReconciliation.settledAt, "paymentReconciliation.settledAt");
      if (typeof paymentReconciliation.transaction !== "string" || !/^0x[0-9a-f]{64}$/.test(paymentReconciliation.transaction)) {
        throw new ServiceError(400, "invalid_guard_record", "paymentReconciliation.transaction must be a lowercase EVM transaction hash");
      }
    }
    return this.#transaction(async (client) => {
      const identityResult = await client.query("SELECT installation_id, policy_hash FROM guard_executions WHERE id = $1", [executionId]);
      const identity = normalizeRow(identityResult.rows[0]);
      if (!identity) throw new ServiceError(404, "guard_execution_not_found", "Guard execution does not exist");
      const policyResult = await client.query("SELECT * FROM guard_policy_versions WHERE policy_hash = $1 FOR SHARE", [identity.policy_hash]);
      const installationResult = await client.query("SELECT * FROM guard_installations WHERE id = $1 FOR SHARE", [identity.installation_id]);
      const currentResult = await client.query("SELECT * FROM guard_executions WHERE id = $1 FOR UPDATE", [executionId]);
      let execution = normalizeRow(currentResult.rows[0]);
      if (!execution) throw new ServiceError(404, "guard_execution_not_found", "Guard execution does not exist");
      const policy = normalizeRow(policyResult.rows[0]);
      const installation = normalizeRow(installationResult.rows[0]);
      if (!policy || !installation || execution.policy_hash !== policy.policy_hash || execution.installation_id !== installation.id || installation.policy_hash !== policy.policy_hash) {
        throw new ServiceError(409, "guard_binding_changed", "Guard execution binding changed concurrently");
      }
      if (paymentReconciliation !== undefined) {
        if (execution.settlement_started_at === null || execution.settlement_claim_id === null) {
          throw new ServiceError(409, "guard_settlement_not_started", "Guard payment reconciliation requires an active settlement claim");
        }
        if (
          execution.settlement_payment_hash !== paymentReconciliation.paymentSha256
          || execution.settlement_payment_identity_hash !== paymentReconciliation.paymentIdentitySha256
        ) {
          throw new ServiceError(409, "guard_payment_proof_mismatch", "Reconciled payment proof does not match the claimed payment authorization");
        }
        if (execution.payment_settled_at !== null) {
          if (execution.payment_transaction !== paymentReconciliation.transaction) {
            throw new ServiceError(409, "guard_payment_transaction_mismatch", "Guard execution is already bound to a different payment transaction");
          }
        } else {
          const reusedTransaction = await client.query(`
            SELECT id FROM guard_executions WHERE payment_transaction = $1 AND id <> $2
          `, [paymentReconciliation.transaction, execution.id]);
          if (reusedTransaction.rowCount > 0) throw new ServiceError(409, "guard_payment_transaction_reused", "Payment transaction is already bound to another Guard execution");
          const reconciled = await client.query(`
            UPDATE guard_executions SET payment_settled_at = $1, payment_transaction = $2
            WHERE id = $3 AND payment_settled_at IS NULL
            RETURNING *
          `, [paymentReconciliation.settledAt, paymentReconciliation.transaction, execution.id]);
          if (reconciled.rowCount !== 1) throw new ServiceError(409, "guard_settlement_conflict", "Guard payment marker changed concurrently");
          execution = normalizeRow(reconciled.rows[0]);
        }
      }
      if (execution.committed_at !== null) {
        return { replay: true, execution: guardExecutionRow(execution) };
      }
      if (execution.revoked_at !== null) throw new ServiceError(409, "guard_execution_revoked", "Guard execution is revoked");
      if (execution.expired_at !== null) throw new ServiceError(409, "guard_execution_expired", "Guard execution authorization expired");
      if (execution.status !== "authorized" || execution.decision !== "ALLOW") {
        throw new ServiceError(409, "guard_execution_not_authorized", "Only an authorized ALLOW execution can be committed");
      }
      if (execution.payment_settled_at === null) {
        throw new ServiceError(409, "guard_payment_not_settled", "Guard authorization payment must settle before forwarding can be committed");
      }
      if (committedAt < execution.created_at || committedAt >= execution.expires_at) {
        throw new ServiceError(409, "guard_execution_expired", "Guard execution must be committed before its authorization expires");
      }
      const binding = {
        installation_expires_at: installation.expires_at,
        installation_revoked_at: installation.revoked_at,
        policy_expires_at: policy.expires_at,
        policy_revoked_at: policy.revoked_at,
      };
      const installationClaimWon = binding.installation_revoked_at !== null
        && execution.settlement_started_at !== null
        && binding.installation_revoked_at >= execution.settlement_started_at;
      if (!binding || (binding.installation_revoked_at !== null && !installationClaimWon) || binding.installation_expires_at <= committedAt) {
        throw new ServiceError(409, "guard_installation_inactive", "Guard installation was revoked or expired before commit");
      }
      const policyClaimWon = binding.policy_revoked_at !== null
        && execution.settlement_started_at !== null
        && binding.policy_revoked_at >= execution.settlement_started_at;
      if ((binding.policy_revoked_at !== null && !policyClaimWon) || binding.policy_expires_at <= committedAt) {
        throw new ServiceError(409, "guard_policy_inactive", "Guard policy was revoked or expired before commit");
      }
      const transitionedReservations = await this.#transitionGuardExecutionReservations(client, execution, "committed", committedAt);
      const hasReservation = transitionedReservations.count > 0;
      const committed = await client.query(`
        UPDATE guard_executions
        SET committed_at = $1, spend_disposition = $2
        WHERE id = $3 AND committed_at IS NULL AND completed_at IS NULL AND expired_at IS NULL AND revoked_at IS NULL
        RETURNING *
      `, [committedAt, hasReservation ? "committed" : "none", executionId]);
      if (committed.rowCount !== 1) throw new ServiceError(409, "guard_execution_finalized", "Guard execution changed while committing");
      return { replay: false, execution: guardExecutionRow(committed.rows[0]) };
    }).catch((error) => {
      if (error?.code === "23505" && error?.constraint === "guard_payment_transaction_unique") {
        throw new ServiceError(409, "guard_payment_transaction_reused", "Payment transaction is already bound to another Guard execution");
      }
      throw error;
    });
  }

  async completeGuardExecution({
    executionId,
    completionReceiptJson,
    outcomeStatus,
    outcomeHash,
    completedAt = Date.now(),
  }) {
    requireNonEmptyString(executionId, "executionId");
    requireJsonObjectText(completionReceiptJson, "completionReceiptJson");
    if (!new Set(["succeeded", "failed", "outcome_unknown"]).has(outcomeStatus)) {
      throw new ServiceError(400, "invalid_guard_record", "outcomeStatus must be succeeded, failed, or outcome_unknown");
    }
    requireSha256(outcomeHash, "outcomeHash");
    requireMillis(completedAt, "completedAt");
    return this.#transaction(async (client) => {
      const currentResult = await client.query("SELECT * FROM guard_executions WHERE id = $1 FOR UPDATE", [executionId]);
      const execution = normalizeRow(currentResult.rows[0]);
      if (!execution) throw new ServiceError(404, "guard_execution_not_found", "Guard execution does not exist");
      if (execution.completed_at !== null) {
        if (
          execution.completion_receipt_json !== completionReceiptJson
          || execution.outcome_status !== outcomeStatus
          || execution.outcome_hash !== outcomeHash
        ) throw new ServiceError(409, "guard_execution_finalized", "Guard execution was already completed differently");
        return { replay: true, execution: guardExecutionRow(execution) };
      }
      if (execution.committed_at === null) {
        throw new ServiceError(409, "guard_execution_not_committed", "Guard execution must be committed before completion");
      }
      if (completedAt < execution.committed_at) {
        throw new ServiceError(400, "invalid_guard_record", "completedAt must not precede committedAt");
      }
      const completed = await client.query(`
        UPDATE guard_executions
        SET completion_receipt_json = $1, outcome_status = $2, outcome_hash = $3, completed_at = $4
        WHERE id = $5 AND committed_at IS NOT NULL AND completed_at IS NULL
        RETURNING *
      `, [completionReceiptJson, outcomeStatus, outcomeHash, completedAt, executionId]);
      if (completed.rowCount !== 1) throw new ServiceError(409, "guard_execution_finalized", "Guard execution changed while completing");
      return { replay: false, execution: guardExecutionRow(completed.rows[0]) };
    });
  }

  async revokeGuardExecution(executionId, revokedAt = Date.now()) {
    requireNonEmptyString(executionId, "executionId");
    requireMillis(revokedAt, "revokedAt");
    return this.#transaction(async (client) => {
      const currentResult = await client.query("SELECT * FROM guard_executions WHERE id = $1 FOR UPDATE", [executionId]);
      const execution = normalizeRow(currentResult.rows[0]);
      if (!execution) throw new ServiceError(404, "guard_execution_not_found", "Guard execution does not exist");
      if (execution.completed_at !== null) throw new ServiceError(409, "guard_execution_finalized", "Completed execution cannot be revoked");
      if (execution.committed_at !== null) throw new ServiceError(409, "guard_execution_committed", "Committed execution cannot be revoked");
      if (execution.expired_at !== null) throw new ServiceError(409, "guard_execution_expired", "Expired execution cannot be revoked");
      if (execution.revoked_at !== null) return { replay: true, execution: guardExecutionRow(execution) };
      if (revokedAt < execution.created_at) throw new ServiceError(400, "invalid_guard_record", "revokedAt must not precede createdAt");
      if (execution.settlement_started_at !== null && execution.expires_at > revokedAt) {
        throw new ServiceError(409, "guard_settlement_in_progress", "Guard settlement or paid authorization is still within its commit window");
      }
      const transitionedReservations = await this.#transitionGuardExecutionReservations(client, execution, "released", revokedAt);
      const hasReservation = transitionedReservations.count > 0;
      const revoked = await client.query(`
        UPDATE guard_executions SET revoked_at = $1, spend_disposition = $2
        WHERE id = $3 AND committed_at IS NULL AND completed_at IS NULL AND expired_at IS NULL AND revoked_at IS NULL
        RETURNING *
      `, [revokedAt, hasReservation ? "released" : "none", executionId]);
      if (revoked.rowCount !== 1) throw new ServiceError(409, "guard_execution_finalized", "Guard execution changed while revoking");
      return { replay: false, execution: guardExecutionRow(revoked.rows[0]) };
    });
  }

  async #releaseExpiredGuardReservations(client, reservationKey, now) {
    const expiredResult = await client.query(`
      SELECT DISTINCT e.*
      FROM guard_executions e
      JOIN guard_execution_reservations r ON r.execution_id = e.id
      WHERE r.reservation_key = $1 AND r.disposition = 'reserved'
        AND e.committed_at IS NULL AND e.completed_at IS NULL AND e.expired_at IS NULL AND e.revoked_at IS NULL
        AND e.expires_at <= $2
      ORDER BY e.id
      FOR UPDATE OF e
    `, [reservationKey, now]);
    if (expiredResult.rowCount === 0) return { releasedExecutions: 0, releasedAtomic: "0" };
    let releasedForKey = 0n;
    for (const row of expiredResult.rows) {
      const execution = normalizeRow(row);
      const transitioned = await this.#transitionGuardExecutionReservations(client, execution, "released", now);
      releasedForKey += BigInt(transitioned.amounts.get(reservationKey) ?? "0");
      const expiredUpdate = await client.query(`
        UPDATE guard_executions SET expired_at = $1, spend_disposition = $2
        WHERE id = $3 AND committed_at IS NULL AND completed_at IS NULL AND expired_at IS NULL AND revoked_at IS NULL
        RETURNING id
      `, [now, transitioned.count > 0 ? "released" : "none", execution.id]);
      if (expiredUpdate.rowCount !== 1) {
        throw new ServiceError(500, "guard_reservation_corrupt", "Expired reservation release did not update every execution exactly once");
      }
    }
    return { releasedExecutions: expiredResult.rowCount, releasedAtomic: releasedForKey.toString() };
  }

  async #revokePendingGuardExecutions(client, whereSql, params, revokedAt) {
    const pendingResult = await client.query(`
      SELECT * FROM guard_executions
      WHERE ${whereSql}
        AND committed_at IS NULL AND completed_at IS NULL AND expired_at IS NULL AND revoked_at IS NULL
      ORDER BY id
      FOR UPDATE
    `, params);
    for (const row of pendingResult.rows) {
      const execution = normalizeRow(row);
      if (revokedAt < execution.created_at) throw new ServiceError(400, "invalid_guard_record", "revokedAt must not precede a pending execution");
      if (execution.settlement_started_at !== null && execution.expires_at > revokedAt) continue;
      const transitioned = await this.#transitionGuardExecutionReservations(client, execution, "released", revokedAt);
      const hasReservation = transitioned.count > 0;
      const revoked = await client.query(`
        UPDATE guard_executions SET revoked_at = $1, spend_disposition = $2
        WHERE id = $3 AND committed_at IS NULL AND completed_at IS NULL AND expired_at IS NULL AND revoked_at IS NULL
        RETURNING id
      `, [revokedAt, hasReservation ? "released" : "none", execution.id]);
      if (revoked.rowCount !== 1) throw new ServiceError(409, "guard_execution_finalized", "Pending execution changed during parent revocation");
    }
    return pendingResult.rowCount;
  }

  async #transitionGuardExecutionReservations(client, execution, disposition, at) {
    const reservationResult = await client.query(`
      SELECT * FROM guard_execution_reservations
      WHERE execution_id = $1 AND disposition = 'reserved'
      ORDER BY reservation_key
      FOR UPDATE
    `, [execution.id]);
    if (execution.reservation_key !== null && reservationResult.rowCount === 0) {
      throw new ServiceError(500, "guard_reservation_corrupt", "Guard execution reservation rows are missing");
    }
    const amounts = new Map();
    for (const reservation of reservationResult.rows) {
      const periodUpdate = disposition === "committed"
        ? await client.query(`
          UPDATE guard_spend_periods
          SET reserved_atomic = reserved_atomic - $2::numeric,
              spent_atomic = spent_atomic + $2::numeric,
              updated_at = $3
          WHERE reservation_key = $1 AND reserved_atomic >= $2::numeric
          RETURNING reservation_key
        `, [reservation.reservation_key, String(reservation.amount_atomic), at])
        : await client.query(`
          UPDATE guard_spend_periods
          SET reserved_atomic = reserved_atomic - $2::numeric,
              updated_at = $3
          WHERE reservation_key = $1 AND reserved_atomic >= $2::numeric
          RETURNING reservation_key
        `, [reservation.reservation_key, String(reservation.amount_atomic), at]);
      if (periodUpdate.rowCount !== 1) {
        throw new ServiceError(500, "guard_reservation_corrupt", "Authoritative spend reservation is missing or inconsistent");
      }
      const changed = await client.query(`
        UPDATE guard_execution_reservations SET disposition = $1
        WHERE execution_id = $2 AND reservation_key = $3 AND disposition = 'reserved'
        RETURNING reservation_key
      `, [disposition, execution.id, reservation.reservation_key]);
      if (changed.rowCount !== 1) throw new ServiceError(500, "guard_reservation_corrupt", "Guard execution reservation changed unexpectedly");
      amounts.set(reservation.reservation_key, String(reservation.amount_atomic));
    }
    return { count: reservationResult.rowCount, amounts };
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
