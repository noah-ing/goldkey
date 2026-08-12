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

function guardExecutionRow(row) {
  if (!row) return row;
  return {
    ...row,
    lifecycle_status: row.revoked_at !== null
      ? "revoked"
      : row.completed_at !== null
        ? "completed"
        : row.committed_at !== null
          ? "forwarding"
          : row.expired_at !== null
            ? "expired"
            : row.status,
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
        budget_confirmed INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'received',
        admin_note TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        reviewed_at INTEGER,
        retention_expires_at INTEGER NOT NULL,
        CHECK (length(idempotency_hash) = 64 AND idempotency_hash NOT GLOB '*[^0-9a-f]*'),
        CHECK (length(request_hash) = 64 AND request_hash NOT GLOB '*[^0-9a-f]*'),
        CHECK (length(source_fingerprint) = 64 AND source_fingerprint NOT GLOB '*[^0-9a-f]*'),
        CHECK (length(contact_fingerprint) = 64 AND contact_fingerprint NOT GLOB '*[^0-9a-f]*'),
        CHECK (budget_confirmed = 1),
        CHECK (status IN ('received', 'reviewing', 'accepted', 'declined', 'closed')),
        CHECK (updated_at >= created_at),
        CHECK (reviewed_at IS NULL OR reviewed_at >= created_at),
        CHECK (retention_expires_at > created_at)
      ) STRICT;

      CREATE TABLE IF NOT EXISTS guard_policy_versions (
        policy_id TEXT NOT NULL,
        version TEXT NOT NULL,
        policy_hash TEXT NOT NULL UNIQUE,
        policy_json TEXT NOT NULL,
        operator_wallet TEXT NOT NULL,
        operator_signature TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER,
        PRIMARY KEY (policy_id, version),
        CHECK (version GLOB '[1-9]*' AND version NOT GLOB '*[^0-9]*'),
        CHECK (length(policy_hash) = 64 AND policy_hash NOT GLOB '*[^0-9a-f]*'),
        CHECK (expires_at > created_at),
        CHECK (revoked_at IS NULL OR revoked_at >= created_at)
      ) STRICT, WITHOUT ROWID;

      CREATE TABLE IF NOT EXISTS guard_installations (
        id TEXT PRIMARY KEY,
        operator_wallet TEXT NOT NULL,
        policy_hash TEXT NOT NULL REFERENCES guard_policy_versions(policy_hash),
        public_key_jwk_json TEXT NOT NULL,
        binding_json TEXT NOT NULL,
        operator_signature TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER,
        CHECK (expires_at > created_at),
        CHECK (revoked_at IS NULL OR revoked_at >= created_at)
      ) STRICT;

      CREATE TABLE IF NOT EXISTS guard_spend_periods (
        reservation_key TEXT PRIMARY KEY,
        cap_atomic TEXT NOT NULL,
        reserved_atomic TEXT NOT NULL DEFAULT '0',
        spent_atomic TEXT NOT NULL DEFAULT '0',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS guard_executions (
        id TEXT PRIMARY KEY,
        installation_id TEXT NOT NULL REFERENCES guard_installations(id),
        idempotency_key TEXT NOT NULL,
        call_hash TEXT NOT NULL,
        policy_hash TEXT NOT NULL REFERENCES guard_policy_versions(policy_hash),
        decision TEXT NOT NULL,
        status TEXT NOT NULL,
        authorization_receipt_json TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        reservation_key TEXT,
        reservation_amount_atomic TEXT,
        completion_receipt_json TEXT,
        outcome_status TEXT,
        outcome_hash TEXT,
        spend_disposition TEXT,
        committed_at INTEGER,
        completed_at INTEGER,
        expired_at INTEGER,
        revoked_at INTEGER,
        settlement_started_at INTEGER,
        settlement_claim_id TEXT,
        settlement_payment_hash TEXT,
        settlement_payment_identity_hash TEXT,
        payment_settled_at INTEGER,
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
        CHECK (length(call_hash) = 64 AND call_hash NOT GLOB '*[^0-9a-f]*'),
        CHECK (length(policy_hash) = 64 AND policy_hash NOT GLOB '*[^0-9a-f]*'),
        CHECK ((reservation_key IS NULL) = (reservation_amount_atomic IS NULL)),
        CHECK ((completed_at IS NULL) = (completion_receipt_json IS NULL)),
        CHECK ((completed_at IS NULL) = (outcome_status IS NULL)),
        CHECK ((completed_at IS NULL) = (outcome_hash IS NULL)),
        CHECK (outcome_status IS NULL OR outcome_status IN ('succeeded', 'failed', 'outcome_unknown')),
        CHECK (outcome_hash IS NULL OR (length(outcome_hash) = 64 AND outcome_hash NOT GLOB '*[^0-9a-f]*')),
        CHECK (completed_at IS NULL OR committed_at IS NOT NULL),
        CHECK (committed_at IS NULL OR (committed_at >= created_at AND committed_at < expires_at)),
        CHECK (completed_at IS NULL OR completed_at >= committed_at),
        CHECK (NOT (expired_at IS NOT NULL AND revoked_at IS NOT NULL)),
        CHECK (committed_at IS NULL OR (expired_at IS NULL AND revoked_at IS NULL)),
        CHECK ((settlement_started_at IS NULL) = (settlement_claim_id IS NULL)),
        CHECK ((settlement_payment_hash IS NULL) = (settlement_payment_identity_hash IS NULL)),
        CHECK (settlement_started_at IS NULL OR settlement_payment_hash IS NOT NULL),
        CHECK (settlement_payment_hash IS NULL OR (length(settlement_payment_hash) = 64 AND settlement_payment_hash NOT GLOB '*[^0-9a-f]*')),
        CHECK (settlement_payment_identity_hash IS NULL OR (length(settlement_payment_identity_hash) = 64 AND settlement_payment_identity_hash NOT GLOB '*[^0-9a-f]*')),
        CHECK (
          (committed_at IS NULL AND expired_at IS NULL AND revoked_at IS NULL AND spend_disposition IS NULL)
          OR (committed_at IS NOT NULL AND expired_at IS NULL AND revoked_at IS NULL AND spend_disposition IN ('committed', 'none'))
          OR (committed_at IS NULL AND completed_at IS NULL AND (expired_at IS NOT NULL OR revoked_at IS NOT NULL)
            AND spend_disposition IN ('released', 'none'))
        ),
        CHECK (expired_at IS NULL OR expired_at >= expires_at),
        CHECK (revoked_at IS NULL OR revoked_at >= created_at)
      ) STRICT;

      CREATE TABLE IF NOT EXISTS guard_execution_reservations (
        execution_id TEXT NOT NULL REFERENCES guard_executions(id) ON DELETE CASCADE,
        installation_id TEXT NOT NULL,
        reservation_key TEXT NOT NULL,
        amount_atomic TEXT NOT NULL,
        cap_atomic TEXT NOT NULL,
        disposition TEXT NOT NULL DEFAULT 'reserved',
        PRIMARY KEY (execution_id, reservation_key),
        FOREIGN KEY (reservation_key) REFERENCES guard_spend_periods(reservation_key),
        CHECK (amount_atomic GLOB '[1-9]*' AND amount_atomic NOT GLOB '*[^0-9]*'),
        CHECK ((cap_atomic = '0') OR (cap_atomic GLOB '[1-9]*' AND cap_atomic NOT GLOB '*[^0-9]*')),
        CHECK (disposition IN ('reserved', 'committed', 'released'))
      ) STRICT, WITHOUT ROWID;

      CREATE INDEX IF NOT EXISTS session_expiry_idx ON sessions(expires_at);
      CREATE INDEX IF NOT EXISTS access_key_token_idx ON access_keys(token_id, term_number);
      CREATE INDEX IF NOT EXISTS pilot_application_source_idx ON pilot_applications(source_fingerprint, created_at);
      CREATE INDEX IF NOT EXISTS pilot_application_contact_idx ON pilot_applications(contact_fingerprint, created_at);
      CREATE INDEX IF NOT EXISTS pilot_application_review_idx ON pilot_applications(status, created_at DESC, id DESC);
      CREATE INDEX IF NOT EXISTS pilot_application_retention_idx ON pilot_applications(retention_expires_at);
      CREATE INDEX IF NOT EXISTS guard_installation_policy_idx ON guard_installations(policy_hash);
      CREATE INDEX IF NOT EXISTS guard_execution_installation_idx ON guard_executions(installation_id, created_at);
      CREATE INDEX IF NOT EXISTS guard_reservation_period_idx ON guard_execution_reservations(reservation_key, disposition);
    `);
    const guardExecutionColumns = new Set(this.db.prepare("PRAGMA table_info(guard_executions)").all().map(({ name }) => name));
    if (!guardExecutionColumns.has("payment_settled_at")) {
      this.db.exec("ALTER TABLE guard_executions ADD COLUMN payment_settled_at INTEGER");
    }
    if (!guardExecutionColumns.has("settlement_started_at")) {
      this.db.exec("ALTER TABLE guard_executions ADD COLUMN settlement_started_at INTEGER");
    }
    if (!guardExecutionColumns.has("settlement_claim_id")) {
      this.db.exec("ALTER TABLE guard_executions ADD COLUMN settlement_claim_id TEXT");
    }
    if (!guardExecutionColumns.has("payment_transaction")) {
      this.db.exec("ALTER TABLE guard_executions ADD COLUMN payment_transaction TEXT");
    }
    if (!guardExecutionColumns.has("settlement_payment_hash")) {
      this.db.exec("ALTER TABLE guard_executions ADD COLUMN settlement_payment_hash TEXT");
    }
    if (!guardExecutionColumns.has("settlement_payment_identity_hash")) {
      this.db.exec("ALTER TABLE guard_executions ADD COLUMN settlement_payment_identity_hash TEXT");
    }
    this.db.exec(`
      CREATE UNIQUE INDEX IF NOT EXISTS guard_settlement_payment_identity_unique
      ON guard_executions(settlement_payment_identity_hash)
      WHERE settlement_payment_identity_hash IS NOT NULL;
      CREATE UNIQUE INDEX IF NOT EXISTS guard_payment_transaction_unique
      ON guard_executions(payment_transaction)
      WHERE payment_transaction IS NOT NULL;
    `);
    this.db.exec(`
      INSERT OR IGNORE INTO guard_execution_reservations(
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
    `);
  }

  close() {
    this.db.close();
  }

  healthCheck() {
    return this.db.prepare("SELECT 1 AS ok").get()?.ok === 1;
  }

  createPilotApplication({
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

    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("DELETE FROM pilot_applications WHERE retention_expires_at <= ?").run(createdAt);
      const existing = this.db.prepare("SELECT * FROM pilot_applications WHERE idempotency_hash = ?").get(idempotencyHash);
      if (existing) {
        if (existing.request_hash !== requestHash) {
          throw new ServiceError(409, "pilot_idempotency_conflict", "Idempotency key was already used for a different application");
        }
        this.db.exec("COMMIT");
        return { replay: true, application: existing };
      }

      const hourStart = createdAt - 3_600_000;
      const dayStart = createdAt - 86_400_000;
      const sourceHourly = this.db.prepare(`
        SELECT COUNT(*) AS count FROM pilot_applications
        WHERE source_fingerprint = ? AND created_at >= ?
      `).get(sourceFingerprint, hourStart).count;
      const sourceDaily = this.db.prepare(`
        SELECT COUNT(*) AS count FROM pilot_applications
        WHERE source_fingerprint = ? AND created_at >= ?
      `).get(sourceFingerprint, dayStart).count;
      const contactDaily = this.db.prepare(`
        SELECT COUNT(*) AS count FROM pilot_applications
        WHERE contact_fingerprint = ? AND created_at >= ?
      `).get(contactFingerprint, dayStart).count;
      if (sourceHourly >= sourceHourlyLimit || sourceDaily >= sourceDailyLimit || contactDaily >= contactDailyLimit) {
        throw new ServiceError(429, "pilot_application_rate_limited", "Too many pilot applications; try again later");
      }

      this.db.prepare(`
        INSERT INTO pilot_applications(
          id, idempotency_hash, request_hash, source_fingerprint, contact_fingerprint,
          name, email, company, agent_stack, connector, action_text, timeline,
          budget_confirmed, status, created_at, updated_at, retention_expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'received', ?, ?, ?)
      `).run(
        id, idempotencyHash, requestHash, sourceFingerprint, contactFingerprint,
        name, email, company, agentStack, connector, action, timeline,
        createdAt, createdAt, retentionExpiresAt,
      );
      const application = this.db.prepare("SELECT * FROM pilot_applications WHERE id = ?").get(id);
      this.db.exec("COMMIT");
      return { replay: false, application };
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  listPilotApplications({ status, limit = 50, cursor, now = Date.now() } = {}) {
    requireMillis(now, "now");
    requirePilotLimit(limit, "limit", 100);
    if (status !== undefined && !PILOT_APPLICATION_STATUSES.has(status)) {
      throw new ServiceError(400, "invalid_pilot_application_query", "Unknown pilot application status");
    }
    this.purgeExpiredPilotApplications(now);
    const where = ["retention_expires_at > ?"];
    const values = [now];
    if (status !== undefined) {
      where.push("status = ?");
      values.push(status);
    }
    if (cursor !== undefined) {
      validatePilotCursor(cursor);
      where.push("(created_at < ? OR (created_at = ? AND id < ?))");
      values.push(cursor.createdAt, cursor.createdAt, cursor.id);
    }
    const rows = this.db.prepare(`
      SELECT * FROM pilot_applications
      WHERE ${where.join(" AND ")}
      ORDER BY created_at DESC, id DESC
      LIMIT ?
    `).all(...values, limit + 1);
    return { applications: rows.slice(0, limit), hasMore: rows.length > limit };
  }

  reviewPilotApplication({ applicationId, status, adminNote, adminNoteProvided = false, reviewedAt = Date.now() }) {
    requireNonEmptyString(applicationId, "applicationId");
    requireMillis(reviewedAt, "reviewedAt");
    if (!PILOT_APPLICATION_STATUSES.has(status)) {
      throw new ServiceError(400, "invalid_pilot_application_review", "Unknown pilot application status");
    }
    if (adminNoteProvided && adminNote !== null && typeof adminNote !== "string") {
      throw new ServiceError(400, "invalid_pilot_application_review", "adminNote must be text or null");
    }
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("DELETE FROM pilot_applications WHERE retention_expires_at <= ?").run(reviewedAt);
      const current = this.db.prepare("SELECT * FROM pilot_applications WHERE id = ?").get(applicationId);
      if (!current) throw new ServiceError(404, "pilot_application_not_found", "Pilot application does not exist");
      if (reviewedAt < current.created_at) {
        throw new ServiceError(400, "invalid_pilot_application_review", "Review time precedes the application");
      }
      this.db.prepare(`
        UPDATE pilot_applications
        SET status = ?, admin_note = CASE WHEN ? = 1 THEN ? ELSE admin_note END,
            reviewed_at = ?, updated_at = ?
        WHERE id = ?
      `).run(status, adminNoteProvided ? 1 : 0, adminNote ?? null, reviewedAt, reviewedAt, applicationId);
      const application = this.db.prepare("SELECT * FROM pilot_applications WHERE id = ?").get(applicationId);
      this.db.exec("COMMIT");
      return application;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  pilotApplicationSummary({ now = Date.now() } = {}) {
    requireMillis(now, "now");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("DELETE FROM pilot_applications WHERE retention_expires_at <= ?").run(now);
      const counts = this.db.prepare(`
        SELECT status, COUNT(*) AS count FROM pilot_applications
        WHERE retention_expires_at > ? GROUP BY status
      `).all(now);
      const newest = this.db.prepare(`
        SELECT id AS application_id, created_at, status FROM pilot_applications
        WHERE retention_expires_at > ? ORDER BY created_at DESC, id DESC LIMIT 1
      `).get(now) ?? null;
      const countsByStatus = Object.fromEntries([...PILOT_APPLICATION_STATUSES].map((value) => [value, 0]));
      for (const row of counts) countsByStatus[row.status] = row.count;
      const totalActive = counts.reduce((total, row) => total + row.count, 0);
      this.db.exec("COMMIT");
      return { totalActive, countsByStatus, newest };
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  purgeExpiredPilotApplications(now = Date.now()) {
    requireMillis(now, "now");
    return this.db.prepare("DELETE FROM pilot_applications WHERE retention_expires_at <= ?").run(now).changes;
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

  createGuardPolicyVersion({
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

    this.db.exec("BEGIN IMMEDIATE");
    try {
      const conflict = this.db.prepare(`
        SELECT policy_id, version, policy_hash FROM guard_policy_versions
        WHERE (policy_id = ? AND version = ?) OR policy_hash = ?
      `).get(policyId, version, policyHash);
      if (conflict) throw new ServiceError(409, "guard_policy_conflict", "Guard policy version or hash already exists", conflict);
      const latest = this.db.prepare(`
        SELECT version, operator_wallet FROM guard_policy_versions
        WHERE policy_id = ? ORDER BY length(version) DESC, version DESC LIMIT 1
      `).get(policyId);
      if (latest && latest.operator_wallet.toLowerCase() !== operatorWallet.toLowerCase()) {
        throw new ServiceError(409, "guard_policy_operator_change_requires_rotation", "A Guard policy ID cannot change operator without an explicit ownership-rotation protocol", {
          current_operator_wallet: latest.operator_wallet,
          requested_operator_wallet: operatorWallet,
        });
      }
      if (latest && BigInt(version) <= BigInt(latest.version)) {
        throw new ServiceError(409, "guard_policy_version_not_monotonic", "Guard policy version must increase monotonically", {
          latest_version: latest.version,
          requested_version: version,
        });
      }
      this.db.prepare(`
        INSERT INTO guard_policy_versions(
          policy_id, version, policy_hash, policy_json, operator_wallet,
          operator_signature, created_at, expires_at, revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(policyId, version, policyHash, policyJson, operatorWallet, operatorSignature, createdAt, expiresAt, revokedAt);
      this.db.exec("COMMIT");
      return this.getGuardPolicyVersion(policyId, version);
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  getGuardPolicyVersion(policyId, version) {
    return this.db.prepare(`
      SELECT * FROM guard_policy_versions WHERE policy_id = ? AND version = ?
    `).get(policyId, version);
  }

  getGuardPolicyVersionByHash(policyHash) {
    return this.db.prepare("SELECT * FROM guard_policy_versions WHERE policy_hash = ?").get(policyHash);
  }

  getLatestGuardPolicyVersion(policyId) {
    return this.db.prepare(`
      SELECT * FROM guard_policy_versions
      WHERE policy_id = ? ORDER BY length(version) DESC, version DESC LIMIT 1
    `).get(policyId);
  }

  revokeGuardPolicyVersion(policyHash, revokedAt = Date.now()) {
    requireSha256(policyHash, "policyHash");
    requireMillis(revokedAt, "revokedAt");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const current = this.db.prepare("SELECT * FROM guard_policy_versions WHERE policy_hash = ?").get(policyHash);
      if (!current) throw new ServiceError(404, "guard_policy_not_found", "Guard policy version does not exist");
      if (revokedAt < current.created_at) throw new ServiceError(400, "invalid_guard_record", "revokedAt must not precede createdAt");
      if (current.revoked_at === null) {
        this.#revokePendingGuardExecutions("policy_hash = ?", [policyHash], revokedAt);
        this.db.prepare("UPDATE guard_policy_versions SET revoked_at = ? WHERE policy_hash = ? AND revoked_at IS NULL").run(revokedAt, policyHash);
      }
      const revoked = this.db.prepare("SELECT * FROM guard_policy_versions WHERE policy_hash = ?").get(policyHash);
      this.db.exec("COMMIT");
      return revoked;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  createGuardInstallation({
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

    this.db.exec("BEGIN IMMEDIATE");
    try {
      const policy = this.db.prepare("SELECT * FROM guard_policy_versions WHERE policy_hash = ?").get(policyHash);
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
      if (this.db.prepare("SELECT id FROM guard_installations WHERE id = ?").get(installationId)) {
        throw new ServiceError(409, "guard_installation_conflict", "Guard installation already exists");
      }
      this.db.prepare(`
        INSERT INTO guard_installations(
          id, operator_wallet, policy_hash, public_key_jwk_json, binding_json,
          operator_signature, created_at, expires_at, revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(installationId, operatorWallet, policyHash, publicKeyJwkJson, bindingJson, operatorSignature, createdAt, expiresAt, revokedAt);
      this.db.exec("COMMIT");
      return this.getGuardInstallation(installationId);
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  getGuardInstallation(installationId) {
    return this.db.prepare("SELECT * FROM guard_installations WHERE id = ?").get(installationId);
  }

  revokeGuardInstallation(installationId, revokedAt = Date.now()) {
    requireNonEmptyString(installationId, "installationId");
    requireMillis(revokedAt, "revokedAt");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const current = this.db.prepare("SELECT * FROM guard_installations WHERE id = ?").get(installationId);
      if (!current) throw new ServiceError(404, "guard_installation_not_found", "Guard installation does not exist");
      if (revokedAt < current.created_at) throw new ServiceError(400, "invalid_guard_record", "revokedAt must not precede createdAt");
      if (current.revoked_at === null) {
        this.#revokePendingGuardExecutions("installation_id = ?", [installationId], revokedAt);
        this.db.prepare("UPDATE guard_installations SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL").run(revokedAt, installationId);
      }
      const revoked = this.db.prepare("SELECT * FROM guard_installations WHERE id = ?").get(installationId);
      this.db.exec("COMMIT");
      return revoked;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  reserveGuardExecution({
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

    this.db.exec("BEGIN IMMEDIATE");
    try {
      const previous = this.db.prepare(`
        SELECT * FROM guard_executions WHERE installation_id = ? AND idempotency_key = ?
      `).get(installationId, idempotencyKey);
      if (previous) {
        if (previous.call_hash !== callHash) {
          throw new ServiceError(409, "idempotency_conflict", "Idempotency key was already used with a different call hash");
        }
        if (previous.reservation_key !== null && previous.expired_at === null && previous.expires_at <= createdAt) {
          this.#releaseExpiredGuardReservations(previous.reservation_key, createdAt);
        }
        const replay = this.db.prepare("SELECT * FROM guard_executions WHERE id = ?").get(previous.id);
        this.db.exec("COMMIT");
        return { replay: true, execution: guardExecutionRow(replay) };
      }

      const installation = this.db.prepare(`
        SELECT i.*, p.expires_at AS policy_expires_at, p.revoked_at AS policy_revoked_at
        FROM guard_installations i
        JOIN guard_policy_versions p ON p.policy_hash = i.policy_hash
        WHERE i.id = ?
      `).get(installationId);
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
        this.#releaseExpiredGuardReservations(reservation.reservationKey, createdAt);
        const amount = BigInt(reservation.reservationAmountAtomic);
        const cap = BigInt(reservation.spendCapAtomic);
        const period = this.db.prepare(`
          SELECT * FROM guard_spend_periods WHERE reservation_key = ?
        `).get(reservation.reservationKey);
        if (!period) {
          if (amount > cap) throw new ServiceError(402, "guard_spend_cap_exceeded", "Spend reservation exceeds the authoritative period cap");
          this.db.prepare(`
            INSERT INTO guard_spend_periods(
              reservation_key, cap_atomic, reserved_atomic, spent_atomic, created_at, updated_at
            ) VALUES (?, ?, ?, '0', ?, ?)
          `).run(
            reservation.reservationKey,
            reservation.spendCapAtomic,
            reservation.reservationAmountAtomic,
            createdAt,
            createdAt,
          );
        } else {
          if (period.cap_atomic !== reservation.spendCapAtomic) {
            throw new ServiceError(409, "guard_spend_cap_conflict", "Spend period was already created with a different cap");
          }
          const nextReserved = BigInt(period.reserved_atomic) + amount;
          if (nextReserved + BigInt(period.spent_atomic) > cap) {
            throw new ServiceError(402, "guard_spend_cap_exceeded", "Spend reservation exceeds the authoritative period cap", {
              cap_atomic: reservation.spendCapAtomic,
              reserved_atomic: period.reserved_atomic,
              spent_atomic: period.spent_atomic,
              requested_atomic: reservation.reservationAmountAtomic,
            });
          }
          this.db.prepare(`
            UPDATE guard_spend_periods SET reserved_atomic = ?, updated_at = ?
            WHERE reservation_key = ?
          `).run(nextReserved.toString(), createdAt, reservation.reservationKey);
        }
      }

      const primaryReservation = reservationList[0];

      this.db.prepare(`
        INSERT INTO guard_executions(
          id, installation_id, idempotency_key, call_hash, policy_hash, decision, status,
          authorization_receipt_json, created_at, expires_at, reservation_key, reservation_amount_atomic
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
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
      );
      for (const reservation of reservationList) {
        this.db.prepare(`
          INSERT INTO guard_execution_reservations(
            execution_id, installation_id, reservation_key, amount_atomic, cap_atomic, disposition
          ) VALUES (?, ?, ?, ?, ?, 'reserved')
        `).run(
          executionId,
          installationId,
          reservation.reservationKey,
          reservation.reservationAmountAtomic,
          reservation.spendCapAtomic,
        );
      }
      const execution = this.db.prepare("SELECT * FROM guard_executions WHERE id = ?").get(executionId);
      this.db.exec("COMMIT");
      return { replay: false, execution: guardExecutionRow(execution) };
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  getGuardExecution(executionId) {
    return guardExecutionRow(this.db.prepare("SELECT * FROM guard_executions WHERE id = ?").get(executionId));
  }

  getGuardExecutionByIdempotency(installationId, idempotencyKey) {
    return guardExecutionRow(this.db.prepare(`
      SELECT * FROM guard_executions WHERE installation_id = ? AND idempotency_key = ?
    `).get(installationId, idempotencyKey));
  }

  beginGuardExecutionSettlement({
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
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const execution = this.db.prepare(`
        SELECT e.*, i.expires_at AS installation_expires_at, i.revoked_at AS installation_revoked_at,
               p.expires_at AS policy_expires_at, p.revoked_at AS policy_revoked_at
        FROM guard_executions e
        JOIN guard_installations i ON i.id = e.installation_id
        JOIN guard_policy_versions p ON p.policy_hash = e.policy_hash
        WHERE e.installation_id = ? AND e.idempotency_key = ?
      `).get(installationId, idempotencyKey);
      if (!execution) throw new ServiceError(404, "guard_execution_not_found", "Guard execution does not exist for settlement");
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
      const reusedIdentity = this.db.prepare(`
        SELECT id FROM guard_executions
        WHERE settlement_payment_identity_hash = ? AND id <> ?
      `).get(paymentIdentitySha256, execution.id);
      if (reusedIdentity) throw new ServiceError(409, "guard_payment_identity_reused", "EIP-3009 payment authorization is already bound to another Guard execution");
      this.db.prepare(`
        UPDATE guard_executions SET settlement_started_at = ?, settlement_claim_id = ?,
          settlement_payment_hash = ?, settlement_payment_identity_hash = ?
        WHERE id = ? AND settlement_started_at IS NULL AND payment_settled_at IS NULL
      `).run(startedAt, settlementClaimId, paymentSha256, paymentIdentitySha256, execution.id);
      const started = this.db.prepare("SELECT * FROM guard_executions WHERE id = ?").get(execution.id);
      this.db.exec("COMMIT");
      return { replay: false, execution: guardExecutionRow(started) };
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  cancelGuardExecutionSettlement({ installationId, idempotencyKey, callHash, settlementClaimId, canceledAt = Date.now() }) {
    requireNonEmptyString(installationId, "installationId");
    requireNonEmptyString(idempotencyKey, "idempotencyKey");
    requireSha256(callHash, "callHash");
    requireNonEmptyString(settlementClaimId, "settlementClaimId");
    requireMillis(canceledAt, "canceledAt");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const execution = this.db.prepare(`
        SELECT * FROM guard_executions WHERE installation_id = ? AND idempotency_key = ?
      `).get(installationId, idempotencyKey);
      if (!execution) throw new ServiceError(404, "guard_execution_not_found", "Guard execution does not exist for settlement cancellation");
      if (execution.call_hash !== callHash) throw new ServiceError(409, "idempotency_conflict", "Settlement cancellation does not match the stored call hash");
      if (execution.settlement_claim_id !== null && execution.settlement_claim_id !== settlementClaimId) {
        throw new ServiceError(409, "guard_settlement_claim_mismatch", "Settlement cancellation does not own the active claim");
      }
      if (execution.payment_settled_at !== null || execution.settlement_started_at === null) {
        this.db.exec("COMMIT");
        return { replay: true, execution: guardExecutionRow(execution) };
      }
      this.db.prepare(`
        UPDATE guard_executions SET settlement_started_at = NULL, settlement_claim_id = NULL
        WHERE id = ? AND payment_settled_at IS NULL
      `).run(execution.id);
      const binding = this.db.prepare(`
        SELECT i.revoked_at AS installation_revoked_at, p.revoked_at AS policy_revoked_at
        FROM guard_installations i JOIN guard_policy_versions p ON p.policy_hash = i.policy_hash
        WHERE i.id = ? AND p.policy_hash = ?
      `).get(execution.installation_id, execution.policy_hash);
      if (binding && (binding.installation_revoked_at !== null || binding.policy_revoked_at !== null)) {
        const transitioned = this.#transitionGuardExecutionReservations(execution, "released", canceledAt);
        this.db.prepare(`
          UPDATE guard_executions SET revoked_at = ?, spend_disposition = ?
          WHERE id = ? AND committed_at IS NULL AND completed_at IS NULL AND expired_at IS NULL AND revoked_at IS NULL
        `).run(canceledAt, transitioned.count > 0 ? "released" : "none", execution.id);
      }
      const canceled = this.db.prepare("SELECT * FROM guard_executions WHERE id = ?").get(execution.id);
      this.db.exec("COMMIT");
      return { replay: false, execution: guardExecutionRow(canceled) };
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  markGuardExecutionPaymentSettled({
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
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const execution = this.db.prepare(`
        SELECT * FROM guard_executions WHERE installation_id = ? AND idempotency_key = ?
      `).get(installationId, idempotencyKey);
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
        this.db.exec("COMMIT");
        return { replay: true, execution: guardExecutionRow(execution) };
      }
      const reusedTransaction = transaction === null ? undefined : this.db.prepare(`
        SELECT id FROM guard_executions WHERE payment_transaction = ? AND id <> ?
      `).get(transaction, execution.id);
      if (reusedTransaction) throw new ServiceError(409, "guard_payment_transaction_reused", "Payment transaction is already bound to another Guard execution");
      this.db.prepare(`
        UPDATE guard_executions SET payment_settled_at = ?, payment_transaction = ?
        WHERE id = ? AND payment_settled_at IS NULL
      `).run(settledAt, transaction, execution.id);
      const settled = this.db.prepare("SELECT * FROM guard_executions WHERE id = ?").get(execution.id);
      this.db.exec("COMMIT");
      return { replay: false, execution: guardExecutionRow(settled) };
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  getGuardSpendPeriod(installationId, reservationKey) {
    requireNonEmptyString(installationId, "installationId");
    requireNonEmptyString(reservationKey, "reservationKey");
    return this.db.prepare(`
      SELECT * FROM guard_spend_periods WHERE reservation_key = ?
    `).get(reservationKey);
  }

  sweepExpiredGuardReservations(installationId, reservationKey, now = Date.now()) {
    requireNonEmptyString(installationId, "installationId");
    requireNonEmptyString(reservationKey, "reservationKey");
    requireMillis(now, "now");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const released = this.#releaseExpiredGuardReservations(reservationKey, now);
      this.db.exec("COMMIT");
      return released;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  commitGuardExecution({ executionId, committedAt = Date.now(), paymentReconciliation } = {}) {
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
    this.db.exec("BEGIN IMMEDIATE");
    try {
      let execution = this.db.prepare("SELECT * FROM guard_executions WHERE id = ?").get(executionId);
      if (!execution) throw new ServiceError(404, "guard_execution_not_found", "Guard execution does not exist");
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
          const reusedTransaction = this.db.prepare(`
            SELECT id FROM guard_executions WHERE payment_transaction = ? AND id <> ?
          `).get(paymentReconciliation.transaction, execution.id);
          if (reusedTransaction) throw new ServiceError(409, "guard_payment_transaction_reused", "Payment transaction is already bound to another Guard execution");
          this.db.prepare(`
            UPDATE guard_executions SET payment_settled_at = ?, payment_transaction = ?
            WHERE id = ? AND payment_settled_at IS NULL
          `).run(paymentReconciliation.settledAt, paymentReconciliation.transaction, execution.id);
          execution = this.db.prepare("SELECT * FROM guard_executions WHERE id = ?").get(execution.id);
        }
      }
      if (execution.committed_at !== null) {
        this.db.exec("COMMIT");
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
      const binding = this.db.prepare(`
        SELECT i.expires_at AS installation_expires_at, i.revoked_at AS installation_revoked_at,
               p.expires_at AS policy_expires_at, p.revoked_at AS policy_revoked_at
        FROM guard_installations i
        JOIN guard_policy_versions p ON p.policy_hash = i.policy_hash
        WHERE i.id = ? AND p.policy_hash = ?
      `).get(execution.installation_id, execution.policy_hash);
      const installationClaimWon = binding?.installation_revoked_at !== null
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
      const transitionedReservations = this.#transitionGuardExecutionReservations(execution, "committed", committedAt);
      const hasReservation = transitionedReservations.count > 0;
      this.db.prepare(`
        UPDATE guard_executions SET committed_at = ?, spend_disposition = ?
        WHERE id = ? AND committed_at IS NULL AND expired_at IS NULL AND revoked_at IS NULL
      `).run(committedAt, hasReservation ? "committed" : "none", executionId);
      const committed = this.db.prepare("SELECT * FROM guard_executions WHERE id = ?").get(executionId);
      this.db.exec("COMMIT");
      return { replay: false, execution: guardExecutionRow(committed) };
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  completeGuardExecution({
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

    this.db.exec("BEGIN IMMEDIATE");
    try {
      const execution = this.db.prepare("SELECT * FROM guard_executions WHERE id = ?").get(executionId);
      if (!execution) throw new ServiceError(404, "guard_execution_not_found", "Guard execution does not exist");
      if (execution.completed_at !== null) {
        if (
          execution.completion_receipt_json !== completionReceiptJson
          || execution.outcome_status !== outcomeStatus
          || execution.outcome_hash !== outcomeHash
        ) throw new ServiceError(409, "guard_execution_finalized", "Guard execution was already completed differently");
        this.db.exec("COMMIT");
        return { replay: true, execution: guardExecutionRow(execution) };
      }
      if (execution.committed_at === null) {
        throw new ServiceError(409, "guard_execution_not_committed", "Guard execution must be committed before completion");
      }
      if (completedAt < execution.committed_at) {
        throw new ServiceError(400, "invalid_guard_record", "completedAt must not precede committedAt");
      }
      this.db.prepare(`
        UPDATE guard_executions
        SET completion_receipt_json = ?, outcome_status = ?, outcome_hash = ?, completed_at = ?
        WHERE id = ? AND committed_at IS NOT NULL AND completed_at IS NULL
      `).run(completionReceiptJson, outcomeStatus, outcomeHash, completedAt, executionId);
      const completed = this.db.prepare("SELECT * FROM guard_executions WHERE id = ?").get(executionId);
      this.db.exec("COMMIT");
      return { replay: false, execution: guardExecutionRow(completed) };
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  revokeGuardExecution(executionId, revokedAt = Date.now()) {
    requireNonEmptyString(executionId, "executionId");
    requireMillis(revokedAt, "revokedAt");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const execution = this.db.prepare("SELECT * FROM guard_executions WHERE id = ?").get(executionId);
      if (!execution) throw new ServiceError(404, "guard_execution_not_found", "Guard execution does not exist");
      if (execution.completed_at !== null) throw new ServiceError(409, "guard_execution_finalized", "Completed execution cannot be revoked");
      if (execution.committed_at !== null) throw new ServiceError(409, "guard_execution_committed", "Committed execution cannot be revoked");
      if (execution.expired_at !== null) throw new ServiceError(409, "guard_execution_expired", "Expired execution cannot be revoked");
      if (execution.revoked_at !== null) {
        this.db.exec("COMMIT");
        return { replay: true, execution: guardExecutionRow(execution) };
      }
      if (revokedAt < execution.created_at) throw new ServiceError(400, "invalid_guard_record", "revokedAt must not precede createdAt");
      if (execution.settlement_started_at !== null && execution.expires_at > revokedAt) {
        throw new ServiceError(409, "guard_settlement_in_progress", "Guard settlement or paid authorization is still within its commit window");
      }
      const transitionedReservations = this.#transitionGuardExecutionReservations(execution, "released", revokedAt);
      const hasReservation = transitionedReservations.count > 0;
      this.db.prepare(`
        UPDATE guard_executions SET revoked_at = ?, spend_disposition = ?
        WHERE id = ? AND committed_at IS NULL AND completed_at IS NULL AND expired_at IS NULL AND revoked_at IS NULL
      `).run(revokedAt, hasReservation ? "released" : "none", executionId);
      const revoked = this.db.prepare("SELECT * FROM guard_executions WHERE id = ?").get(executionId);
      this.db.exec("COMMIT");
      return { replay: false, execution: guardExecutionRow(revoked) };
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  #releaseExpiredGuardReservations(reservationKey, now) {
    const expired = this.db.prepare(`
      SELECT DISTINCT e.*
      FROM guard_executions e
      JOIN guard_execution_reservations r ON r.execution_id = e.id
      WHERE r.reservation_key = ? AND r.disposition = 'reserved'
        AND e.committed_at IS NULL AND e.completed_at IS NULL AND e.expired_at IS NULL AND e.revoked_at IS NULL
        AND e.expires_at <= ?
      ORDER BY e.id
    `).all(reservationKey, now);
    if (expired.length === 0) return { releasedExecutions: 0, releasedAtomic: "0" };
    let releasedForKey = 0n;
    for (const execution of expired) {
      const transitioned = this.#transitionGuardExecutionReservations(execution, "released", now);
      releasedForKey += BigInt(transitioned.amounts.get(reservationKey) ?? "0");
      const changed = this.db.prepare(`
        UPDATE guard_executions SET expired_at = ?, spend_disposition = ?
        WHERE id = ? AND committed_at IS NULL AND completed_at IS NULL AND expired_at IS NULL AND revoked_at IS NULL
      `).run(now, transitioned.count > 0 ? "released" : "none", execution.id).changes;
      if (changed !== 1) {
        throw new ServiceError(500, "guard_reservation_corrupt", "Expired reservation release did not update every execution exactly once");
      }
    }
    return { releasedExecutions: expired.length, releasedAtomic: releasedForKey.toString() };
  }

  #revokePendingGuardExecutions(whereSql, params, revokedAt) {
    const pending = this.db.prepare(`
      SELECT * FROM guard_executions
      WHERE ${whereSql}
        AND committed_at IS NULL AND completed_at IS NULL AND expired_at IS NULL AND revoked_at IS NULL
      ORDER BY id
    `).all(...params);
    for (const execution of pending) {
      if (revokedAt < execution.created_at) throw new ServiceError(400, "invalid_guard_record", "revokedAt must not precede a pending execution");
      if (execution.settlement_started_at !== null && execution.expires_at > revokedAt) continue;
      const transitioned = this.#transitionGuardExecutionReservations(execution, "released", revokedAt);
      const hasReservation = transitioned.count > 0;
      const changed = this.db.prepare(`
        UPDATE guard_executions SET revoked_at = ?, spend_disposition = ?
        WHERE id = ? AND committed_at IS NULL AND completed_at IS NULL AND expired_at IS NULL AND revoked_at IS NULL
      `).run(revokedAt, hasReservation ? "released" : "none", execution.id).changes;
      if (changed !== 1) throw new ServiceError(409, "guard_execution_finalized", "Pending execution changed during parent revocation");
    }
    return pending.length;
  }

  #transitionGuardExecutionReservations(execution, disposition, at) {
    const reservations = this.db.prepare(`
      SELECT * FROM guard_execution_reservations
      WHERE execution_id = ? AND disposition = 'reserved'
      ORDER BY reservation_key
    `).all(execution.id);
    if (execution.reservation_key !== null && reservations.length === 0) {
      throw new ServiceError(500, "guard_reservation_corrupt", "Guard execution reservation rows are missing");
    }
    const amounts = new Map();
    for (const reservation of reservations) {
      const period = this.db.prepare(`
        SELECT * FROM guard_spend_periods WHERE reservation_key = ?
      `).get(reservation.reservation_key);
      const amount = BigInt(reservation.amount_atomic);
      if (!period || BigInt(period.reserved_atomic) < amount) {
        throw new ServiceError(500, "guard_reservation_corrupt", "Authoritative spend reservation is missing or inconsistent");
      }
      const nextReserved = BigInt(period.reserved_atomic) - amount;
      const nextSpent = disposition === "committed" ? BigInt(period.spent_atomic) + amount : BigInt(period.spent_atomic);
      this.db.prepare(`
        UPDATE guard_spend_periods SET reserved_atomic = ?, spent_atomic = ?, updated_at = ?
        WHERE reservation_key = ?
      `).run(nextReserved.toString(), nextSpent.toString(), at, reservation.reservation_key);
      const changed = this.db.prepare(`
        UPDATE guard_execution_reservations SET disposition = ?
        WHERE execution_id = ? AND reservation_key = ? AND disposition = 'reserved'
      `).run(disposition, execution.id, reservation.reservation_key).changes;
      if (changed !== 1) throw new ServiceError(500, "guard_reservation_corrupt", "Guard execution reservation changed unexpectedly");
      amounts.set(reservation.reservation_key, reservation.amount_atomic);
    }
    return { count: reservations.length, amounts };
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
