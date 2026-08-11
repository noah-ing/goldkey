import { randomUUID } from "node:crypto";
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  statSync,
} from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { getAddress, isAddress } from "viem";
import {
  InvalidInputError,
  LocalStateError,
  PaymentPolicyError,
} from "./errors.mjs";
import { isCanonicalSha256 } from "./canonical.mjs";

const ATOMIC = /^(0|[1-9]\d{0,77})$/;
const TRANSACTION_HASH = /^0x[0-9a-f]{64}$/;
const PAYMENT_NONCE = /^0x[0-9a-f]{64}$/;
const BASE_MAINNET_X402_NETWORK = "eip155:8453";
const BASE_MAINNET_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const ACTIVE_STATUSES = new Set(["RESERVED", "TRANSMITTED"]);
const CHARGED_STATUSES = new Set(["RESERVED", "TRANSMITTED", "SETTLED", "EXPIRED_UNKNOWN"]);
const MAX_PERIOD_SECONDS = 31_536_000;

function atomic(value, name, { allowZero = false } = {}) {
  if (typeof value !== "string" || !ATOMIC.test(value) || (!allowZero && value === "0")) {
    throw new InvalidInputError(`${name} must be a canonical positive atomic-unit integer string`);
  }
  return BigInt(value);
}

function nonempty(value, name, maximum = 256) {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum) {
    throw new InvalidInputError(`${name} must be a nonempty string of at most ${maximum} characters`);
  }
  return value;
}

function payerAddress(value) {
  if (!isAddress(value)) throw new InvalidInputError("payer must be a canonical EVM address");
  return getAddress(value);
}

function transactionHash(value) {
  if (typeof value !== "string" || !TRANSACTION_HASH.test(value.toLowerCase())) {
    throw new InvalidInputError("transaction must be one canonical EVM transaction hash");
  }
  return value.toLowerCase();
}

function publicRecord(row) {
  if (!row) return undefined;
  return Object.freeze({
    reservationId: row.reservation_id,
    installationId: row.installation_id,
    idempotencyKey: row.idempotency_key,
    callSha256: row.call_sha256,
    amountAtomic: row.amount_atomic,
    payer: row.payer,
    payee: row.payee,
    network: row.network,
    asset: row.asset,
    paymentNonce: row.payment_nonce,
    periodStartMs: row.period_start_ms,
    periodEndMs: row.period_end_ms,
    validBeforeMs: row.valid_before_ms,
    status: row.status,
    transaction: row.transaction_hash ?? undefined,
    createdAtMs: row.created_at_ms,
    updatedAtMs: row.updated_at_ms,
  });
}

/**
 * Durable, process-safe x402 exposure ledger.
 *
 * SQLite BEGIN IMMEDIATE serializes the read-cap-insert decision across every
 * process using the same operator-owned database. Amounts remain decimal text
 * and are summed as BigInt in JavaScript so no SQLite numeric coercion can
 * weaken an atomic-USDC limit.
 */
export class SqlitePaymentBudgetStore {
  #db;
  #clock;
  #periodSeconds;
  #periodMs;
  #maxPeriodAtomic;
  #maxOutstandingAtomic;
  #maxOutstandingCount;

  constructor({
    filename,
    periodSeconds,
    maxPeriodAtomic,
    maxOutstandingAtomic,
    maxOutstandingCount,
    clock = () => Date.now(),
  }) {
    if (typeof filename !== "string" || filename.length < 1 || filename === ":memory:") {
      throw new InvalidInputError("A durable payment-budget SQLite filename is required");
    }
    if (!Number.isSafeInteger(periodSeconds) || periodSeconds < 60 || periodSeconds > MAX_PERIOD_SECONDS) {
      throw new InvalidInputError(`periodSeconds must be 60-${MAX_PERIOD_SECONDS}`);
    }
    if (!Number.isSafeInteger(maxOutstandingCount) || maxOutstandingCount < 1 || maxOutstandingCount > 1_000_000) {
      throw new InvalidInputError("maxOutstandingCount must be 1-1000000");
    }
    if (typeof clock !== "function") throw new InvalidInputError("clock must be a function");
    const periodCap = atomic(maxPeriodAtomic, "maxPeriodAtomic");
    const outstandingCap = atomic(maxOutstandingAtomic, "maxOutstandingAtomic");
    if (outstandingCap > periodCap) {
      throw new InvalidInputError("maxOutstandingAtomic cannot exceed maxPeriodAtomic");
    }

    const resolved = path.resolve(filename);
    const directory = path.dirname(resolved);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    if (process.platform !== "win32" && (statSync(directory).mode & 0o077) !== 0) {
      throw new LocalStateError(`Payment-budget directory ${directory} must not be accessible by group or other users`);
    }
    try {
      if (lstatSync(resolved).isSymbolicLink()) {
        throw new LocalStateError("Payment-budget database must not be a symbolic link");
      }
    } catch (cause) {
      if (cause instanceof LocalStateError) throw cause;
      if (cause?.code !== "ENOENT") throw new LocalStateError("Unable to inspect payment-budget database", { cause });
    }

    this.filename = resolved;
    this.#clock = clock;
    this.#periodSeconds = periodSeconds;
    this.#periodMs = periodSeconds * 1000;
    this.#maxPeriodAtomic = maxPeriodAtomic;
    this.#maxOutstandingAtomic = maxOutstandingAtomic;
    this.#maxOutstandingCount = maxOutstandingCount;
    try {
      this.#db = new DatabaseSync(resolved);
      if (process.platform !== "win32") chmodSync(resolved, 0o600);
      this.#db.exec("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 10000; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;");
      this.#migrate();
    } catch (cause) {
      this.#db?.close?.();
      throw cause instanceof LocalStateError ? cause : new LocalStateError("Unable to initialize durable payment-budget database", { cause });
    }
    Object.freeze(this);
  }

  #migrate() {
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS payment_budget_config (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        schema TEXT NOT NULL,
        period_seconds INTEGER NOT NULL,
        max_period_atomic TEXT NOT NULL,
        max_outstanding_atomic TEXT NOT NULL,
        max_outstanding_count INTEGER NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS payment_budget_reservations (
        reservation_id TEXT PRIMARY KEY,
        installation_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        call_sha256 TEXT NOT NULL,
        amount_atomic TEXT NOT NULL,
        payer TEXT NOT NULL,
        payee TEXT NOT NULL,
        network TEXT NOT NULL,
        asset TEXT NOT NULL,
        payment_nonce TEXT NOT NULL,
        period_start_ms INTEGER NOT NULL,
        period_end_ms INTEGER NOT NULL,
        valid_before_ms INTEGER NOT NULL,
        status TEXT NOT NULL CHECK (status IN (
          'RESERVED',
          'TRANSMITTED',
          'SETTLED',
          'EXPIRED_UNKNOWN',
          'RELEASED_UNTRANSMITTED',
          'RESOLVED_UNPAID'
        )),
        transaction_hash TEXT,
        created_at_ms INTEGER NOT NULL,
        updated_at_ms INTEGER NOT NULL,
        UNIQUE (installation_id, idempotency_key),
        UNIQUE (network, asset, payer, payment_nonce),
        CHECK (period_end_ms > period_start_ms),
        CHECK (valid_before_ms > created_at_ms)
      ) STRICT;

      CREATE INDEX IF NOT EXISTS payment_budget_period_idx
        ON payment_budget_reservations(period_start_ms, period_end_ms, status);
      CREATE INDEX IF NOT EXISTS payment_budget_outstanding_idx
        ON payment_budget_reservations(status, valid_before_ms);
    `);
    this.#transaction(() => {
      this.#db.prepare(`
        INSERT OR IGNORE INTO payment_budget_config (
          singleton, schema, period_seconds, max_period_atomic,
          max_outstanding_atomic, max_outstanding_count
        ) VALUES (1, 'goldkey.payment-budget.v1', ?, ?, ?, ?)
      `).run(
        this.#periodSeconds,
        this.#maxPeriodAtomic,
        this.#maxOutstandingAtomic,
        this.#maxOutstandingCount,
      );
      const stored = this.#db.prepare("SELECT * FROM payment_budget_config WHERE singleton = 1").get();
      if (
        stored?.schema !== "goldkey.payment-budget.v1"
        || stored.period_seconds !== this.#periodSeconds
        || stored.max_period_atomic !== this.#maxPeriodAtomic
        || stored.max_outstanding_atomic !== this.#maxOutstandingAtomic
        || stored.max_outstanding_count !== this.#maxOutstandingCount
      ) {
        throw new LocalStateError("Payment-budget database is pinned to different operator limits");
      }
    });
  }

  #transaction(operation) {
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      this.#db.exec("COMMIT");
      return result;
    } catch (cause) {
      try {
        this.#db.exec("ROLLBACK");
      } catch {}
      throw cause;
    }
  }

  #now() {
    const now = this.#clock();
    if (!Number.isSafeInteger(now) || now < 0) throw new LocalStateError("Payment-budget clock returned an invalid timestamp");
    return now;
  }

  #expire(now) {
    this.#db.prepare(`
      UPDATE payment_budget_reservations
      SET status = 'EXPIRED_UNKNOWN', updated_at_ms = ?
      WHERE status IN ('RESERVED', 'TRANSMITTED') AND valid_before_ms <= ?
    `).run(now, now);
  }

  #boundRow(reservationId, binding) {
    const row = this.#db.prepare("SELECT * FROM payment_budget_reservations WHERE reservation_id = ?").get(reservationId);
    if (!row) throw new LocalStateError("Payment-budget reservation does not exist");
    if (
      row.installation_id !== binding.installationId
      || row.idempotency_key !== binding.idempotencyKey
      || row.call_sha256 !== binding.callSha256
    ) throw new LocalStateError("Payment-budget reservation binding does not match the exact authorization call");
    return row;
  }

  async reserve({
    installationId,
    idempotencyKey,
    callSha256,
    amountAtomic,
    payer,
    payee,
    network,
    asset,
    paymentNonce,
    validBeforeMs,
  }) {
    nonempty(installationId, "installationId");
    nonempty(idempotencyKey, "idempotencyKey");
    if (!isCanonicalSha256(callSha256)) throw new InvalidInputError("callSha256 must be a lowercase SHA-256 digest");
    const proposedAmount = atomic(amountAtomic, "amountAtomic");
    const normalizedPayer = payerAddress(payer);
    const normalizedPayee = payerAddress(payee);
    if (network !== BASE_MAINNET_X402_NETWORK) throw new InvalidInputError(`network must be ${BASE_MAINNET_X402_NETWORK}`);
    if (!isAddress(asset) || getAddress(asset) !== getAddress(BASE_MAINNET_USDC)) {
      throw new InvalidInputError("asset must be canonical Base USDC");
    }
    if (typeof paymentNonce !== "string" || !PAYMENT_NONCE.test(paymentNonce.toLowerCase())) {
      throw new InvalidInputError("paymentNonce must be one canonical EIP-3009 bytes32 nonce");
    }
    const normalizedNonce = paymentNonce.toLowerCase();
    const now = this.#now();
    if (!Number.isSafeInteger(validBeforeMs) || validBeforeMs <= now) {
      throw new PaymentPolicyError("x402 authorization validBefore must be a future safe-integer timestamp");
    }
    const periodStartMs = Math.floor(now / this.#periodMs) * this.#periodMs;
    const periodEndMs = periodStartMs + this.#periodMs;
    if (!Number.isSafeInteger(periodStartMs) || !Number.isSafeInteger(periodEndMs)) {
      throw new LocalStateError("Payment-budget period exceeds safe timestamp bounds");
    }

    try {
      return this.#transaction(() => {
        this.#expire(now);
        const existing = this.#db.prepare(`
          SELECT * FROM payment_budget_reservations
          WHERE installation_id = ? AND idempotency_key = ?
        `).get(installationId, idempotencyKey);
        if (existing) {
          const exact = existing.call_sha256 === callSha256
            && existing.amount_atomic === amountAtomic
            && existing.payer === normalizedPayer
            && existing.payee === normalizedPayee
            && existing.network === network
            && existing.asset === getAddress(asset)
            && existing.payment_nonce === normalizedNonce
            && existing.period_start_ms === periodStartMs;
          throw new PaymentPolicyError(
            exact
              ? "This idempotency key already has an x402 payment reservation"
              : "This idempotency key is already bound to a different x402 payment reservation",
            { reservation_id: existing.reservation_id, status: existing.status },
          );
        }

        const periodRows = this.#db.prepare(`
          SELECT amount_atomic, status FROM payment_budget_reservations
          WHERE period_start_ms = ? AND period_end_ms = ?
        `).all(periodStartMs, periodEndMs);
        const periodExposure = periodRows.reduce(
          (sum, row) => sum + (CHARGED_STATUSES.has(row.status) ? BigInt(row.amount_atomic) : 0n),
          0n,
        );
        if (periodExposure + proposedAmount > BigInt(this.#maxPeriodAtomic)) {
          throw new PaymentPolicyError("Cumulative x402 payment period cap would be exceeded", {
            period_start_ms: periodStartMs,
            period_end_ms: periodEndMs,
            current_atomic: periodExposure.toString(),
            proposed_atomic: amountAtomic,
            cap_atomic: this.#maxPeriodAtomic,
          });
        }

        const outstandingRows = this.#db.prepare(`
          SELECT amount_atomic, status FROM payment_budget_reservations
          WHERE status IN ('RESERVED', 'TRANSMITTED')
        `).all();
        const outstandingAmount = outstandingRows.reduce(
          (sum, row) => sum + (ACTIVE_STATUSES.has(row.status) ? BigInt(row.amount_atomic) : 0n),
          0n,
        );
        if (outstandingRows.length + 1 > this.#maxOutstandingCount) {
          throw new PaymentPolicyError("Maximum outstanding x402 payment reservation count would be exceeded", {
            current_count: outstandingRows.length,
            cap_count: this.#maxOutstandingCount,
          });
        }
        if (outstandingAmount + proposedAmount > BigInt(this.#maxOutstandingAtomic)) {
          throw new PaymentPolicyError("Maximum outstanding x402 payment amount would be exceeded", {
            current_atomic: outstandingAmount.toString(),
            proposed_atomic: amountAtomic,
            cap_atomic: this.#maxOutstandingAtomic,
          });
        }

        const reservationId = randomUUID();
        this.#db.prepare(`
          INSERT INTO payment_budget_reservations (
            reservation_id, installation_id, idempotency_key, call_sha256,
            amount_atomic, payer, payee, network, asset, payment_nonce,
            period_start_ms, period_end_ms,
            valid_before_ms, status, transaction_hash, created_at_ms, updated_at_ms
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'RESERVED', NULL, ?, ?)
        `).run(
          reservationId,
          installationId,
          idempotencyKey,
          callSha256,
          amountAtomic,
          normalizedPayer,
          normalizedPayee,
          network,
          getAddress(asset),
          normalizedNonce,
          periodStartMs,
          periodEndMs,
          validBeforeMs,
          now,
          now,
        );
        return publicRecord(this.#db.prepare("SELECT * FROM payment_budget_reservations WHERE reservation_id = ?").get(reservationId));
      });
    } catch (cause) {
      if (cause instanceof PaymentPolicyError || cause instanceof LocalStateError) throw cause;
      throw new LocalStateError("Unable to reserve cumulative x402 payment budget", { cause });
    }
  }

  async markTransmitted({ reservationId, installationId, idempotencyKey, callSha256 }) {
    nonempty(reservationId, "reservationId");
    const binding = { installationId, idempotencyKey, callSha256 };
    const now = this.#now();
    try {
      return this.#transaction(() => {
        this.#expire(now);
        const row = this.#boundRow(reservationId, binding);
        if (row.status !== "RESERVED") {
          throw new LocalStateError(`Refusing payment reservation transition ${row.status} -> TRANSMITTED`);
        }
        this.#db.prepare(`
          UPDATE payment_budget_reservations
          SET status = 'TRANSMITTED', updated_at_ms = ? WHERE reservation_id = ?
        `).run(now, reservationId);
        return publicRecord(this.#db.prepare("SELECT * FROM payment_budget_reservations WHERE reservation_id = ?").get(reservationId));
      });
    } catch (cause) {
      if (cause instanceof LocalStateError) throw cause;
      throw new LocalStateError("Unable to mark x402 payment as transmitted", { cause });
    }
  }

  async releaseUntransmitted({ reservationId, installationId, idempotencyKey, callSha256 }) {
    nonempty(reservationId, "reservationId");
    const binding = { installationId, idempotencyKey, callSha256 };
    const now = this.#now();
    try {
      return this.#transaction(() => {
        const row = this.#boundRow(reservationId, binding);
        if (row.status !== "RESERVED") {
          throw new LocalStateError(`Only a definitely untransmitted RESERVED payment can be released; found ${row.status}`);
        }
        this.#db.prepare(`
          UPDATE payment_budget_reservations
          SET status = 'RELEASED_UNTRANSMITTED', updated_at_ms = ? WHERE reservation_id = ?
        `).run(now, reservationId);
        return publicRecord(this.#db.prepare("SELECT * FROM payment_budget_reservations WHERE reservation_id = ?").get(reservationId));
      });
    } catch (cause) {
      if (cause instanceof LocalStateError) throw cause;
      throw new LocalStateError("Unable to release definitely untransmitted x402 payment budget", { cause });
    }
  }

  async commitSettlement({ reservationId, installationId, idempotencyKey, callSha256, transaction }) {
    nonempty(reservationId, "reservationId");
    const normalizedTransaction = transactionHash(transaction);
    const binding = { installationId, idempotencyKey, callSha256 };
    const now = this.#now();
    try {
      return this.#transaction(() => {
        this.#expire(now);
        const row = this.#boundRow(reservationId, binding);
        if (row.status === "SETTLED" && row.transaction_hash === normalizedTransaction) return publicRecord(row);
        if (row.status !== "TRANSMITTED" && row.status !== "EXPIRED_UNKNOWN") {
          throw new LocalStateError(`Refusing payment reservation transition ${row.status} -> SETTLED`);
        }
        this.#db.prepare(`
          UPDATE payment_budget_reservations
          SET status = 'SETTLED', transaction_hash = ?, updated_at_ms = ?
          WHERE reservation_id = ?
        `).run(normalizedTransaction, now, reservationId);
        return publicRecord(this.#db.prepare("SELECT * FROM payment_budget_reservations WHERE reservation_id = ?").get(reservationId));
      });
    } catch (cause) {
      if (cause instanceof LocalStateError) throw cause;
      throw new LocalStateError("Unable to commit settled x402 payment budget", { cause });
    }
  }

  async resolve({ reservationId, resolution, transaction }) {
    nonempty(reservationId, "reservationId");
    if (resolution !== "SETTLED" && resolution !== "NOT_SETTLED") {
      throw new InvalidInputError("resolution must be SETTLED or NOT_SETTLED");
    }
    const now = this.#now();
    try {
      return this.#transaction(() => {
        this.#expire(now);
        const row = this.#db.prepare("SELECT * FROM payment_budget_reservations WHERE reservation_id = ?").get(reservationId);
        if (!row) throw new LocalStateError("Payment-budget reservation does not exist");
        if (resolution === "SETTLED") {
          const normalizedTransaction = transactionHash(transaction);
          if (row.status !== "TRANSMITTED" && row.status !== "EXPIRED_UNKNOWN" && row.status !== "SETTLED") {
            throw new LocalStateError(`Refusing manual settlement of ${row.status} payment reservation`);
          }
          if (row.status === "SETTLED" && row.transaction_hash !== normalizedTransaction) {
            throw new LocalStateError("Settled payment reservation is bound to a different transaction");
          }
          this.#db.prepare(`
            UPDATE payment_budget_reservations
            SET status = 'SETTLED', transaction_hash = ?, updated_at_ms = ?
            WHERE reservation_id = ?
          `).run(normalizedTransaction, now, reservationId);
        } else {
          if (row.status === "SETTLED") throw new LocalStateError("A settled payment reservation cannot be resolved as unpaid");
          if (row.status !== "RESERVED" && row.status !== "TRANSMITTED" && row.status !== "EXPIRED_UNKNOWN") {
            throw new LocalStateError(`Refusing manual unpaid resolution of ${row.status} payment reservation`);
          }
          this.#db.prepare(`
            UPDATE payment_budget_reservations
            SET status = 'RESOLVED_UNPAID', updated_at_ms = ? WHERE reservation_id = ?
          `).run(now, reservationId);
        }
        return publicRecord(this.#db.prepare("SELECT * FROM payment_budget_reservations WHERE reservation_id = ?").get(reservationId));
      });
    } catch (cause) {
      if (cause instanceof InvalidInputError || cause instanceof LocalStateError) throw cause;
      throw new LocalStateError("Unable to manually resolve x402 payment reservation", { cause });
    }
  }

  async get(reservationId) {
    nonempty(reservationId, "reservationId");
    const now = this.#now();
    try {
      return this.#transaction(() => {
        this.#expire(now);
        return publicRecord(this.#db.prepare("SELECT * FROM payment_budget_reservations WHERE reservation_id = ?").get(reservationId));
      });
    } catch (cause) {
      if (cause instanceof LocalStateError) throw cause;
      throw new LocalStateError("Unable to read x402 payment reservation", { cause });
    }
  }

  async snapshot(atMs = this.#now()) {
    if (!Number.isSafeInteger(atMs) || atMs < 0) throw new InvalidInputError("snapshot timestamp must be a safe integer");
    try {
      return this.#transaction(() => {
        this.#expire(atMs);
        const periodStartMs = Math.floor(atMs / this.#periodMs) * this.#periodMs;
        const periodEndMs = periodStartMs + this.#periodMs;
        const rows = this.#db.prepare("SELECT * FROM payment_budget_reservations ORDER BY created_at_ms, reservation_id").all();
        const periodExposure = rows.reduce(
          (sum, row) => sum + (
            row.period_start_ms === periodStartMs
            && row.period_end_ms === periodEndMs
            && CHARGED_STATUSES.has(row.status)
              ? BigInt(row.amount_atomic)
              : 0n
          ),
          0n,
        );
        const outstanding = rows.filter((row) => ACTIVE_STATUSES.has(row.status));
        const outstandingAmount = outstanding.reduce((sum, row) => sum + BigInt(row.amount_atomic), 0n);
        return Object.freeze({
          schema: "goldkey.payment-budget-snapshot.v1",
          periodStartMs,
          periodEndMs,
          periodExposureAtomic: periodExposure.toString(),
          maxPeriodAtomic: this.#maxPeriodAtomic,
          outstandingAmountAtomic: outstandingAmount.toString(),
          maxOutstandingAtomic: this.#maxOutstandingAtomic,
          outstandingCount: outstanding.length,
          maxOutstandingCount: this.#maxOutstandingCount,
          reservations: Object.freeze(rows.map(publicRecord)),
        });
      });
    } catch (cause) {
      if (cause instanceof InvalidInputError || cause instanceof LocalStateError) throw cause;
      throw new LocalStateError("Unable to read x402 payment-budget snapshot", { cause });
    }
  }

  close() {
    this.#db.close();
  }
}

Object.freeze(SqlitePaymentBudgetStore.prototype);
