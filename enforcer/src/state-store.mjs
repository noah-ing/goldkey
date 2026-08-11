import { randomUUID } from "node:crypto";
import { mkdir, open, readFile, rename, stat, unlink } from "node:fs/promises";
import path from "node:path";
import { canonicalize, isCanonicalSha256, sha256Hex } from "./canonical.mjs";
import {
  IdempotencyConflictError,
  InvalidInputError,
  LocalStateError,
} from "./errors.mjs";

const STATES = new Set([
  "AUTHORIZING",
  "AUTHORIZED",
  "DENIED",
  "AUTHORIZATION_FAILED",
  "PREPARATION_FAILED",
  "FORWARDING",
  "SUCCEEDED",
  "UNKNOWN",
]);

const TRANSITIONS = Object.freeze({
  AUTHORIZING: new Set(["AUTHORIZED", "DENIED", "AUTHORIZATION_FAILED"]),
  AUTHORIZED: new Set(["FORWARDING", "PREPARATION_FAILED"]),
  FORWARDING: new Set(["SUCCEEDED", "UNKNOWN"]),
});

function validateRecord(record, filename) {
  if (!record || record.schema !== "goldkey-enforcer-state.v1" || !STATES.has(record.state)) {
    throw new LocalStateError(`Local state record ${filename} is invalid`);
  }
  if (!isCanonicalSha256(record.call_hash) || !Number.isSafeInteger(record.revision) || record.revision < 1) {
    throw new LocalStateError(`Local state record ${filename} has invalid integrity fields`);
  }
  return record;
}

export class FileOutcomeStore {
  constructor({ directory, clock = () => Date.now() }) {
    if (typeof directory !== "string" || directory.length === 0) throw new InvalidInputError("Outcome store directory is required");
    this.directory = path.resolve(directory);
    this.clock = clock;
    this.ready = undefined;
  }

  async #initialize() {
    this.ready ??= (async () => {
      await mkdir(this.directory, { recursive: true, mode: 0o700 });
      if (process.platform !== "win32") {
        const metadata = await stat(this.directory);
        if ((metadata.mode & 0o077) !== 0) {
          throw new LocalStateError(`Outcome directory ${this.directory} must not be accessible by group or other users`);
        }
      }
    })();
    await this.ready;
  }

  async #syncDirectory() {
    if (process.platform === "win32") return;
    let handle;
    try {
      handle = await open(this.directory, "r");
      await handle.sync();
    } catch (cause) {
      throw new LocalStateError(`Unable to sync local outcome directory ${this.directory}`, { cause });
    } finally {
      await handle?.close().catch(() => {});
    }
  }

  #filename(idempotencyKey) {
    return path.join(this.directory, `${sha256Hex(Buffer.from(idempotencyKey, "utf8"))}.json`);
  }

  async #readFilename(filename) {
    let bytes;
    try {
      bytes = await readFile(filename, "utf8");
    } catch (cause) {
      if (cause?.code === "ENOENT") return undefined;
      throw new LocalStateError(`Unable to read local outcome state ${filename}`, { cause });
    }
    try {
      return validateRecord(JSON.parse(bytes), filename);
    } catch (cause) {
      if (cause instanceof LocalStateError) throw cause;
      throw new LocalStateError(`Unable to parse local outcome state ${filename}`, { cause });
    }
  }

  async get(idempotencyKey) {
    await this.#initialize();
    return this.#readFilename(this.#filename(idempotencyKey));
  }

  async begin({ idempotencyKey, callHash, callKind }) {
    await this.#initialize();
    if (!isCanonicalSha256(callHash)) throw new InvalidInputError("callHash must be a lowercase SHA-256 hex digest");
    const filename = this.#filename(idempotencyKey);
    const now = this.clock();
    const record = {
      schema: "goldkey-enforcer-state.v1",
      revision: 1,
      idempotency_key: idempotencyKey,
      call_hash: callHash,
      call_kind: callKind,
      state: "AUTHORIZING",
      created_at: new Date(now).toISOString(),
      updated_at: new Date(now).toISOString(),
    };
    let handle;
    try {
      handle = await open(filename, "wx", 0o600);
      await handle.writeFile(`${canonicalize(record)}\n`, "utf8");
      await handle.sync();
      await handle.close();
      handle = undefined;
      await this.#syncDirectory();
      return { created: true, record };
    } catch (cause) {
      await handle?.close().catch(() => {});
      if (cause?.code !== "EEXIST") throw new LocalStateError(`Unable to create local outcome state ${filename}`, { cause });
      const existing = await this.#readFilename(filename);
      if (!existing) throw new LocalStateError(`Local outcome state ${filename} disappeared during creation`);
      if (existing.idempotency_key !== idempotencyKey || existing.call_hash !== callHash) {
        throw new IdempotencyConflictError(undefined, {
          existing_call_hash: existing.call_hash,
          proposed_call_hash: callHash,
          existing_state: existing.state,
        });
      }
      return { created: false, record: existing };
    }
  }

  async transition({ idempotencyKey, callHash, from, to, patch = {} }) {
    await this.#initialize();
    if (!STATES.has(to)) throw new InvalidInputError(`Unsupported local state transition target ${to}`);
    const filename = this.#filename(idempotencyKey);
    const current = await this.#readFilename(filename);
    if (!current) throw new LocalStateError(`Local outcome state ${filename} does not exist`);
    if (current.idempotency_key !== idempotencyKey || current.call_hash !== callHash) {
      throw new IdempotencyConflictError(undefined, { existing_call_hash: current.call_hash, proposed_call_hash: callHash });
    }
    const expected = Array.isArray(from) ? new Set(from) : new Set([from]);
    if (!expected.has(current.state) || !TRANSITIONS[current.state]?.has(to)) {
      throw new LocalStateError(`Refusing invalid local state transition ${current.state} -> ${to}`);
    }
    const now = this.clock();
    const next = {
      ...current,
      ...patch,
      schema: current.schema,
      revision: current.revision + 1,
      idempotency_key: current.idempotency_key,
      call_hash: current.call_hash,
      call_kind: current.call_kind,
      state: to,
      created_at: current.created_at,
      updated_at: new Date(now).toISOString(),
    };
    const temporary = `${filename}.${process.pid}.${randomUUID()}.tmp`;
    let handle;
    try {
      handle = await open(temporary, "wx", 0o600);
      await handle.writeFile(`${canonicalize(next)}\n`, "utf8");
      await handle.sync();
      await handle.close();
      handle = undefined;
      await rename(temporary, filename);
      await this.#syncDirectory();
      return next;
    } catch (cause) {
      await handle?.close().catch(() => {});
      await unlink(temporary).catch(() => {});
      throw new LocalStateError(`Unable to persist local state transition ${current.state} -> ${to}`, { cause });
    }
  }
}
