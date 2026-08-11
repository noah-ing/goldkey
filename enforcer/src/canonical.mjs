import { createHash } from "node:crypto";
import { InvalidInputError } from "./errors.mjs";

const MAX_CANONICAL_DEPTH = 48;
const MAX_CANONICAL_NODES = 50_000;

export function canonicalize(value) {
  let nodes = 0;

  function encode(current, depth) {
    nodes += 1;
    if (nodes > MAX_CANONICAL_NODES) throw new InvalidInputError(`JSON exceeds ${MAX_CANONICAL_NODES} nodes`);
    if (depth > MAX_CANONICAL_DEPTH) throw new InvalidInputError(`JSON exceeds depth ${MAX_CANONICAL_DEPTH}`);

    if (current === null) return "null";
    if (typeof current === "boolean" || typeof current === "string") return JSON.stringify(current);
    if (typeof current === "number") {
      if (!Number.isFinite(current)) throw new InvalidInputError("NaN and Infinity are not valid JSON values");
      return JSON.stringify(Object.is(current, -0) ? 0 : current);
    }
    if (Array.isArray(current)) return `[${current.map((entry) => encode(entry, depth + 1)).join(",")}]`;
    if (typeof current === "object") {
      const prototype = Object.getPrototypeOf(current);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new InvalidInputError("Only plain JSON objects may be signed");
      }
      const entries = Object.keys(current).sort().map((key) => {
        const child = current[key];
        if (child === undefined) throw new InvalidInputError(`Undefined JSON value at property ${key}`);
        return `${JSON.stringify(key)}:${encode(child, depth + 1)}`;
      });
      return `{${entries.join(",")}}`;
    }
    throw new InvalidInputError(`Unsupported JSON value type: ${typeof current}`);
  }

  return encode(value, 0);
}

export function canonicalBytes(value) {
  return Buffer.from(canonicalize(value), "utf8");
}

export function sha256Bytes(value) {
  return createHash("sha256").update(value).digest();
}

export function sha256Hex(value) {
  return sha256Bytes(value).toString("hex");
}

export function canonicalSha256(value) {
  return sha256Hex(canonicalBytes(value));
}

export function toBase64url(value) {
  return Buffer.from(value).toString("base64url");
}

export function fromBase64url(value, { exactBytes } = {}) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new InvalidInputError("Expected an unpadded base64url string");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) throw new InvalidInputError("Non-canonical base64url encoding");
  if (exactBytes !== undefined && decoded.byteLength !== exactBytes) {
    throw new InvalidInputError(`Expected ${exactBytes} decoded bytes`);
  }
  return decoded;
}

export function exactBytes(value, name = "bytes") {
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (value instanceof Uint8Array) return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  if (typeof value === "string") return Buffer.from(value, "utf8");
  throw new InvalidInputError(`${name} must be a Buffer, Uint8Array, or UTF-8 string`);
}

export function canonicalJsonBytes(value, name = "JSON bytes") {
  const bytes = exactBytes(value, name);
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new InvalidInputError(`${name} must contain valid UTF-8 JSON`);
  }
  const canonical = canonicalBytes(parsed);
  if (!bytes.equals(canonical)) {
    throw new InvalidInputError(`${name} must use canonical JSON (sorted keys, no insignificant whitespace)`);
  }
  return { bytes, parsed };
}

export function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

export function isCanonicalSha256(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

export function assertSafeIdentifier(value, name, { min = 1, max = 128 } = {}) {
  if (typeof value !== "string" || value.length < min || value.length > max || !/^[A-Za-z0-9._:-]+$/.test(value)) {
    throw new InvalidInputError(`${name} must be ${min}-${max} characters using only letters, digits, dot, underscore, colon, or hyphen`);
  }
  return value;
}

export function assertIdempotencyKey(value) {
  return assertSafeIdentifier(value, "idempotencyKey", { min: 8, max: 128 });
}
