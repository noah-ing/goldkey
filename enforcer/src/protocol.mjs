import { createPublicKey, verify as verifyBytes } from "node:crypto";
import { getAddress, isAddress } from "viem";
import {
  assertIdempotencyKey,
  assertSafeIdentifier,
  canonicalBytes,
  canonicalSha256,
  canonicalize,
  deepFreeze,
  isCanonicalSha256,
} from "./canonical.mjs";
import { InvalidInputError, ReceiptVerificationError } from "./errors.mjs";

export const GUARD_REQUEST_SCHEMA = "goldkey.guard-request.v1";
export const GUARD_REQUEST_SIGNING_DOMAIN = "GoldKey Guard Request v1";
export const GUARD_COMMIT_SCHEMA = "goldkey.guard-commit.v1";
export const GUARD_COMPLETION_SCHEMA = "goldkey.guard-completion.v1";
export const GUARD_COMMIT_SIGNING_DOMAIN = "GoldKey Guard Commit v1";
export const GUARD_COMPLETION_SIGNING_DOMAIN = "GoldKey Guard Completion v1";
export const GUARD_AUTHORIZATION_RECEIPT_SCHEMA = "goldkey.guard-authorization-receipt.v1";
export const GUARD_AUTHORIZATION_ENVELOPE_SCHEMA = "goldkey.guard-authorization-envelope.v1";
export const GUARD_RECEIPT_KEYSET_SCHEMA = "goldkey.guard-receipt-keyset.v1";
export const GUARD_EVIDENCE_SCHEMA = "goldkey.guard-evidence.v1";
export const GUARD_RECEIPT_SIGNING_DOMAIN = "GoldKey Guard Authorization Receipt v1";

const MAX_CALL_BYTES = 64 * 1024;
const MAX_EVIDENCE_BYTES = 32 * 1024;
const MAX_RECEIPT_TTL_MS = 5 * 60_000;
const SHA256 = /^[0-9a-f]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const TOOL = /^[A-Za-z0-9._:-]{1,256}$/;
const REASON = /^[a-z0-9._:-]{1,128}$/;
const DATA = /^0x(?:[0-9a-fA-F]{2})*$/;
const ATOMIC = /^(0|[1-9]\d{0,77})$/;
const MAX_UINT256 = (1n << 256n) - 1n;
const EFFECTS = new Set(["read", "write", "network", "payment", "execute"]);
const DECISIONS = new Set(["ALLOW", "REVIEW", "BLOCK"]);
const CALL_KINDS = new Set(["mcp_tool", "https", "evm_transaction"]);
const OUTCOME_STATUSES = new Set(["succeeded", "failed", "outcome_unknown"]);

function exactKeys(value, allowed, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new InvalidInputError(`${name} must be an object`);
  const extras = Object.keys(value).filter((key) => !allowed.has(key));
  if (extras.length > 0) throw new InvalidInputError(`${name} contains unsupported fields`, { fields: extras.sort() });
}

function canonicalDate(value, name) {
  if (typeof value !== "string") throw new InvalidInputError(`${name} must be an ISO date-time`);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new InvalidInputError(`${name} must be a canonical ISO date-time`);
  }
  return value;
}

function jsonClone(value, name) {
  try {
    return JSON.parse(canonicalize(value));
  } catch (cause) {
    if (cause instanceof InvalidInputError) throw cause;
    throw new InvalidInputError(`${name} must be a JSON value`, { cause: cause.message });
  }
}

function normalizeQuery(query) {
  if (!query || typeof query !== "object" || Array.isArray(query)) throw new InvalidInputError("call.query must be an object");
  const keys = Object.keys(query);
  if (keys.length > 100) throw new InvalidInputError("call.query must contain at most 100 keys");
  const normalized = {};
  for (const key of keys.sort()) {
    if (key.length < 1 || key.length > 256 || /[\r\n\0]/.test(key)) throw new InvalidInputError("call.query contains an invalid key");
    const values = Array.isArray(query[key]) ? query[key] : [query[key]];
    if (values.length < 1 || values.length > 20) throw new InvalidInputError(`call.query.${key} contains too many values`);
    if (!values.every((value) => typeof value === "string" && value.length <= 2048 && !/[\r\n\0]/.test(value))) {
      throw new InvalidInputError(`call.query.${key} must contain bounded strings`);
    }
    normalized[key] = Array.isArray(query[key]) ? [...values] : values[0];
  }
  return normalized;
}

function atomic(value, name) {
  if (typeof value !== "string" || !ATOMIC.test(value)) throw new InvalidInputError(`${name} must be a canonical atomic-unit integer string`);
  if (BigInt(value) > MAX_UINT256) throw new InvalidInputError(`${name} exceeds uint256`);
  return value;
}

export function normalizeEvmTransaction(transaction) {
  exactKeys(transaction, new Set([
    "chain_id",
    "from",
    "to",
    "value_atomic",
    "data",
    "nonce",
    "gas_limit",
    "max_fee_per_gas_atomic",
    "max_priority_fee_per_gas_atomic",
    "type",
    "access_list",
  ]), "transaction");
  for (const field of ["nonce", "gas_limit", "max_fee_per_gas_atomic", "max_priority_fee_per_gas_atomic"]) {
    if (!Object.hasOwn(transaction, field)) throw new InvalidInputError(`transaction.${field} is required`);
  }
  if (!Number.isSafeInteger(transaction.chain_id) || transaction.chain_id <= 0) throw new InvalidInputError("transaction.chain_id must be a positive safe integer");
  if (!isAddress(transaction.from)) throw new InvalidInputError("transaction.from must be an EVM address");
  if (transaction.to !== undefined && transaction.to !== null && !isAddress(transaction.to)) throw new InvalidInputError("transaction.to must be an EVM address when provided");
  if (typeof transaction.data !== "string" || !DATA.test(transaction.data)) throw new InvalidInputError("transaction.data must be even-length hexadecimal bytes");
  if (transaction.type !== undefined && transaction.type !== "eip1559") throw new InvalidInputError("transaction.type must be eip1559 when provided");
  if (transaction.access_list !== undefined && (!Array.isArray(transaction.access_list) || transaction.access_list.length !== 0)) throw new InvalidInputError("transaction.access_list must be empty when provided");
  if ((transaction.data.length - 2) / 2 > MAX_CALL_BYTES) throw new InvalidInputError(`transaction.data exceeds ${MAX_CALL_BYTES} bytes`);
  const normalized = {
    chain_id: transaction.chain_id,
    from: getAddress(transaction.from),
    ...(transaction.to === undefined || transaction.to === null ? {} : { to: getAddress(transaction.to) }),
    value_atomic: atomic(transaction.value_atomic, "transaction.value_atomic"),
    data: transaction.data.toLowerCase(),
    type: "eip1559",
    access_list: Object.freeze([]),
  };
  for (const field of ["nonce", "gas_limit", "max_fee_per_gas_atomic", "max_priority_fee_per_gas_atomic"]) {
    if (transaction[field] !== undefined) normalized[field] = atomic(transaction[field], `transaction.${field}`);
  }
  if (BigInt(normalized.nonce) > BigInt(Number.MAX_SAFE_INTEGER)) throw new InvalidInputError("transaction.nonce exceeds the supported safe-integer range");
  if (BigInt(normalized.gas_limit) === 0n) throw new InvalidInputError("transaction.gas_limit must be greater than zero");
  if (BigInt(normalized.max_fee_per_gas_atomic) === 0n) throw new InvalidInputError("transaction.max_fee_per_gas_atomic must be greater than zero");
  if (
    normalized.max_priority_fee_per_gas_atomic !== undefined
    && normalized.max_fee_per_gas_atomic !== undefined
    && BigInt(normalized.max_priority_fee_per_gas_atomic) > BigInt(normalized.max_fee_per_gas_atomic)
  ) throw new InvalidInputError("max_priority_fee_per_gas_atomic must not exceed max_fee_per_gas_atomic");
  return Object.freeze(normalized);
}

export function normalizeGuardCall(call) {
  if (!call || typeof call !== "object" || Array.isArray(call)) throw new InvalidInputError("call must be an object");
  let normalized;
  if (call.kind === "mcp_tool") {
    exactKeys(call, new Set(["kind", "connector_id", "tool", "input_schema_sha256", "arguments"]), "mcp_tool call");
    if (!SHA256.test(call.input_schema_sha256)) throw new InvalidInputError("call.input_schema_sha256 must be a lowercase SHA-256 digest");
    if (typeof call.tool !== "string" || !TOOL.test(call.tool)) throw new InvalidInputError("call.tool is invalid");
    normalized = {
      kind: "mcp_tool",
      connector_id: assertSafeIdentifier(call.connector_id, "call.connector_id"),
      tool: call.tool,
      input_schema_sha256: call.input_schema_sha256,
      arguments: jsonClone(call.arguments, "call.arguments"),
    };
  } else if (call.kind === "https") {
    exactKeys(call, new Set(["kind", "connector_id", "operation_id", "query", "body"]), "https call");
    normalized = {
      kind: "https",
      connector_id: assertSafeIdentifier(call.connector_id, "call.connector_id"),
      operation_id: assertSafeIdentifier(call.operation_id, "call.operation_id"),
    };
    if (call.query !== undefined) normalized.query = normalizeQuery(call.query);
    if (call.body !== undefined) normalized.body = jsonClone(call.body, "call.body");
  } else if (call.kind === "evm_transaction") {
    exactKeys(call, new Set(["kind", "connector_id", "transaction"]), "evm_transaction call");
    normalized = {
      kind: "evm_transaction",
      connector_id: assertSafeIdentifier(call.connector_id, "call.connector_id"),
      transaction: normalizeEvmTransaction(call.transaction),
    };
  } else {
    throw new InvalidInputError("call.kind must be mcp_tool, https, or evm_transaction");
  }
  const canonical = canonicalize(normalized);
  if (Buffer.byteLength(canonical) > MAX_CALL_BYTES) throw new InvalidInputError(`Canonical call exceeds ${MAX_CALL_BYTES} bytes`);
  return deepFreeze(JSON.parse(canonical));
}

export function hashGuardCall(call) {
  return canonicalSha256(normalizeGuardCall(call));
}

function unsignedGuardRequest(request) {
  const value = { ...request };
  delete value.signature;
  exactKeys(value, new Set(["schema", "installation_id", "idempotency_key", "issued_at", "call"]), "unsigned guard request");
  if (value.schema !== GUARD_REQUEST_SCHEMA) throw new InvalidInputError(`request.schema must be ${GUARD_REQUEST_SCHEMA}`);
  return Object.freeze({
    schema: GUARD_REQUEST_SCHEMA,
    installation_id: assertSafeIdentifier(value.installation_id, "request.installation_id"),
    idempotency_key: assertIdempotencyKey(value.idempotency_key),
    issued_at: canonicalDate(value.issued_at, "request.issued_at"),
    call: normalizeGuardCall(value.call),
  });
}

export function guardRequestSigningMessage(request) {
  return `${GUARD_REQUEST_SIGNING_DOMAIN}\n${canonicalize(unsignedGuardRequest(request))}`;
}

export function createSignedGuardRequest({ installationIdentity, idempotencyKey, call, issuedAt = Date.now() }) {
  if (!installationIdentity?.installationId || typeof installationIdentity.signMessage !== "function") throw new InvalidInputError("Installation identity is missing signMessage");
  const unsigned = unsignedGuardRequest({
    schema: GUARD_REQUEST_SCHEMA,
    installation_id: installationIdentity.installationId,
    idempotency_key: idempotencyKey,
    issued_at: new Date(issuedAt).toISOString(),
    call,
  });
  const signature = installationIdentity.signMessage(guardRequestSigningMessage(unsigned));
  if (!SIGNATURE.test(signature)) throw new InvalidInputError("Installation identity returned an invalid Ed25519 signature");
  return Object.freeze({ ...unsigned, signature });
}

function normalizeLifecycleUnsigned(envelope, kind) {
  const completion = kind === "completion";
  const schema = completion ? GUARD_COMPLETION_SCHEMA : GUARD_COMMIT_SCHEMA;
  const value = { ...envelope };
  delete value.signature;
  exactKeys(value, new Set([
    "schema", "installation_id", "execution_id", "receipt_id", "receipt_sha256", "call_sha256", "issued_at",
    ...(completion ? ["outcome_status", "outcome_sha256"] : []),
  ]), `${kind} envelope`);
  if (value.schema !== schema) throw new InvalidInputError(`envelope.schema must be ${schema}`);
  if (!isCanonicalSha256(value.receipt_sha256) || !isCanonicalSha256(value.call_sha256)) throw new InvalidInputError(`${kind} hashes must be lowercase SHA-256 digests`);
  const normalized = {
    schema,
    installation_id: assertSafeIdentifier(value.installation_id, "installation_id"),
    execution_id: assertSafeIdentifier(value.execution_id, "execution_id"),
    receipt_id: assertSafeIdentifier(value.receipt_id, "receipt_id"),
    receipt_sha256: value.receipt_sha256,
    call_sha256: value.call_sha256,
    issued_at: canonicalDate(value.issued_at, "issued_at"),
  };
  if (completion) {
    if (!OUTCOME_STATUSES.has(value.outcome_status) || !isCanonicalSha256(value.outcome_sha256)) throw new InvalidInputError("Completion outcome fields are invalid");
    normalized.outcome_status = value.outcome_status;
    normalized.outcome_sha256 = value.outcome_sha256;
  }
  return Object.freeze(normalized);
}

export function createSignedGuardLifecycle({ installationIdentity, kind, receipt, receiptSha256, callSha256, outcomeStatus, outcomeSha256, issuedAt = Date.now() }) {
  if (!installationIdentity?.installationId || typeof installationIdentity.signMessage !== "function") throw new InvalidInputError("Installation identity is missing signMessage");
  const completion = kind === "completion";
  const unsigned = normalizeLifecycleUnsigned({
    schema: completion ? GUARD_COMPLETION_SCHEMA : GUARD_COMMIT_SCHEMA,
    installation_id: installationIdentity.installationId,
    execution_id: receipt.receipt_id,
    receipt_id: receipt.receipt_id,
    receipt_sha256: receiptSha256,
    call_sha256: callSha256,
    issued_at: new Date(issuedAt).toISOString(),
    ...(completion ? { outcome_status: outcomeStatus, outcome_sha256: outcomeSha256 } : {}),
  }, kind);
  const domain = completion ? GUARD_COMPLETION_SIGNING_DOMAIN : GUARD_COMMIT_SIGNING_DOMAIN;
  const signature = installationIdentity.signMessage(`${domain}\n${canonicalize(unsigned)}`);
  if (!SIGNATURE.test(signature)) throw new InvalidInputError(`Installation ${kind} signature is invalid`);
  return Object.freeze({ ...unsigned, signature });
}

function stableReasons(reasonCodes) {
  if (!Array.isArray(reasonCodes) || reasonCodes.length > 100 || !reasonCodes.every((reason) => typeof reason === "string" && REASON.test(reason))) {
    throw new ReceiptVerificationError("Receipt reason_codes are invalid");
  }
  return [...new Set(reasonCodes)].sort();
}

function normalizeEvidence(evidence, decision, reasonCodes) {
  exactKeys(evidence, new Set(["schema", "decision", "reason_codes", "effect", "destination", "details"]), "guard evidence");
  if (evidence.schema !== GUARD_EVIDENCE_SCHEMA || evidence.decision !== decision) throw new ReceiptVerificationError("Receipt evidence schema or decision is invalid");
  const reasons = stableReasons(evidence.reason_codes);
  if (canonicalize(reasons) !== canonicalize(reasonCodes)) throw new ReceiptVerificationError("Receipt evidence reason_codes do not match receipt");
  if (evidence.effect !== null && !EFFECTS.has(evidence.effect)) throw new ReceiptVerificationError("Receipt evidence effect is invalid");
  if (evidence.destination !== null && (typeof evidence.destination !== "string" || evidence.destination.length < 1 || evidence.destination.length > 2048 || /[\r\n\0]/.test(evidence.destination))) {
    throw new ReceiptVerificationError("Receipt evidence destination is invalid");
  }
  const normalized = { schema: GUARD_EVIDENCE_SCHEMA, decision, reason_codes: reasons, effect: evidence.effect, destination: evidence.destination };
  if (evidence.details !== undefined) {
    if (!evidence.details || typeof evidence.details !== "object" || Array.isArray(evidence.details)) throw new ReceiptVerificationError("Receipt evidence details must be an object");
    normalized.details = jsonClone(evidence.details, "receipt evidence details");
  }
  const canonical = canonicalize(normalized);
  if (Buffer.byteLength(canonical) > MAX_EVIDENCE_BYTES) throw new ReceiptVerificationError(`Receipt evidence exceeds ${MAX_EVIDENCE_BYTES} bytes`);
  return deepFreeze(JSON.parse(canonical));
}

function normalizeReceipt(receipt) {
  exactKeys(receipt, new Set([
    "schema", "receipt_id", "key_id", "installation_id", "idempotency_key", "connector_id", "kind", "policy_id",
    "policy_version", "policy_sha256", "call_sha256", "evidence_sha256", "decision", "reason_codes", "issued_at", "expires_at",
  ]), "authorization receipt");
  if (receipt.schema !== GUARD_AUTHORIZATION_RECEIPT_SCHEMA) throw new ReceiptVerificationError("Receipt schema is invalid");
  if (!Number.isSafeInteger(receipt.policy_version) || receipt.policy_version < 1) throw new ReceiptVerificationError("Receipt policy_version is invalid");
  if (!CALL_KINDS.has(receipt.kind) || !DECISIONS.has(receipt.decision)) throw new ReceiptVerificationError("Receipt kind or decision is invalid");
  for (const field of ["policy_sha256", "call_sha256", "evidence_sha256"]) if (!SHA256.test(receipt[field])) throw new ReceiptVerificationError(`Receipt ${field} is invalid`);
  const issuedAt = canonicalDate(receipt.issued_at, "receipt.issued_at");
  const expiresAt = canonicalDate(receipt.expires_at, "receipt.expires_at");
  const lifetime = Date.parse(expiresAt) - Date.parse(issuedAt);
  if (lifetime < 1 || lifetime > MAX_RECEIPT_TTL_MS) throw new ReceiptVerificationError("Receipt lifetime is invalid");
  return Object.freeze({
    schema: GUARD_AUTHORIZATION_RECEIPT_SCHEMA,
    receipt_id: assertSafeIdentifier(receipt.receipt_id, "receipt.receipt_id"),
    key_id: assertSafeIdentifier(receipt.key_id, "receipt.key_id"),
    installation_id: assertSafeIdentifier(receipt.installation_id, "receipt.installation_id"),
    idempotency_key: assertIdempotencyKey(receipt.idempotency_key),
    connector_id: assertSafeIdentifier(receipt.connector_id, "receipt.connector_id"),
    kind: receipt.kind,
    policy_id: assertSafeIdentifier(receipt.policy_id, "receipt.policy_id"),
    policy_version: receipt.policy_version,
    policy_sha256: receipt.policy_sha256,
    call_sha256: receipt.call_sha256,
    evidence_sha256: receipt.evidence_sha256,
    decision: receipt.decision,
    reason_codes: Object.freeze(stableReasons(receipt.reason_codes)),
    issued_at: issuedAt,
    expires_at: expiresAt,
  });
}

export function normalizeReceiptKeyset({ receiptKeyset, receiptPublicJwk, receiptKeyId } = {}) {
  let keyset = receiptKeyset;
  if (!keyset && receiptPublicJwk) {
    const kid = receiptPublicJwk.kid ?? receiptKeyId;
    if (!kid) throw new InvalidInputError("A receiptKeyId is required when the public JWK has no kid");
    keyset = { schema: GUARD_RECEIPT_KEYSET_SCHEMA, keys: [{ ...receiptPublicJwk, kid }] };
  }
  exactKeys(keyset, new Set(["schema", "keys"]), "receipt keyset");
  if (keyset.schema !== GUARD_RECEIPT_KEYSET_SCHEMA || !Array.isArray(keyset.keys) || keyset.keys.length < 1 || keyset.keys.length > 32) {
    throw new InvalidInputError("Receipt keyset must contain 1-32 keys");
  }
  const keys = keyset.keys.map((jwk, index) => {
    exactKeys(jwk, new Set([
      "kty",
      "crv",
      "x",
      "kid",
      "use",
      "alg",
      "key_ops",
      "not_before",
      "signing_not_after",
      "revoked_at",
    ]), `receipt keyset key ${index}`);
    if (
      jwk.kty !== "OKP"
      || jwk.crv !== "Ed25519"
      || typeof jwk.x !== "string"
      || !/^[A-Za-z0-9_-]{43}$/.test(jwk.x)
      || typeof jwk.kid !== "string"
      || Object.hasOwn(jwk, "d")
      || Object.hasOwn(jwk, "k")
    ) {
      throw new InvalidInputError("Receipt keyset contains a non-public or invalid Ed25519 JWK");
    }
    assertSafeIdentifier(jwk.kid, "receipt JWK kid");
    if (jwk.use !== undefined && jwk.use !== "sig") throw new InvalidInputError("Receipt key JWK use must be sig");
    if (jwk.alg !== undefined && jwk.alg !== "EdDSA") throw new InvalidInputError("Receipt key JWK alg must be EdDSA");
    if (jwk.key_ops !== undefined && (!Array.isArray(jwk.key_ops) || jwk.key_ops.length !== 1 || jwk.key_ops[0] !== "verify")) {
      throw new InvalidInputError("Receipt key JWK key_ops must contain only verify");
    }

    const hasNotBefore = jwk.not_before !== undefined;
    const hasSigningNotAfter = jwk.signing_not_after !== undefined;
    if (hasNotBefore !== hasSigningNotAfter) throw new InvalidInputError("Receipt key signing interval must provide not_before and signing_not_after together");
    if (index > 0 && !hasNotBefore) throw new InvalidInputError("Retained receipt keys must have a bounded signing interval");
    if (jwk.revoked_at !== undefined && !hasNotBefore) throw new InvalidInputError("Receipt key revoked_at requires a bounded signing interval");

    const normalized = {
      kty: "OKP",
      crv: "Ed25519",
      x: jwk.x,
      kid: jwk.kid,
      use: "sig",
      alg: "EdDSA",
      key_ops: Object.freeze(["verify"]),
    };
    if (hasNotBefore) {
      normalized.not_before = canonicalDate(jwk.not_before, "receipt key not_before");
      normalized.signing_not_after = canonicalDate(jwk.signing_not_after, "receipt key signing_not_after");
      if (Date.parse(normalized.not_before) >= Date.parse(normalized.signing_not_after)) {
        throw new InvalidInputError("Receipt key signing interval must be non-empty");
      }
      if (jwk.revoked_at !== undefined) {
        normalized.revoked_at = canonicalDate(jwk.revoked_at, "receipt key revoked_at");
        if (
          Date.parse(normalized.revoked_at) < Date.parse(normalized.not_before)
          || Date.parse(normalized.revoked_at) > Date.parse(normalized.signing_not_after)
        ) throw new InvalidInputError("Receipt key revoked_at must fall within its signing interval");
      }
    }
    return Object.freeze(normalized);
  });
  if (new Set(keys.map(({ kid }) => kid)).size !== keys.length) throw new InvalidInputError("Receipt key IDs must be unique");
  return Object.freeze({ schema: GUARD_RECEIPT_KEYSET_SCHEMA, keys: Object.freeze(keys) });
}

export function verifyGuardAuthorizationEnvelope(envelope, { keyset, now = Date.now() } = {}) {
  exactKeys(envelope, new Set(["schema", "receipt", "evidence", "receipt_sha256", "signature"]), "authorization envelope");
  if (envelope.schema !== GUARD_AUTHORIZATION_ENVELOPE_SCHEMA) throw new ReceiptVerificationError("Authorization envelope schema is invalid");
  const receipt = normalizeReceipt(envelope.receipt);
  const evidence = normalizeEvidence(envelope.evidence, receipt.decision, receipt.reason_codes);
  if (canonicalSha256(evidence) !== receipt.evidence_sha256) throw new ReceiptVerificationError("Receipt evidence hash does not match evidence");
  if (!SHA256.test(envelope.receipt_sha256) || canonicalSha256(receipt) !== envelope.receipt_sha256) throw new ReceiptVerificationError("Receipt hash does not match receipt");
  if (!SIGNATURE.test(envelope.signature)) throw new ReceiptVerificationError("Receipt signature must be an Ed25519 base64url signature");
  const normalizedKeyset = normalizeReceiptKeyset({ receiptKeyset: keyset });
  const jwk = normalizedKeyset.keys.find((candidate) => candidate.kid === receipt.key_id);
  if (!jwk) throw new ReceiptVerificationError("Receipt signing key is not in the pinned keyset");
  let valid;
  try {
    const key = createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x }, format: "jwk" });
    const signingBytes = Buffer.concat([Buffer.from(GUARD_RECEIPT_SIGNING_DOMAIN), Buffer.from([0]), canonicalBytes(receipt)]);
    valid = verifyBytes(null, signingBytes, key, Buffer.from(envelope.signature, "base64url"));
  } catch (cause) {
    throw new ReceiptVerificationError("Receipt signing key or signature is invalid", { cause: cause.message });
  }
  if (!valid) throw new ReceiptVerificationError("Receipt signature is invalid");
  const issuedAt = Date.parse(receipt.issued_at);
  if (jwk.not_before !== undefined) {
    if (issuedAt < Date.parse(jwk.not_before)) throw new ReceiptVerificationError("Receipt predates its signing key validity interval");
    if (issuedAt >= Date.parse(jwk.signing_not_after)) throw new ReceiptVerificationError("Receipt was issued after its signing key was retired");
    if (jwk.revoked_at !== undefined && issuedAt >= Date.parse(jwk.revoked_at)) {
      throw new ReceiptVerificationError("Receipt was issued after its signing key was revoked");
    }
  }
  if (!Number.isSafeInteger(now) || issuedAt > now || Date.parse(receipt.expires_at) <= now) {
    throw new ReceiptVerificationError("Receipt is not currently valid");
  }
  return Object.freeze({ valid: true, receipt, evidence, receipt_sha256: envelope.receipt_sha256 });
}
