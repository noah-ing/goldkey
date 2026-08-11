import {
  createPrivateKey,
  createPublicKey,
  randomUUID,
  sign as signBytes,
  verify as verifyBytes,
} from "node:crypto";
import { canonicalize, sha256 } from "./canonical.mjs";
import { ServiceError, assert } from "./errors.mjs";

export const GUARD_AUTHORIZATION_RECEIPT_SCHEMA = "goldkey.guard-authorization-receipt.v1";
export const GUARD_AUTHORIZATION_ENVELOPE_SCHEMA = "goldkey.guard-authorization-envelope.v1";
export const GUARD_RECEIPT_KEYSET_SCHEMA = "goldkey.guard-receipt-keyset.v1";
export const GUARD_RECEIPT_EVIDENCE_SCHEMA = "goldkey.guard-evidence.v1";
export const GUARD_RECEIPT_SIGNING_DOMAIN = "GoldKey Guard Authorization Receipt v1";

const ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;
const REASON_PATTERN = /^[a-z0-9._:-]{1,128}$/;
const IDEMPOTENCY_PATTERN = /^[A-Za-z0-9._:-]{8,128}$/;
const KINDS = new Set(["mcp_tool", "https", "evm_transaction"]);
const EFFECTS = new Set(["read", "write", "network", "payment", "execute"]);
const DECISIONS = new Set(["ALLOW", "REVIEW", "BLOCK"]);
const DEFAULT_TTL_MS = 30_000;
const MAX_TTL_MS = 5 * 60_000;
const MAX_EVIDENCE_BYTES = 32 * 1024;

function exactKeys(value, allowed, name, code = "invalid_guard_receipt") {
  assert(value && typeof value === "object" && !Array.isArray(value), 400, code, `${name} must be an object`);
  const extras = Object.keys(value).filter((key) => !allowed.has(key));
  assert(extras.length === 0, 400, code, `${name} contains unsupported fields`, { fields: extras.sort() });
}

function safeId(value, name, pattern = ID_PATTERN) {
  assert(typeof value === "string" && pattern.test(value), 400, "invalid_guard_receipt", `${name} is invalid`);
  return value;
}

function digest(value, name) {
  assert(typeof value === "string" && SHA256_PATTERN.test(value), 400, "invalid_guard_receipt", `${name} must be a lowercase SHA-256 digest`);
  return value;
}

function canonicalDate(value, name) {
  assert(typeof value === "string", 400, "invalid_guard_receipt", `${name} must be an ISO date-time`);
  const parsed = Date.parse(value);
  assert(Number.isFinite(parsed) && new Date(parsed).toISOString() === value, 400, "invalid_guard_receipt", `${name} must be a canonical ISO date-time`);
  return value;
}

function stableReasons(reasonCodes) {
  assert(Array.isArray(reasonCodes) && reasonCodes.length <= 100, 400, "invalid_guard_receipt", "reason_codes must contain at most 100 entries");
  assert(reasonCodes.every((reason) => typeof reason === "string" && REASON_PATTERN.test(reason)), 400, "invalid_guard_receipt", "reason_codes contains an invalid reason code");
  return [...new Set(reasonCodes)].sort();
}

function normalizeEvidence(evidence, decision, reasonCodes) {
  exactKeys(evidence, new Set(["schema", "decision", "reason_codes", "effect", "destination", "details"]), "guard evidence");
  assert(evidence.schema === GUARD_RECEIPT_EVIDENCE_SCHEMA, 400, "invalid_guard_receipt", `evidence.schema must be ${GUARD_RECEIPT_EVIDENCE_SCHEMA}`);
  assert(evidence.decision === decision, 400, "invalid_guard_receipt", "evidence.decision must match receipt decision");
  const normalizedReasons = stableReasons(evidence.reason_codes);
  assert(canonicalize(normalizedReasons) === canonicalize(reasonCodes), 400, "invalid_guard_receipt", "evidence.reason_codes must match receipt reason_codes");
  assert(evidence.effect === null || EFFECTS.has(evidence.effect), 400, "invalid_guard_receipt", "evidence.effect is invalid");
  assert(evidence.destination === null || (typeof evidence.destination === "string" && evidence.destination.length >= 1 && evidence.destination.length <= 2048 && !/[\r\n\0]/.test(evidence.destination)), 400, "invalid_guard_receipt", "evidence.destination is invalid");
  const normalized = {
    schema: GUARD_RECEIPT_EVIDENCE_SCHEMA,
    decision,
    reason_codes: normalizedReasons,
    effect: evidence.effect,
    destination: evidence.destination,
  };
  if (evidence.details !== undefined) {
    assert(evidence.details && typeof evidence.details === "object" && !Array.isArray(evidence.details), 400, "invalid_guard_receipt", "evidence.details must be an object");
    normalized.details = JSON.parse(canonicalize(evidence.details));
  }
  const canonical = canonicalize(normalized);
  assert(Buffer.byteLength(canonical) <= MAX_EVIDENCE_BYTES, 413, "guard_receipt_evidence_too_large", `Guard evidence exceeds ${MAX_EVIDENCE_BYTES} bytes`);
  return Object.freeze(JSON.parse(canonical));
}

function signingBytes(receipt) {
  return Buffer.concat([
    Buffer.from(GUARD_RECEIPT_SIGNING_DOMAIN, "utf8"),
    Buffer.from([0]),
    Buffer.from(canonicalize(receipt), "utf8"),
  ]);
}

function normalizeReceipt(receipt) {
  exactKeys(receipt, new Set([
    "schema",
    "receipt_id",
    "key_id",
    "installation_id",
    "idempotency_key",
    "connector_id",
    "kind",
    "policy_id",
    "policy_version",
    "policy_sha256",
    "call_sha256",
    "evidence_sha256",
    "decision",
    "reason_codes",
    "issued_at",
    "expires_at",
  ]), "authorization receipt");
  assert(receipt.schema === GUARD_AUTHORIZATION_RECEIPT_SCHEMA, 400, "invalid_guard_receipt", `receipt.schema must be ${GUARD_AUTHORIZATION_RECEIPT_SCHEMA}`);
  assert(Number.isSafeInteger(receipt.policy_version) && receipt.policy_version >= 1, 400, "invalid_guard_receipt", "receipt.policy_version must be a positive safe integer");
  assert(KINDS.has(receipt.kind), 400, "invalid_guard_receipt", "receipt.kind is invalid");
  assert(DECISIONS.has(receipt.decision), 400, "invalid_guard_receipt", "receipt.decision is invalid");
  const issuedAt = canonicalDate(receipt.issued_at, "receipt.issued_at");
  const expiresAt = canonicalDate(receipt.expires_at, "receipt.expires_at");
  const lifetime = Date.parse(expiresAt) - Date.parse(issuedAt);
  assert(lifetime >= 1 && lifetime <= MAX_TTL_MS, 400, "invalid_guard_receipt", `receipt lifetime must be 1-${MAX_TTL_MS} milliseconds`);
  return Object.freeze({
    schema: GUARD_AUTHORIZATION_RECEIPT_SCHEMA,
    receipt_id: safeId(receipt.receipt_id, "receipt.receipt_id"),
    key_id: safeId(receipt.key_id, "receipt.key_id"),
    installation_id: safeId(receipt.installation_id, "receipt.installation_id"),
    idempotency_key: safeId(receipt.idempotency_key, "receipt.idempotency_key", IDEMPOTENCY_PATTERN),
    connector_id: safeId(receipt.connector_id, "receipt.connector_id"),
    kind: receipt.kind,
    policy_id: safeId(receipt.policy_id, "receipt.policy_id"),
    policy_version: receipt.policy_version,
    policy_sha256: digest(receipt.policy_sha256, "receipt.policy_sha256"),
    call_sha256: digest(receipt.call_sha256, "receipt.call_sha256"),
    evidence_sha256: digest(receipt.evidence_sha256, "receipt.evidence_sha256"),
    decision: receipt.decision,
    reason_codes: Object.freeze(stableReasons(receipt.reason_codes)),
    issued_at: issuedAt,
    expires_at: expiresAt,
  });
}

function importPrivateKey(privateKeyPkcs8Base64) {
  assert(typeof privateKeyPkcs8Base64 === "string" && privateKeyPkcs8Base64.length >= 40 && /^[A-Za-z0-9+/]+={0,2}$/.test(privateKeyPkcs8Base64), 500, "guard_receipt_key_invalid", "Receipt signing key must be base64 PKCS8 DER");
  let key;
  try {
    key = createPrivateKey({ key: Buffer.from(privateKeyPkcs8Base64, "base64"), format: "der", type: "pkcs8" });
  } catch (cause) {
    throw new ServiceError(500, "guard_receipt_key_invalid", "Receipt signing key is not valid PKCS8 DER", { cause: cause.message });
  }
  assert(key.asymmetricKeyType === "ed25519", 500, "guard_receipt_key_invalid", "Receipt signing key must be Ed25519");
  return key;
}

function publicJwk(privateKey, keyId) {
  const exported = createPublicKey(privateKey).export({ format: "jwk" });
  return Object.freeze({
    kty: exported.kty,
    crv: exported.crv,
    x: exported.x,
    kid: keyId,
    use: "sig",
    alg: "EdDSA",
    key_ops: Object.freeze(["verify"]),
  });
}

function keysetDate(value, name) {
  assert(typeof value === "string", 400, "invalid_guard_keyset", `${name} must be an ISO date-time`);
  const parsed = Date.parse(value);
  assert(Number.isFinite(parsed) && new Date(parsed).toISOString() === value, 400, "invalid_guard_keyset", `${name} must be a canonical ISO date-time`);
  return value;
}

function normalizePublicJwk(value, index, { requireBoundedSigningWindow = false } = {}) {
  const name = `keyset.keys[${index}]`;
  exactKeys(value, new Set([
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
  ]), name, "invalid_guard_keyset");
  assert(value.kty === "OKP" && value.crv === "Ed25519" && typeof value.x === "string" && /^[A-Za-z0-9_-]{43}$/.test(value.x), 400, "invalid_guard_keyset", `${name} must be a public Ed25519 JWK`);
  const kid = safeId(value.kid, `${name}.kid`);
  if (value.use !== undefined) assert(value.use === "sig", 400, "invalid_guard_keyset", `${name}.use must be sig`);
  if (value.alg !== undefined) assert(value.alg === "EdDSA", 400, "invalid_guard_keyset", `${name}.alg must be EdDSA`);
  if (value.key_ops !== undefined) assert(Array.isArray(value.key_ops) && value.key_ops.length === 1 && value.key_ops[0] === "verify", 400, "invalid_guard_keyset", `${name}.key_ops must contain only verify`);

  const hasNotBefore = value.not_before !== undefined;
  const hasSigningNotAfter = value.signing_not_after !== undefined;
  assert(hasNotBefore === hasSigningNotAfter, 400, "invalid_guard_keyset", `${name} must provide not_before and signing_not_after together`);
  assert(!requireBoundedSigningWindow || (hasNotBefore && hasSigningNotAfter), 400, "invalid_guard_keyset", `${name} is a retained key and must have a bounded signing interval`);
  assert(value.revoked_at === undefined || hasNotBefore, 400, "invalid_guard_keyset", `${name}.revoked_at requires a bounded signing interval`);

  const normalized = {
    kty: "OKP",
    crv: "Ed25519",
    x: value.x,
    kid,
    use: "sig",
    alg: "EdDSA",
    key_ops: Object.freeze(["verify"]),
  };
  if (hasNotBefore) {
    normalized.not_before = keysetDate(value.not_before, `${name}.not_before`);
    normalized.signing_not_after = keysetDate(value.signing_not_after, `${name}.signing_not_after`);
    assert(Date.parse(normalized.not_before) < Date.parse(normalized.signing_not_after), 400, "invalid_guard_keyset", `${name} signing interval must be non-empty`);
    if (value.revoked_at !== undefined) {
      normalized.revoked_at = keysetDate(value.revoked_at, `${name}.revoked_at`);
      assert(Date.parse(normalized.revoked_at) >= Date.parse(normalized.not_before), 400, "invalid_guard_keyset", `${name}.revoked_at must not precede not_before`);
      assert(Date.parse(normalized.revoked_at) <= Date.parse(normalized.signing_not_after), 400, "invalid_guard_keyset", `${name}.revoked_at must not follow signing_not_after`);
    }
  }
  return Object.freeze(normalized);
}

function normalizeKeyset(keyset) {
  exactKeys(keyset, new Set(["schema", "keys"]), "receipt keyset", "invalid_guard_keyset");
  assert(keyset.schema === GUARD_RECEIPT_KEYSET_SCHEMA, 400, "invalid_guard_keyset", `keyset.schema must be ${GUARD_RECEIPT_KEYSET_SCHEMA}`);
  assert(Array.isArray(keyset.keys) && keyset.keys.length >= 1 && keyset.keys.length <= 32, 400, "invalid_guard_keyset", "keyset.keys must contain 1-32 keys");
  // Key zero is the active signer. Every retained key must be bounded so that
  // possession of an old private key cannot mint fresh, apparently valid receipts.
  // Receipts issued before retirement remain verifiable until their own (bounded)
  // receipt TTL expires.
  const keys = keyset.keys.map((key, index) => normalizePublicJwk(key, index, {
    requireBoundedSigningWindow: index > 0,
  }));
  assert(new Set(keys.map(({ kid }) => kid)).size === keys.length, 400, "invalid_guard_keyset", "keyset key IDs must be distinct");
  return Object.freeze({ schema: GUARD_RECEIPT_KEYSET_SCHEMA, keys: Object.freeze(keys) });
}

export function createGuardReceiptSigner({
  privateKeyPkcs8Base64,
  keyId,
  clock = () => Date.now(),
  idGenerator = () => randomUUID(),
  previousPublicKeys = [],
} = {}) {
  safeId(keyId, "keyId");
  assert(typeof clock === "function", 500, "guard_receipt_clock_invalid", "Receipt clock must be a function");
  assert(typeof idGenerator === "function", 500, "guard_receipt_id_generator_invalid", "Receipt ID generator must be a function");
  assert(Array.isArray(previousPublicKeys) && previousPublicKeys.length <= 31, 500, "invalid_guard_keyset", "previousPublicKeys must contain at most 31 public keys");
  const privateKey = importPrivateKey(privateKeyPkcs8Base64);
  const jwk = publicJwk(privateKey, keyId);
  const previous = previousPublicKeys.map((key, index) => normalizePublicJwk(key, index + 1, {
    requireBoundedSigningWindow: true,
  }));
  const keyIds = [keyId, ...previous.map(({ kid }) => kid)];
  assert(new Set(keyIds).size === keyIds.length, 500, "invalid_guard_keyset", "Current and previous receipt key IDs must be distinct");
  const keyset = Object.freeze({ schema: GUARD_RECEIPT_KEYSET_SCHEMA, keys: Object.freeze([jwk, ...previous]) });

  function signAuthorization({
    installation_id: installationId,
    idempotency_key: idempotencyKey,
    connector_id: connectorId,
    kind,
    policy_id: policyId,
    policy_version: policyVersion,
    policy_sha256: policySha256,
    call_sha256: callSha256,
    decision,
    reason_codes: reasonCodes = [],
    evidence,
    ttl_ms: ttlMs = DEFAULT_TTL_MS,
  } = {}) {
    assert(Number.isSafeInteger(ttlMs) && ttlMs >= 1 && ttlMs <= MAX_TTL_MS, 400, "invalid_guard_receipt_ttl", `ttl_ms must be 1-${MAX_TTL_MS}`);
    const issuedAtMs = clock();
    assert(Number.isSafeInteger(issuedAtMs) && issuedAtMs >= 0, 500, "guard_receipt_clock_invalid", "Receipt clock returned an invalid time");
    assert(KINDS.has(kind), 400, "invalid_guard_receipt", "kind is invalid");
    const normalizedReasons = stableReasons(reasonCodes);
    const normalizedEvidence = normalizeEvidence(evidence, decision, normalizedReasons);
    const evidenceSha256 = sha256(canonicalize(normalizedEvidence));
    const receipt = normalizeReceipt({
      schema: GUARD_AUTHORIZATION_RECEIPT_SCHEMA,
      receipt_id: idGenerator(),
      key_id: keyId,
      installation_id: installationId,
      idempotency_key: idempotencyKey,
      connector_id: connectorId,
      kind,
      policy_id: policyId,
      policy_version: policyVersion,
      policy_sha256: policySha256,
      call_sha256: callSha256,
      evidence_sha256: evidenceSha256,
      decision,
      reason_codes: normalizedReasons,
      issued_at: new Date(issuedAtMs).toISOString(),
      expires_at: new Date(issuedAtMs + ttlMs).toISOString(),
    });
    const receiptSha256 = sha256(canonicalize(receipt));
    const signature = signBytes(null, signingBytes(receipt), privateKey).toString("base64url");
    return Object.freeze({
      schema: GUARD_AUTHORIZATION_ENVELOPE_SCHEMA,
      receipt,
      evidence: normalizedEvidence,
      receipt_sha256: receiptSha256,
      signature,
    });
  }

  return Object.freeze({
    keyId,
    publicKeyJwk: jwk,
    keyset,
    signAuthorization,
  });
}

export function verifyGuardAuthorizationReceipt(envelope, { keyset, now = Date.now() } = {}) {
  exactKeys(envelope, new Set(["schema", "receipt", "evidence", "receipt_sha256", "signature"]), "authorization envelope");
  assert(envelope.schema === GUARD_AUTHORIZATION_ENVELOPE_SCHEMA, 400, "invalid_guard_receipt", `envelope.schema must be ${GUARD_AUTHORIZATION_ENVELOPE_SCHEMA}`);
  const receipt = normalizeReceipt(envelope.receipt);
  const evidence = normalizeEvidence(envelope.evidence, receipt.decision, receipt.reason_codes);
  assert(sha256(canonicalize(evidence)) === receipt.evidence_sha256, 400, "guard_receipt_evidence_mismatch", "Receipt evidence hash does not match its canonical evidence");
  assert(typeof envelope.receipt_sha256 === "string" && SHA256_PATTERN.test(envelope.receipt_sha256), 400, "invalid_guard_receipt", "envelope.receipt_sha256 is invalid");
  assert(sha256(canonicalize(receipt)) === envelope.receipt_sha256, 400, "guard_receipt_hash_mismatch", "Receipt hash does not match its canonical payload");
  assert(typeof envelope.signature === "string" && SIGNATURE_PATTERN.test(envelope.signature), 400, "invalid_guard_receipt", "Receipt signature must be an Ed25519 base64url signature");
  const normalizedKeyset = normalizeKeyset(keyset);
  const jwk = normalizedKeyset.keys.find((candidate) => candidate?.kid === receipt.key_id);
  assert(jwk && jwk.kty === "OKP" && jwk.crv === "Ed25519" && typeof jwk.x === "string", 401, "guard_receipt_key_unknown", "Receipt signing key is not present in the supplied keyset");
  let publicKey;
  try {
    publicKey = createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x }, format: "jwk" });
  } catch (cause) {
    throw new ServiceError(400, "invalid_guard_keyset", "Receipt keyset contains an invalid Ed25519 key", { cause: cause.message });
  }
  const valid = verifyBytes(null, signingBytes(receipt), publicKey, Buffer.from(envelope.signature, "base64url"));
  assert(valid, 401, "invalid_guard_receipt_signature", "Receipt signature is invalid");
  const issuedAtMs = Date.parse(receipt.issued_at);
  if (jwk.not_before !== undefined) {
    assert(issuedAtMs >= Date.parse(jwk.not_before), 401, "guard_receipt_key_not_yet_valid", "Receipt was issued before its signing key became valid");
    assert(issuedAtMs < Date.parse(jwk.signing_not_after), 401, "guard_receipt_key_retired", "Receipt was issued after its signing key was retired");
    if (jwk.revoked_at !== undefined) {
      assert(issuedAtMs < Date.parse(jwk.revoked_at), 401, "guard_receipt_key_revoked", "Receipt was issued after its signing key was revoked");
    }
  }
  assert(Number.isSafeInteger(now) && now >= 0, 500, "guard_receipt_clock_invalid", "Verification time is invalid");
  assert(issuedAtMs <= now, 401, "guard_receipt_not_yet_valid", "Receipt is not yet valid");
  assert(Date.parse(receipt.expires_at) > now, 401, "guard_receipt_expired", "Receipt has expired");
  return Object.freeze({ valid: true, receipt, evidence, receipt_sha256: envelope.receipt_sha256 });
}
