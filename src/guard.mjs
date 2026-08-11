import { canonicalize, hashCanonical } from "./canonical.mjs";
import { ServiceError, assert } from "./errors.mjs";
import { evaluateEvmTransaction, normalizeEvmTransaction } from "./evm-guard.mjs";
import { verifyGuardPolicy } from "./guard-policy.mjs";
import { validateBoundedJsonSchemaValue } from "./tools.mjs";

export const GUARD_REQUEST_SCHEMA = "goldkey.guard-request.v1";
export const GUARD_DECISION_SCHEMA = "goldkey.guard-decision.v1";
export const GUARD_REQUEST_SIGNING_DOMAIN = "GoldKey Guard Request v1";
export const GUARD_EVIDENCE_SCHEMA = "goldkey.guard-evidence.v1";
export const GUARD_COMMIT_SCHEMA = "goldkey.guard-commit.v1";
export const GUARD_COMPLETION_SCHEMA = "goldkey.guard-completion.v1";
export const GUARD_COMMIT_SIGNING_DOMAIN = "GoldKey Guard Commit v1";
export const GUARD_COMPLETION_SIGNING_DOMAIN = "GoldKey Guard Completion v1";

const ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const IDEMPOTENCY_PATTERN = /^[A-Za-z0-9._:-]{8,128}$/;
const TOOL_PATTERN = /^[A-Za-z0-9._:-]{1,256}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const INSTALLATION_SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;
const MAX_CALL_BYTES = 64 * 1024;
const DEFAULT_MAX_REQUEST_AGE_MS = 60_000;
const DEFAULT_MAX_FUTURE_SKEW_MS = 5_000;
const OUTCOME_STATUSES = new Set(["succeeded", "failed", "outcome_unknown"]);

function exactKeys(value, allowed, name) {
  assert(value && typeof value === "object" && !Array.isArray(value), 400, "invalid_guard_request", `${name} must be an object`);
  const extras = Object.keys(value).filter((key) => !allowed.has(key));
  assert(extras.length === 0, 400, "invalid_guard_request", `${name} contains unsupported fields`, { fields: extras.sort() });
}

function safeId(value, name, pattern = ID_PATTERN) {
  assert(typeof value === "string" && pattern.test(value), 400, "invalid_guard_request", `${name} is invalid`);
  return value;
}

function canonicalDate(value, name) {
  assert(typeof value === "string", 400, "invalid_guard_request", `${name} must be an ISO date-time`);
  const parsed = Date.parse(value);
  assert(Number.isFinite(parsed) && new Date(parsed).toISOString() === value, 400, "invalid_guard_request", `${name} must be a canonical ISO date-time`);
  return value;
}

function normalizeJsonValue(value, name) {
  try {
    return JSON.parse(canonicalize(value));
  } catch (cause) {
    if (cause instanceof ServiceError) throw cause;
    throw new ServiceError(400, "invalid_guard_request", `${name} must be a JSON value`, { cause: cause.message });
  }
}

function normalizeMcpCall(call) {
  exactKeys(call, new Set(["kind", "connector_id", "tool", "input_schema_sha256", "arguments"]), "mcp_tool call");
  assert(typeof call.input_schema_sha256 === "string" && SHA256_PATTERN.test(call.input_schema_sha256), 400, "invalid_guard_request", "call.input_schema_sha256 must be a lowercase SHA-256 digest");
  return {
    kind: "mcp_tool",
    connector_id: safeId(call.connector_id, "call.connector_id"),
    tool: safeId(call.tool, "call.tool", TOOL_PATTERN),
    input_schema_sha256: call.input_schema_sha256,
    arguments: normalizeJsonValue(call.arguments, "call.arguments"),
  };
}

function normalizeQuery(query) {
  assert(query && typeof query === "object" && !Array.isArray(query), 400, "invalid_guard_request", "call.query must be an object");
  const keys = Object.keys(query);
  assert(keys.length <= 100, 400, "invalid_guard_request", "call.query must contain at most 100 keys");
  const normalized = {};
  for (const key of keys.sort()) {
    assert(key.length >= 1 && key.length <= 256 && !/[\r\n\0]/.test(key), 400, "invalid_guard_request", "call.query contains an invalid key");
    const values = Array.isArray(query[key]) ? query[key] : [query[key]];
    assert(values.length >= 1 && values.length <= 20, 400, "invalid_guard_request", `call.query.${key} contains too many values`);
    assert(values.every((value) => typeof value === "string" && value.length <= 2048 && !/[\r\n\0]/.test(value)), 400, "invalid_guard_request", `call.query.${key} must contain bounded strings`);
    normalized[key] = Array.isArray(query[key]) ? [...values] : values[0];
  }
  return normalized;
}

function normalizeHttpsCall(call) {
  exactKeys(call, new Set(["kind", "connector_id", "operation_id", "query", "body"]), "https call");
  const normalized = {
    kind: "https",
    connector_id: safeId(call.connector_id, "call.connector_id"),
    operation_id: safeId(call.operation_id, "call.operation_id"),
  };
  if (call.query !== undefined) normalized.query = normalizeQuery(call.query);
  if (call.body !== undefined) normalized.body = normalizeJsonValue(call.body, "call.body");
  return normalized;
}

function normalizeEvmCall(call) {
  exactKeys(call, new Set(["kind", "connector_id", "transaction"]), "evm_transaction call");
  return {
    kind: "evm_transaction",
    connector_id: safeId(call.connector_id, "call.connector_id"),
    transaction: normalizeEvmTransaction(call.transaction),
  };
}

export function normalizeGuardCall(call) {
  assert(call && typeof call === "object" && !Array.isArray(call), 400, "invalid_guard_request", "call must be an object");
  let normalized;
  if (call.kind === "mcp_tool") normalized = normalizeMcpCall(call);
  else if (call.kind === "https") normalized = normalizeHttpsCall(call);
  else if (call.kind === "evm_transaction") normalized = normalizeEvmCall(call);
  else throw new ServiceError(400, "invalid_guard_request", "call.kind must be mcp_tool, https, or evm_transaction");
  const canonical = canonicalize(normalized);
  assert(Buffer.byteLength(canonical) <= MAX_CALL_BYTES, 413, "guard_call_too_large", `Canonical call exceeds ${MAX_CALL_BYTES} bytes`);
  return Object.freeze(JSON.parse(canonical));
}

function withoutSignature(request) {
  if (!request || typeof request !== "object" || Array.isArray(request)) return request;
  const { signature: _signature, ...unsigned } = request;
  return unsigned;
}

function normalizeUnsignedGuardRequest(request) {
  exactKeys(request, new Set(["schema", "installation_id", "idempotency_key", "issued_at", "call"]), "unsigned guard request");
  assert(request.schema === GUARD_REQUEST_SCHEMA, 400, "invalid_guard_request", `request.schema must be ${GUARD_REQUEST_SCHEMA}`);
  return Object.freeze({
    schema: GUARD_REQUEST_SCHEMA,
    installation_id: safeId(request.installation_id, "request.installation_id"),
    idempotency_key: safeId(request.idempotency_key, "request.idempotency_key", IDEMPOTENCY_PATTERN),
    issued_at: canonicalDate(request.issued_at, "request.issued_at"),
    call: normalizeGuardCall(request.call),
  });
}

export function validateGuardRequest(request) {
  exactKeys(request, new Set(["schema", "installation_id", "idempotency_key", "issued_at", "call", "signature"]), "guard request");
  assert(typeof request.signature === "string" && INSTALLATION_SIGNATURE_PATTERN.test(request.signature), 400, "invalid_guard_request_signature", "request.signature must be a base64url Ed25519 signature");
  return Object.freeze({ ...normalizeUnsignedGuardRequest(withoutSignature(request)), signature: request.signature });
}

export function hashGuardCall(call) {
  return hashCanonical(normalizeGuardCall(call)).sha256;
}

export function guardDecisionEvidence(decision) {
  assert(decision?.schema === GUARD_DECISION_SCHEMA, 400, "invalid_guard_decision", `decision.schema must be ${GUARD_DECISION_SCHEMA}`);
  const evidence = {
    schema: GUARD_EVIDENCE_SCHEMA,
    decision: decision.decision,
    reason_codes: decision.reason_codes,
    effect: decision.effect,
    destination: decision.destination,
  };
  if (decision.details !== undefined) evidence.details = decision.details;
  return Object.freeze(JSON.parse(canonicalize(evidence)));
}

export function guardRequestSigningMessage(request) {
  const normalized = normalizeUnsignedGuardRequest(withoutSignature(request));
  return `${GUARD_REQUEST_SIGNING_DOMAIN}\n${canonicalize(normalized)}`;
}

function normalizeLifecycleUnsigned(envelope, kind) {
  const completion = kind === "completion";
  const schema = completion ? GUARD_COMPLETION_SCHEMA : GUARD_COMMIT_SCHEMA;
  const allowed = new Set([
    "schema",
    "installation_id",
    "execution_id",
    "receipt_id",
    "receipt_sha256",
    "call_sha256",
    "issued_at",
    ...(completion ? ["outcome_status", "outcome_sha256"] : []),
  ]);
  exactKeys(envelope, allowed, `${kind} envelope`);
  assert(envelope.schema === schema, 400, "invalid_guard_lifecycle", `envelope.schema must be ${schema}`);
  assert(typeof envelope.receipt_sha256 === "string" && SHA256_PATTERN.test(envelope.receipt_sha256), 400, "invalid_guard_lifecycle", "receipt_sha256 must be a lowercase SHA-256 digest");
  assert(typeof envelope.call_sha256 === "string" && SHA256_PATTERN.test(envelope.call_sha256), 400, "invalid_guard_lifecycle", "call_sha256 must be a lowercase SHA-256 digest");
  const normalized = {
    schema,
    installation_id: safeId(envelope.installation_id, "installation_id"),
    execution_id: safeId(envelope.execution_id, "execution_id"),
    receipt_id: safeId(envelope.receipt_id, "receipt_id"),
    receipt_sha256: envelope.receipt_sha256,
    call_sha256: envelope.call_sha256,
    issued_at: canonicalDate(envelope.issued_at, "issued_at"),
  };
  if (completion) {
    assert(OUTCOME_STATUSES.has(envelope.outcome_status), 400, "invalid_guard_lifecycle", "outcome_status must be succeeded, failed, or outcome_unknown");
    assert(typeof envelope.outcome_sha256 === "string" && SHA256_PATTERN.test(envelope.outcome_sha256), 400, "invalid_guard_lifecycle", "outcome_sha256 must be a lowercase SHA-256 digest");
    normalized.outcome_status = envelope.outcome_status;
    normalized.outcome_sha256 = envelope.outcome_sha256;
  }
  return Object.freeze(normalized);
}

function normalizeLifecycleSigned(envelope, kind) {
  const allowed = new Set([
    "schema",
    "installation_id",
    "execution_id",
    "receipt_id",
    "receipt_sha256",
    "call_sha256",
    "issued_at",
    "signature",
    ...(kind === "completion" ? ["outcome_status", "outcome_sha256"] : []),
  ]);
  exactKeys(envelope, allowed, `${kind} envelope`);
  assert(typeof envelope.signature === "string" && INSTALLATION_SIGNATURE_PATTERN.test(envelope.signature), 400, "invalid_guard_lifecycle_signature", `${kind} signature must be a base64url Ed25519 signature`);
  return Object.freeze({ ...normalizeLifecycleUnsigned(withoutSignature(envelope), kind), signature: envelope.signature });
}

export function guardCommitSigningMessage(envelope) {
  return `${GUARD_COMMIT_SIGNING_DOMAIN}\n${canonicalize(normalizeLifecycleUnsigned(withoutSignature(envelope), "commit"))}`;
}

export function guardCompletionSigningMessage(envelope) {
  return `${GUARD_COMPLETION_SIGNING_DOMAIN}\n${canonicalize(normalizeLifecycleUnsigned(withoutSignature(envelope), "completion"))}`;
}

export function validateGuardCommit(envelope) {
  return normalizeLifecycleSigned(envelope, "commit");
}

export function validateGuardCompletion(envelope) {
  return normalizeLifecycleSigned(envelope, "completion");
}

async function verifyLifecycle(envelope, kind, { verifyInstallationSignature, now = Date.now(), maxAgeMs = 60_000, maxFutureSkewMs = 5_000 } = {}) {
  assert(typeof verifyInstallationSignature === "function", 500, "guard_installation_verifier_missing", "verifyInstallationSignature must be configured");
  assert(Number.isSafeInteger(now) && now >= 0 && Number.isSafeInteger(maxAgeMs) && maxAgeMs >= 1 && maxAgeMs <= 5 * 60_000 && Number.isSafeInteger(maxFutureSkewMs) && maxFutureSkewMs >= 0 && maxFutureSkewMs <= 60_000, 500, "guard_clock_invalid", "Lifecycle verification time bounds are invalid");
  const normalized = kind === "completion" ? validateGuardCompletion(envelope) : validateGuardCommit(envelope);
  const message = kind === "completion" ? guardCompletionSigningMessage(normalized) : guardCommitSigningMessage(normalized);
  let valid;
  try {
    valid = await verifyInstallationSignature({ installationId: normalized.installation_id, message, signature: normalized.signature });
  } catch (cause) {
    throw new ServiceError(503, "guard_installation_verification_unavailable", `Unable to verify installation ${kind} signature`, { cause: cause.message });
  }
  assert(valid, 401, "invalid_guard_lifecycle_signature", `Guard ${kind} signature does not match the installation`);
  const issuedAt = Date.parse(normalized.issued_at);
  assert(issuedAt <= now + maxFutureSkewMs && issuedAt >= now - maxAgeMs, 401, "guard_lifecycle_expired", `Guard ${kind} envelope is outside its accepted time window`);
  return normalized;
}

export function verifyGuardCommit(envelope, options) {
  return verifyLifecycle(envelope, "commit", options);
}

export function verifyGuardCompletion(envelope, options) {
  return verifyLifecycle(envelope, "completion", options);
}

function stableDecision({
  decision,
  reasons,
  request,
  verifiedPolicy,
  effect = null,
  destination = null,
  details,
}) {
  const reasonCodes = [...new Set(reasons)].sort();
  return Object.freeze({
    schema: GUARD_DECISION_SCHEMA,
    installation_id: request.installation_id,
    idempotency_key: request.idempotency_key,
    policy_id: verifiedPolicy.policy.policy_id,
    policy_version: verifiedPolicy.policy.version,
    policy_sha256: verifiedPolicy.policy_sha256,
    call_sha256: hashGuardCall(request.call),
    decision,
    reason_codes: Object.freeze(reasonCodes),
    effect,
    destination,
    ...(details === undefined ? {} : { details }),
  });
}

function blocked(request, verifiedPolicy, reason, { effect = null, destination = null, details } = {}) {
  return stableDecision({ decision: "BLOCK", reasons: [reason], request, verifiedPolicy, effect, destination, details });
}

function evaluateMcp(request, connector, verifiedPolicy) {
  const tool = connector.tools.find((candidate) => candidate.name === request.call.tool);
  if (!tool) return blocked(request, verifiedPolicy, "mcp_tool_not_allowed", { destination: `mcp://${connector.server_id}/${request.call.tool}` });
  const destination = `mcp://${connector.server_id}/${tool.name}`;
  if (tool.input_schema_sha256 !== request.call.input_schema_sha256) {
    return blocked(request, verifiedPolicy, "mcp_tool_schema_changed", { effect: tool.effect, destination });
  }
  if (tool.arguments_schema !== undefined && !validateBoundedJsonSchemaValue(request.call.arguments, tool.arguments_schema).valid) {
    return blocked(request, verifiedPolicy, "mcp_arguments_policy_mismatch", { effect: tool.effect, destination });
  }
  return stableDecision({ decision: "ALLOW", reasons: [], request, verifiedPolicy, effect: tool.effect, destination });
}

function evaluateHttps(request, connector, verifiedPolicy) {
  const operation = connector.operations.find((candidate) => candidate.id === request.call.operation_id);
  if (!operation) return blocked(request, verifiedPolicy, "https_operation_not_allowed", { destination: connector.origin });
  const reasons = [];
  if (
    operation.query_schema !== undefined &&
    (!Object.hasOwn(request.call, "query") || !validateBoundedJsonSchemaValue(request.call.query, operation.query_schema).valid)
  ) {
    reasons.push("https_query_policy_mismatch");
  }
  if (
    operation.body_schema !== undefined &&
    (!Object.hasOwn(request.call, "body") || !validateBoundedJsonSchemaValue(request.call.body, operation.body_schema).valid)
  ) {
    reasons.push("https_body_policy_mismatch");
  }
  return stableDecision({
    decision: reasons.length === 0 ? "ALLOW" : "BLOCK",
    reasons,
    request,
    verifiedPolicy,
    effect: operation.effect,
    destination: `${connector.origin}${operation.path}`,
    details: Object.freeze({ method: operation.method, operation_id: operation.id }),
  });
}

function evaluateEvm(request, connector, verifiedPolicy, simulation) {
  const result = evaluateEvmTransaction({ transaction: request.call.transaction, connector, simulation });
  const details = {
    transaction_sha256: result.transaction_sha256,
    decoded: result.decoded,
  };
  if (result.reservation !== undefined) details.reservation = result.reservation;
  if (result.fee_reservation !== undefined) details.fee_reservation = result.fee_reservation;
  if (result.nonce_reservation !== undefined) details.nonce_reservation = result.nonce_reservation;
  if (result.simulation !== undefined) details.simulation = result.simulation;
  return stableDecision({
    decision: result.decision,
    reasons: result.reason_codes,
    request,
    verifiedPolicy,
    effect: result.effect,
    destination: result.destination,
    details: Object.freeze(details),
  });
}

export async function evaluateGuardRequest({
  request: rawRequest,
  policy: rawPolicy,
  audience,
  verifyWalletMessage,
  verifyInstallationSignature,
  simulation,
  now = Date.now(),
  maxRequestAgeMs = DEFAULT_MAX_REQUEST_AGE_MS,
  maxFutureSkewMs = DEFAULT_MAX_FUTURE_SKEW_MS,
} = {}) {
  const request = validateGuardRequest(rawRequest);
  assert(typeof verifyInstallationSignature === "function", 500, "guard_installation_verifier_missing", "verifyInstallationSignature must be configured");
  assert(Number.isSafeInteger(now) && now >= 0, 500, "guard_clock_invalid", "Guard evaluation time is invalid");
  assert(Number.isSafeInteger(maxRequestAgeMs) && maxRequestAgeMs >= 1 && maxRequestAgeMs <= 5 * 60_000, 500, "guard_clock_invalid", "maxRequestAgeMs is invalid");
  assert(Number.isSafeInteger(maxFutureSkewMs) && maxFutureSkewMs >= 0 && maxFutureSkewMs <= 60_000, 500, "guard_clock_invalid", "maxFutureSkewMs is invalid");

  const verifiedPolicy = await verifyGuardPolicy(rawPolicy, { verifyWalletMessage });
  let expectedAudience;
  try {
    expectedAudience = new URL(audience).origin;
  } catch {
    throw new ServiceError(500, "guard_audience_invalid", "Guard audience must be configured as an absolute origin");
  }
  assert(expectedAudience === audience && verifiedPolicy.policy.audience === expectedAudience, 403, "guard_policy_audience_mismatch", "Guard policy is signed for a different service audience");

  const message = guardRequestSigningMessage(request);
  let signatureValid;
  try {
    signatureValid = await verifyInstallationSignature({
      installationId: request.installation_id,
      message,
      signature: request.signature,
    });
  } catch (cause) {
    throw new ServiceError(503, "guard_installation_verification_unavailable", "Unable to verify installation request signature", { cause: cause.message });
  }
  assert(signatureValid, 401, "invalid_guard_request_signature", "Guard request signature does not match the installation");

  const issuedAt = Date.parse(request.issued_at);
  if (issuedAt > now + maxFutureSkewMs) return blocked(request, verifiedPolicy, "request_issued_in_future");
  if (issuedAt < now - maxRequestAgeMs) return blocked(request, verifiedPolicy, "request_expired");
  if (Date.parse(verifiedPolicy.policy.issued_at) > now) return blocked(request, verifiedPolicy, "policy_not_yet_active");
  if (Date.parse(verifiedPolicy.policy.expires_at) <= now) return blocked(request, verifiedPolicy, "policy_expired");

  const connector = verifiedPolicy.policy.connectors.find(({ id }) => id === request.call.connector_id);
  if (!connector) return blocked(request, verifiedPolicy, "connector_not_allowed");
  if (connector.kind !== request.call.kind) return blocked(request, verifiedPolicy, "connector_kind_mismatch");

  if (connector.kind === "mcp_tool") return evaluateMcp(request, connector, verifiedPolicy);
  if (connector.kind === "https") return evaluateHttps(request, connector, verifiedPolicy);
  return evaluateEvm(request, connector, verifiedPolicy, simulation);
}
