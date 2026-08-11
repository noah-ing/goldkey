import { canonicalBytes } from "./canonical.mjs";
import {
  AuthorizationServiceError,
  InvalidInputError,
  ResponseLimitError,
} from "./errors.mjs";
import {
  GUARD_COMMIT_SCHEMA,
  GUARD_COMPLETION_SCHEMA,
} from "./protocol.mjs";

const MAX_ACK_BYTES = 64 * 1024;
const MAX_PAYMENT_PROOF_BYTES = 64 * 1024;
const IDENTIFIER = /^[A-Za-z0-9._:-]{1,128}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const TRANSACTION_HASH = /^0x[0-9a-f]{64}$/;
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const OUTCOME_STATUSES = new Set(["succeeded", "failed", "outcome_unknown"]);
const GUARD_KINDS = new Set(["mcp_tool", "https", "evm_transaction"]);
const BASE_NETWORK = "eip155:8453";
const BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const NETWORK_PRICE = "50000";
const EVM_PRICE = "100000";
const RECONCILED_COMMIT_SCHEMA = "goldkey.guard-reconciled-commit.v1";

function serviceOrigin(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new InvalidInputError("serviceOrigin must be an absolute HTTPS origin");
  }
  if (
    parsed.protocol !== "https:"
    || parsed.username
    || parsed.password
    || parsed.search
    || parsed.hash
    || parsed.pathname !== "/"
    || value !== parsed.origin
  ) {
    throw new InvalidInputError("serviceOrigin must be exactly one credential-free HTTPS origin");
  }
  return parsed.origin;
}

function lifecycleEndpoint(origin, executionId, action) {
  if (typeof executionId !== "string" || !IDENTIFIER.test(executionId)) {
    throw new InvalidInputError("Lifecycle execution_id is invalid");
  }
  return `${origin}/v1/guard/executions/${encodeURIComponent(executionId)}/${action}`;
}

function exactObject(value, allowed, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new InvalidInputError(`${name} must be an object`);
  const extras = Object.keys(value).filter((key) => !allowed.has(key));
  if (extras.length > 0) throw new InvalidInputError(`${name} contains unsupported fields`, { fields: extras.sort() });
  return value;
}

function normalizePaymentProof(value, { origin, kind }) {
  const proof = exactObject(value, new Set(["transaction", "payment_payload"]), "paymentProof");
  if (typeof proof.transaction !== "string" || !TRANSACTION_HASH.test(proof.transaction)) {
    throw new InvalidInputError("paymentProof.transaction must be one canonical lowercase Base transaction hash");
  }
  const payload = exactObject(proof.payment_payload, new Set(["x402Version", "resource", "accepted", "payload", "extensions"]), "paymentProof.payment_payload");
  const bytes = canonicalBytes(payload);
  if (bytes.byteLength > MAX_PAYMENT_PROOF_BYTES) throw new ResponseLimitError("Guard payment proof exceeds 64 KiB");
  const route = kind === "evm_transaction" ? "evm" : "network";
  const expectedAmount = kind === "evm_transaction" ? EVM_PRICE : NETWORK_PRICE;
  const expectedResource = `${origin}/v1/guard/paygo/authorize/${route}`;
  if (payload.x402Version !== 2 || payload.resource?.url !== expectedResource) {
    throw new InvalidInputError("paymentProof is not bound to the exact Guard authorization resource");
  }
  const accepted = exactObject(payload.accepted, new Set(["scheme", "network", "amount", "asset", "payTo", "maxTimeoutSeconds", "extra"]), "paymentProof.payment_payload.accepted");
  if (
    accepted.scheme !== "exact"
    || accepted.network !== BASE_NETWORK
    || accepted.amount !== expectedAmount
    || typeof accepted.asset !== "string"
    || accepted.asset.toLowerCase() !== BASE_USDC.toLowerCase()
    || typeof accepted.payTo !== "string"
    || !EVM_ADDRESS.test(accepted.payTo)
    || !Number.isSafeInteger(accepted.maxTimeoutSeconds)
    || accepted.maxTimeoutSeconds < 1
    || accepted.maxTimeoutSeconds > 30
  ) throw new InvalidInputError("paymentProof does not contain the exact bounded Base-USDC payment requirements");
  const extra = exactObject(accepted.extra, new Set(["name", "version", "assetTransferMethod"]), "paymentProof.payment_payload.accepted.extra");
  if (extra.name !== "USD Coin" || extra.version !== "2" || (extra.assetTransferMethod !== undefined && extra.assetTransferMethod !== "eip3009")) {
    throw new InvalidInputError("paymentProof does not use canonical USDC EIP-3009 parameters");
  }
  exactObject(payload.payload, new Set(Object.keys(payload.payload ?? {})), "paymentProof.payment_payload.payload");
  if (payload.extensions !== undefined) exactObject(payload.extensions, new Set(Object.keys(payload.extensions ?? {})), "paymentProof.payment_payload.extensions");
  return proof;
}

async function boundedAck(response) {
  const declared = response.headers?.get?.("content-length");
  if (declared !== null && declared !== undefined && declared !== "") {
    const length = Number(declared);
    if (!Number.isSafeInteger(length) || length < 0 || length > MAX_ACK_BYTES) {
      throw new ResponseLimitError("Guard lifecycle response exceeds 64 KiB");
    }
  }
  const reader = response.body?.getReader?.();
  let bytes;
  if (reader) {
    const chunks = [];
    let length = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = Buffer.from(value);
        length += chunk.byteLength;
        if (length > MAX_ACK_BYTES) {
          await reader.cancel().catch(() => {});
          throw new ResponseLimitError("Guard lifecycle response exceeds 64 KiB");
        }
        chunks.push(chunk);
      }
    } finally {
      reader.releaseLock?.();
    }
    bytes = Buffer.concat(chunks, length);
  } else {
    bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.byteLength > MAX_ACK_BYTES) throw new ResponseLimitError("Guard lifecycle response exceeds 64 KiB");
  }
  if (bytes.byteLength === 0) {
    throw new AuthorizationServiceError("Guard lifecycle endpoint returned an empty acknowledgment");
  }
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new AuthorizationServiceError("Guard lifecycle endpoint returned invalid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new AuthorizationServiceError("Guard lifecycle acknowledgment must be a JSON object");
  }
  return Object.freeze(parsed);
}

function binding(envelope, context, kind) {
  const receipt = context?.receipt;
  const completion = kind === "completion";
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new InvalidInputError(`Guard ${kind} envelope must be an object`);
  }
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) {
    throw new InvalidInputError(`Guard ${kind} requires the verified authorization receipt in context.receipt`);
  }
  if (
    envelope.schema !== (completion ? GUARD_COMPLETION_SCHEMA : GUARD_COMMIT_SCHEMA)
    || typeof envelope.signature !== "string"
    || !SIGNATURE.test(envelope.signature)
    || typeof envelope.execution_id !== "string"
    || !IDENTIFIER.test(envelope.execution_id)
    || envelope.execution_id !== envelope.receipt_id
    || envelope.execution_id !== receipt.receipt_id
    || typeof envelope.installation_id !== "string"
    || !IDENTIFIER.test(envelope.installation_id)
    || envelope.installation_id !== receipt.installation_id
    || typeof envelope.call_sha256 !== "string"
    || !SHA256.test(envelope.call_sha256)
    || envelope.call_sha256 !== receipt.call_sha256
    || typeof envelope.receipt_sha256 !== "string"
    || !SHA256.test(envelope.receipt_sha256)
    || !canonicalDate(envelope.issued_at)
    || typeof receipt.policy_sha256 !== "string"
    || !SHA256.test(receipt.policy_sha256)
    || !GUARD_KINDS.has(receipt.kind)
    || receipt.decision !== "ALLOW"
    || (completion && (!OUTCOME_STATUSES.has(envelope.outcome_status) || !SHA256.test(envelope.outcome_sha256)))
  ) {
    throw new InvalidInputError(`Guard ${kind} envelope is not bound to one verified ALLOW authorization`);
  }
  return Object.freeze({
    executionId: envelope.execution_id,
    installationId: envelope.installation_id,
    callSha256: envelope.call_sha256,
    policySha256: receipt.policy_sha256,
    kind: receipt.kind,
    ...(kind === "completion" ? {
      outcomeStatus: envelope.outcome_status,
      outcomeSha256: envelope.outcome_sha256,
    } : {}),
  });
}

function canonicalDate(value) {
  const parsed = typeof value === "string" ? Date.parse(value) : NaN;
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function assertAcknowledgment(acknowledgment, expected, kind) {
  const status = kind === "commit" ? "forwarding" : "completed";
  if (
    acknowledgment.execution_id !== expected.executionId
    || acknowledgment.installation_id !== expected.installationId
    || acknowledgment.call_sha256 !== expected.callSha256
    || acknowledgment.policy_sha256 !== expected.policySha256
    || acknowledgment.decision !== "ALLOW"
    || acknowledgment.status !== status
    || typeof acknowledgment.replay !== "boolean"
    || (kind === "commit" && acknowledgment.replay !== false)
    || !canonicalDate(acknowledgment.committed_at)
  ) {
    throw new AuthorizationServiceError(`Guard ${kind} acknowledgment is not bound to the exact ALLOW authorization`);
  }
  if (
    kind === "completion"
    && (
      acknowledgment.outcome_status !== expected.outcomeStatus
      || acknowledgment.outcome_sha256 !== expected.outcomeSha256
      || !canonicalDate(acknowledgment.completed_at)
    )
  ) {
    throw new AuthorizationServiceError("Guard completion acknowledgment does not match the signed outcome");
  }
  return acknowledgment;
}

export function createGuardLifecycleHttpClient({
  serviceOrigin: rawServiceOrigin,
  fetchImpl,
}) {
  if (typeof fetchImpl !== "function") throw new InvalidInputError("A lifecycle fetch implementation is required");
  const origin = serviceOrigin(rawServiceOrigin);

  async function post(action, envelope, context = {}) {
    const kind = action === "commit" ? "commit" : "completion";
    const expected = binding(envelope, context, kind);
    const paymentProof = kind === "commit" && context.paymentProof !== null && context.paymentProof !== undefined
      ? normalizePaymentProof(context.paymentProof, { origin, kind: expected.kind })
      : null;
    async function send(endpointAction, body) {
      const url = lifecycleEndpoint(origin, expected.executionId, endpointAction);
      try {
        const response = await fetchImpl(url, {
          method: "POST",
          headers: { accept: "application/json", "content-type": "application/json" },
          body: canonicalBytes(body),
          redirect: "error",
          signal: context.signal,
        });
        if (!response || typeof response.status !== "number" || typeof response.arrayBuffer !== "function") {
          throw new AuthorizationServiceError("Lifecycle fetch returned an invalid response");
        }
        return response;
      } catch (cause) {
        if (cause instanceof ResponseLimitError || cause instanceof AuthorizationServiceError) throw cause;
        throw new AuthorizationServiceError("Guard lifecycle request failed", { cause });
      }
    }

    let response = await send(action, envelope);
    if (response.status < 200 || response.status >= 300) {
      if (kind === "commit" && paymentProof && response.status === 409) {
        const failure = await boundedAck(response);
        if (failure?.error?.code !== "guard_payment_not_settled") {
          throw new AuthorizationServiceError("Guard lifecycle endpoint returned HTTP 409");
        }
        response = await send("reconcile-commit", {
          schema: RECONCILED_COMMIT_SCHEMA,
          commit: envelope,
          payment_proof: paymentProof,
        });
      }
    }
    if (response.status < 200 || response.status >= 300) {
      throw new AuthorizationServiceError("Guard lifecycle endpoint returned HTTP " + response.status);
    }
    return assertAcknowledgment(await boundedAck(response), expected, kind);
  }

  return Object.freeze({
    commitAuthorization: (commit, context) => post("commit", commit, context),
    completeAuthorization: (completion, context) => post("complete", completion, context),
  });
}
