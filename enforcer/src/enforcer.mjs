import {
  canonicalBytes,
  canonicalSha256,
  deepFreeze,
  sha256Hex,
} from "./canonical.mjs";
import { getAddress, isAddress } from "viem";
import { normalizeConnectorRegistry } from "./connectors.mjs";
import { BASE_GAS_PRICE_ORACLE, EVM_PREBROADCAST_FEE_SCHEMA } from "./evm-fee-recheck.mjs";
import {
  AmbiguousOutcomeError,
  AuthorizationDeniedError,
  DeadlineExceededError,
  InvalidInputError,
  ReceiptVerificationError,
  ReplayDetectedError,
} from "./errors.mjs";
import {
  buildHttpsRequest,
  MAX_DEADLINE_MS,
  performPinnedHttpsRequest,
  resolvePublicAddresses,
} from "./network.mjs";
import {
  createSignedGuardLifecycle,
  hashGuardCall,
  normalizeGuardCall,
} from "./protocol.mjs";

const ATOMIC = /^(0|[1-9]\d{0,77})$/;
const SHA256 = /^[0-9a-f]{64}$/;
const BYTES32 = /^0x[0-9a-f]{64}$/;
const MAX_UINT256 = (1n << 256n) - 1n;
const EVM_SIMULATION_SCHEMA = "goldkey.evm-simulation-evidence.v2";

function exactSignedObject(value, fields, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new ReceiptVerificationError(`${name} must be an object`);
  const keys = Object.keys(value);
  const extras = keys.filter((key) => !fields.has(key));
  const missing = [...fields].filter((key) => !Object.hasOwn(value, key));
  if (extras.length > 0 || missing.length > 0) {
    throw new ReceiptVerificationError(`${name} must have the exact signed shape`, {
      extras: extras.sort(),
      missing: missing.sort(),
    });
  }
  return value;
}

function signedAtomic(value, name) {
  if (typeof value !== "string" || !ATOMIC.test(value) || BigInt(value) > MAX_UINT256) {
    throw new ReceiptVerificationError(`${name} must be a canonical uint256 atomic-unit string`);
  }
  return BigInt(value);
}

function exactLocalObject(value, fields, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new InvalidInputError(`${name} must be an object`);
  const keys = Object.keys(value);
  const extras = keys.filter((key) => !fields.has(key));
  const missing = [...fields].filter((key) => !Object.hasOwn(value, key));
  if (extras.length > 0 || missing.length > 0) {
    throw new InvalidInputError(`${name} must have the exact operator-controlled shape`, {
      extras: extras.sort(),
      missing: missing.sort(),
    });
  }
  return value;
}

function localAtomic(value, name) {
  if (typeof value !== "string" || !ATOMIC.test(value) || BigInt(value) > MAX_UINT256) {
    throw new InvalidInputError(`${name} must be a canonical uint256 atomic-unit string`);
  }
  return BigInt(value);
}

function assertEvmAllowEvidence({ call, verified, connector }) {
  if (verified.receipt.decision !== "ALLOW") return;
  const details = verified.evidence.details;
  if (!details || typeof details !== "object" || Array.isArray(details)) {
    throw new ReceiptVerificationError("EVM ALLOW evidence details are required");
  }
  const transactionSha256 = canonicalSha256(call.transaction);
  if (details.transaction_sha256 !== transactionSha256) {
    throw new ReceiptVerificationError("EVM evidence is not bound to the exact frozen transaction");
  }

  const simulation = exactSignedObject(details.simulation, new Set([
    "schema",
    "status",
    "chain_id",
    "transaction_sha256",
    "block_number",
    "block_hash",
    "target_code_sha256",
    "return_data_sha256",
    "gas_estimate",
    "pending_nonce",
    "l1_fee_estimate_atomic",
    "operator_fee_estimate_atomic",
    "gas_price_oracle_address",
  ]), "EVM simulation evidence");
  if (
    simulation.schema !== EVM_SIMULATION_SCHEMA
    || simulation.status !== "success"
    || simulation.chain_id !== call.transaction.chain_id
    || simulation.transaction_sha256 !== transactionSha256
  ) throw new ReceiptVerificationError("EVM simulation is not a successful proof for the exact transaction");
  signedAtomic(simulation.block_number, "simulation.block_number");
  if (typeof simulation.block_hash !== "string" || !BYTES32.test(simulation.block_hash)) {
    throw new ReceiptVerificationError("simulation.block_hash must be canonical 32-byte lowercase hex");
  }
  if (typeof simulation.target_code_sha256 !== "string" || !SHA256.test(simulation.target_code_sha256)) {
    throw new ReceiptVerificationError("simulation.target_code_sha256 must be a canonical signed target-code hash");
  }
  if (typeof simulation.return_data_sha256 !== "string" || !SHA256.test(simulation.return_data_sha256)) {
    throw new ReceiptVerificationError("simulation.return_data_sha256 must be a canonical hash");
  }
  const gasEstimate = signedAtomic(simulation.gas_estimate, "simulation.gas_estimate");
  const gasLimit = signedAtomic(call.transaction.gas_limit, "transaction.gas_limit");
  if (gasEstimate > gasLimit) throw new ReceiptVerificationError("Signed gas estimate exceeds the frozen transaction gas limit");
  signedAtomic(simulation.pending_nonce, "simulation.pending_nonce");
  if (simulation.pending_nonce !== call.transaction.nonce) {
    throw new ReceiptVerificationError("Signed pending nonce does not match the frozen transaction nonce");
  }
  const l1FeeEstimate = signedAtomic(simulation.l1_fee_estimate_atomic, "simulation.l1_fee_estimate_atomic");
  const operatorFeeEstimate = signedAtomic(simulation.operator_fee_estimate_atomic, "simulation.operator_fee_estimate_atomic");
  if (
    typeof simulation.gas_price_oracle_address !== "string"
    || simulation.gas_price_oracle_address.toLowerCase() !== BASE_GAS_PRICE_ORACLE.toLowerCase()
  ) throw new ReceiptVerificationError("Simulation does not bind the canonical Base GasPriceOracle");

  const fee = exactSignedObject(details.fee_reservation, new Set([
    "period_key_scope",
    "fee_domain",
    "amount_atomic",
    "spend_period_seconds",
    "max_period_atomic",
    "exposure",
  ]), "EVM fee reservation");
  const maxFeePerGas = signedAtomic(call.transaction.max_fee_per_gas_atomic, "transaction.max_fee_per_gas_atomic");
  const expectedFee = gasLimit * maxFeePerGas + l1FeeEstimate + operatorFeeEstimate;
  if (expectedFee > MAX_UINT256) throw new ReceiptVerificationError("Frozen transaction fee exposure exceeds uint256");
  const feeAmount = signedAtomic(fee.amount_atomic, "fee_reservation.amount_atomic");
  const feeCap = signedAtomic(fee.max_period_atomic, "fee_reservation.max_period_atomic");
  if (
    fee.period_key_scope !== "chain_native_fee"
    || fee.fee_domain !== `native:eip155:${call.transaction.chain_id}`
    || fee.exposure !== "network_fee"
    || feeAmount !== expectedFee
    || feeCap < feeAmount
    || !Number.isSafeInteger(fee.spend_period_seconds)
    || fee.spend_period_seconds < 60
    || fee.spend_period_seconds > 31_536_000
  ) throw new ReceiptVerificationError("EVM fee reservation does not exactly cover the frozen transaction fee exposure");

  const nonce = exactSignedObject(details.nonce_reservation, new Set([
    "period_key_scope",
    "lock_key",
    "connector_id",
    "chain_id",
    "from",
    "nonce",
    "amount_atomic",
    "max_period_atomic",
    "exposure",
  ]), "EVM nonce reservation");
  const expectedLock = `eip155:${call.transaction.chain_id}:${call.transaction.from}:nonce:${call.transaction.nonce}`;
  if (
    nonce.period_key_scope !== "wallet_nonce"
    || nonce.lock_key !== expectedLock
    || nonce.connector_id !== connector.id
    || nonce.chain_id !== call.transaction.chain_id
    || nonce.from !== call.transaction.from
    || nonce.nonce !== call.transaction.nonce
    || nonce.amount_atomic !== "1"
    || nonce.max_period_atomic !== "1"
    || nonce.exposure !== "nonce_lock"
  ) throw new ReceiptVerificationError("EVM wallet nonce lock does not exactly match the frozen transaction");
}

function assertEvmPreBroadcastFeeState({ call, verified, connector, state }) {
  const checked = exactLocalObject(state, new Set([
    "schema",
    "chain_id",
    "from",
    "transaction_sha256",
    "block_number",
    "block_hash",
    "pending_nonce",
    "native_balance_atomic",
    "l1_fee_estimate_atomic",
    "operator_fee_estimate_atomic",
  ]), "EVM pre-broadcast fee state");
  if (checked.schema !== EVM_PREBROADCAST_FEE_SCHEMA) {
    throw new InvalidInputError(`EVM pre-broadcast fee state schema must be ${EVM_PREBROADCAST_FEE_SCHEMA}`);
  }
  if (checked.chain_id !== call.transaction.chain_id) throw new InvalidInputError("EVM pre-broadcast chain does not match the frozen transaction");
  if (!isAddress(checked.from) || getAddress(checked.from) !== call.transaction.from) {
    throw new InvalidInputError("EVM pre-broadcast sender does not match the frozen transaction");
  }
  const transactionSha256 = canonicalSha256(call.transaction);
  if (checked.transaction_sha256 !== transactionSha256) throw new InvalidInputError("EVM pre-broadcast state is not bound to the frozen transaction");
  localAtomic(checked.block_number, "EVM pre-broadcast block_number");
  if (typeof checked.block_hash !== "string" || !BYTES32.test(checked.block_hash)) {
    throw new InvalidInputError("EVM pre-broadcast block_hash must be canonical 32-byte lowercase hex");
  }
  const pendingNonce = localAtomic(checked.pending_nonce, "EVM pre-broadcast pending_nonce");
  if (pendingNonce !== BigInt(call.transaction.nonce)) throw new InvalidInputError("EVM pre-broadcast pending nonce changed after authorization");

  const nativeBalance = localAtomic(checked.native_balance_atomic, "EVM pre-broadcast native_balance_atomic");
  const l1FeeEstimate = localAtomic(checked.l1_fee_estimate_atomic, "EVM pre-broadcast l1_fee_estimate_atomic");
  const operatorFeeEstimate = localAtomic(checked.operator_fee_estimate_atomic, "EVM pre-broadcast operator_fee_estimate_atomic");
  const gasLimit = localAtomic(call.transaction.gas_limit, "transaction.gas_limit");
  const maxFeePerGas = localAtomic(call.transaction.max_fee_per_gas_atomic, "transaction.max_fee_per_gas_atomic");
  const nativeValue = localAtomic(call.transaction.value_atomic, "transaction.value_atomic");
  const executionFeeMaximum = gasLimit * maxFeePerGas;
  const estimatedNetworkFee = executionFeeMaximum + l1FeeEstimate + operatorFeeEstimate;
  const estimatedNativeRequirement = nativeValue + estimatedNetworkFee;
  if (estimatedNetworkFee > MAX_UINT256 || estimatedNativeRequirement > MAX_UINT256) {
    throw new InvalidInputError("EVM pre-broadcast native exposure exceeds uint256");
  }

  const signedReservation = signedAtomic(verified.evidence.details.fee_reservation.amount_atomic, "fee_reservation.amount_atomic");
  const localEstimatedFeeCap = BigInt(connector.max_estimated_network_fee_atomic);
  const walletExposureCap = BigInt(connector.max_wallet_native_exposure_atomic);
  if (estimatedNetworkFee > signedReservation) {
    throw new InvalidInputError("Current EVM network-fee estimate exceeds the signed reservation; a fresh authorization is required");
  }
  if (estimatedNetworkFee > localEstimatedFeeCap) {
    throw new InvalidInputError("Current EVM network-fee estimate exceeds the operator's local transaction cap");
  }
  if (nativeBalance > walletExposureCap) {
    throw new InvalidInputError("EVM fee wallet balance exceeds the operator's segregated-wallet exposure cap");
  }
  if (nativeBalance < estimatedNativeRequirement) {
    throw new InvalidInputError("EVM fee wallet cannot cover the frozen native value and current fee estimate");
  }

  return deepFreeze({
    schema: EVM_PREBROADCAST_FEE_SCHEMA,
    chain_id: checked.chain_id,
    from: call.transaction.from,
    transaction_sha256: transactionSha256,
    block_number: checked.block_number,
    block_hash: checked.block_hash,
    pending_nonce: checked.pending_nonce,
    native_balance_atomic: checked.native_balance_atomic,
    l1_fee_estimate_atomic: checked.l1_fee_estimate_atomic,
    operator_fee_estimate_atomic: checked.operator_fee_estimate_atomic,
    execution_fee_maximum_atomic: executionFeeMaximum.toString(),
    estimated_network_fee_atomic: estimatedNetworkFee.toString(),
    estimated_native_requirement_atomic: estimatedNativeRequirement.toString(),
    max_estimated_network_fee_atomic: connector.max_estimated_network_fee_atomic,
    max_wallet_native_exposure_atomic: connector.max_wallet_native_exposure_atomic,
  });
}

function safeFailure(error) {
  return Object.freeze({
    code: typeof error?.code === "string" ? error.code : "unknown_error",
    name: typeof error?.name === "string" ? error.name : "Error",
  });
}

function outcomeValue(value, state = { nodes: 0, seen: new WeakSet() }, depth = 0) {
  state.nodes += 1;
  if (state.nodes > 20_000) return "[node-limit]";
  if (depth > 32) return "[depth-limit]";
  if (value === undefined) return null;
  if (value === null || typeof value === "boolean" || typeof value === "number") return value;
  if (typeof value === "string") {
    const bytes = Buffer.from(value, "utf8");
    return bytes.byteLength <= 64 * 1024 ? value : { string_bytes: bytes.byteLength, string_sha256: sha256Hex(bytes) };
  }
  if (typeof value === "bigint") return value.toString();
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const bytes = Buffer.from(value);
    return { bytes_length: bytes.byteLength, bytes_sha256: sha256Hex(bytes) };
  }
  if (value && typeof value === "object") {
    if (state.seen.has(value)) return "[cycle]";
    state.seen.add(value);
  }
  if (Array.isArray(value)) {
    const normalized = value.slice(0, 1000).map((entry) => outcomeValue(entry, state, depth + 1));
    if (value.length > 1000) normalized.push("[item-limit:" + value.length + "]");
    return normalized;
  }
  if (typeof value === "object") {
    const normalized = {};
    const keys = Object.keys(value).sort();
    for (const key of keys.slice(0, 1000)) {
      try {
        normalized[key] = outcomeValue(value[key], state, depth + 1);
      } catch {
        normalized[key] = "[unreadable]";
      }
    }
    if (keys.length > 1000) normalized["[property-limit]"] = keys.length;
    return normalized;
  }
  return String(value);
}

function digestOutcome(value) {
  try {
    return canonicalSha256(outcomeValue(value));
  } catch {
    return canonicalSha256({ status: "succeeded", outcome: "uninspectable" });
  }
}

function assertReceiptEvidence(verified, expected) {
  const { receipt, evidence } = verified;
  for (const [field, value] of Object.entries(expected.receipt ?? {})) {
    if (receipt[field] !== value) throw new ReceiptVerificationError("Receipt " + field + " does not match the operator-bound connector");
  }
  for (const [field, value] of Object.entries(expected.evidence ?? {})) {
    if (evidence[field] !== value) throw new ReceiptVerificationError("Receipt evidence " + field + " does not match the operator-bound connector");
  }
  for (const [field, value] of Object.entries(expected.details ?? {})) {
    if (evidence.details?.[field] !== value) throw new ReceiptVerificationError("Receipt evidence detail " + field + " does not match the exact call");
  }
}

export class GoldKeyEnforcer {
  #installationIdentity;
  #outcomeStore;
  #authorizer;
  #commitAuthorization;
  #completeAuthorization;
  #connectors;
  #clock;
  #deadlineMs;
  #resolve4;
  #resolve6;
  #httpsRequest;

  constructor({
    installationIdentity,
    outcomeStore,
    authorizer,
    commitAuthorization,
    completeAuthorization,
    connectors,
    clock = () => Date.now(),
    deadlineMs = MAX_DEADLINE_MS,
    resolve4,
    resolve6,
    httpsRequest,
  }) {
    if (!installationIdentity?.installationId || typeof installationIdentity.signMessage !== "function") throw new InvalidInputError("A proxy-local Ed25519 installation identity is required");
    if (!outcomeStore || typeof outcomeStore.begin !== "function" || typeof outcomeStore.transition !== "function") throw new InvalidInputError("A durable outcomeStore is required");
    if (!authorizer || typeof authorizer.authorize !== "function" || typeof authorizer.assertReceiptFresh !== "function") throw new InvalidInputError("A receipt-verifying authorizer is required");
    if (typeof commitAuthorization !== "function") throw new InvalidInputError("An idempotent commitAuthorization callback is required; forwarding without server commit is forbidden");
    if (completeAuthorization !== undefined && typeof completeAuthorization !== "function") throw new InvalidInputError("completeAuthorization must be a function when supplied");
    if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > MAX_DEADLINE_MS) throw new InvalidInputError("deadlineMs must be 1-15000 milliseconds");
    this.#installationIdentity = installationIdentity;
    this.#outcomeStore = outcomeStore;
    this.#authorizer = authorizer;
    this.#commitAuthorization = commitAuthorization;
    this.#completeAuthorization = completeAuthorization;
    this.#connectors = normalizeConnectorRegistry(connectors);
    this.#clock = clock;
    this.#deadlineMs = deadlineMs;
    this.#resolve4 = resolve4;
    this.#resolve6 = resolve6;
    this.#httpsRequest = httpsRequest;
    Object.freeze(this);
  }

  #connector(connectorId, kind) {
    const connector = this.#connectors.get(connectorId);
    if (!connector || connector.kind !== kind) throw new InvalidInputError("No operator-controlled " + kind + " connector matches " + connectorId);
    return connector;
  }

  async #withinDeadline(deadlineAt, operation, label) {
    const remaining = deadlineAt - this.#clock();
    if (remaining <= 0) throw new DeadlineExceededError(label + " exceeded the enforcement deadline");
    const controller = new AbortController();
    let timeout;
    const timeoutPromise = new Promise((_, reject) => {
      timeout = setTimeout(() => {
        const error = new DeadlineExceededError(label + " exceeded the enforcement deadline");
        controller.abort(error);
        reject(error);
      }, remaining);
    });
    try {
      return await Promise.race([
        Promise.resolve().then(() => operation(controller.signal)),
        timeoutPromise,
      ]);
    } finally {
      clearTimeout(timeout);
    }
  }

  async #bestEffortUnknownCompletion({ verified, callHash, deadlineAt }) {
    if (!this.#completeAuthorization) return;
    try {
      const outcomeSha256 = canonicalSha256({ status: "outcome_unknown" });
      const completion = createSignedGuardLifecycle({
        installationIdentity: this.#installationIdentity,
        kind: "completion",
        receipt: verified.receipt,
        receiptSha256: verified.receipt_sha256,
        callSha256: callHash,
        outcomeStatus: "outcome_unknown",
        outcomeSha256,
        issuedAt: this.#clock(),
      });
      await this.#withinDeadline(deadlineAt, (signal) => this.#completeAuthorization(completion, {
        signal,
        deadlineAt,
        receipt: verified.receipt,
      }), "Guard completion");
    } catch {
      // Local UNKNOWN is authoritative for retry safety even if remote completion is unavailable.
    }
  }

  async #execute({ idempotencyKey, rawCall, expected, validateAuthorization, prepare, forward }) {
    const call = normalizeGuardCall(rawCall);
    const callHash = hashGuardCall(call);
    const begun = await this.#outcomeStore.begin({
      idempotencyKey,
      callHash,
      callKind: call.kind,
    });
    if (!begun.created) {
      if (["FORWARDING", "UNKNOWN"].includes(begun.record.state)) {
        throw new AmbiguousOutcomeError(undefined, { details: { state: begun.record.state, call_hash: callHash } });
      }
      throw new ReplayDetectedError(undefined, { state: begun.record.state, call_hash: callHash });
    }
    const deadlineAt = this.#clock() + this.#deadlineMs;
    let verified;
    try {
      verified = await this.#authorizer.authorize({ call, idempotencyKey, deadlineAt });
      assertReceiptEvidence(verified, expected(call));
      validateAuthorization?.({ call, verified });
    } catch (error) {
      await this.#outcomeStore.transition({
        idempotencyKey,
        callHash,
        from: "AUTHORIZING",
        to: "AUTHORIZATION_FAILED",
        patch: { failure: safeFailure(error) },
      });
      throw error;
    }
    if (verified.receipt.decision !== "ALLOW") {
      await this.#outcomeStore.transition({
        idempotencyKey,
        callHash,
        from: "AUTHORIZING",
        to: "DENIED",
        patch: {
          receipt_id: verified.receipt.receipt_id,
          receipt_sha256: verified.receipt_sha256,
          decision: verified.receipt.decision,
          reason_codes: verified.receipt.reason_codes,
        },
      });
      throw new AuthorizationDeniedError("GoldKey returned " + verified.receipt.decision, {
        reason_codes: verified.receipt.reason_codes,
        receipt_id: verified.receipt.receipt_id,
      });
    }
    await this.#outcomeStore.transition({
      idempotencyKey,
      callHash,
      from: "AUTHORIZING",
      to: "AUTHORIZED",
      patch: {
        receipt_id: verified.receipt.receipt_id,
        receipt_sha256: verified.receipt_sha256,
        policy_sha256: verified.receipt.policy_sha256,
        receipt_expires_at: verified.receipt.expires_at,
        payment_proof: verified.paymentProof,
      },
    });

    let prepared;
    try {
      prepared = prepare
        ? await this.#withinDeadline(deadlineAt, (signal) => prepare({ call, verified, signal, deadlineAt }), "Local connector preparation")
        : undefined;
      this.#authorizer.assertReceiptFresh(verified.receipt);
    } catch (error) {
      await this.#outcomeStore.transition({
        idempotencyKey,
        callHash,
        from: "AUTHORIZED",
        to: "PREPARATION_FAILED",
        patch: { failure: safeFailure(error) },
      });
      throw error;
    }

    await this.#outcomeStore.transition({
      idempotencyKey,
      callHash,
      from: "AUTHORIZED",
      to: "FORWARDING",
      patch: { execution_id: verified.receipt.receipt_id },
    });
    try {
      const commit = createSignedGuardLifecycle({
        installationIdentity: this.#installationIdentity,
        kind: "commit",
        receipt: verified.receipt,
        receiptSha256: verified.receipt_sha256,
        callSha256: callHash,
        issuedAt: this.#clock(),
      });
      const acknowledgment = await this.#withinDeadline(deadlineAt, (signal) => this.#commitAuthorization(commit, {
        signal,
        deadlineAt,
        receipt: verified.receipt,
        call,
        paymentProof: verified.paymentProof,
      }), "Guard commit");
      if (
        !acknowledgment
        || typeof acknowledgment !== "object"
        || Array.isArray(acknowledgment)
        || acknowledgment.replay !== false
        || acknowledgment.ok === false
      ) {
        throw new Error("Guard commit did not acknowledge one fresh, non-replay execution");
      }
      this.#authorizer.assertReceiptFresh(verified.receipt);
    } catch (error) {
      await this.#outcomeStore.transition({
        idempotencyKey,
        callHash,
        from: "FORWARDING",
        to: "UNKNOWN",
        patch: { failure: safeFailure(error), phase: "commit" },
      });
      throw new AmbiguousOutcomeError("Guard commit was unavailable or ambiguous; upstream was not invoked", { cause: error });
    }

    let result;
    try {
      result = await this.#withinDeadline(deadlineAt, (signal) => forward({
        call,
        prepared,
        verified,
        signal,
        deadlineAt,
      }), "Guarded upstream action");
    } catch (error) {
      await this.#bestEffortUnknownCompletion({ verified, callHash, deadlineAt });
      await this.#outcomeStore.transition({
        idempotencyKey,
        callHash,
        from: "FORWARDING",
        to: "UNKNOWN",
        patch: { failure: safeFailure(error), phase: "upstream" },
      });
      throw new AmbiguousOutcomeError("The guarded upstream outcome is ambiguous and will not be retried automatically", { cause: error });
    }

    const outcomeSha256 = digestOutcome(result);
    if (this.#completeAuthorization) {
      try {
        const completion = createSignedGuardLifecycle({
          installationIdentity: this.#installationIdentity,
          kind: "completion",
          receipt: verified.receipt,
          receiptSha256: verified.receipt_sha256,
          callSha256: callHash,
          outcomeStatus: "succeeded",
          outcomeSha256,
          issuedAt: this.#clock(),
        });
        const acknowledgment = await this.#withinDeadline(deadlineAt, (signal) => this.#completeAuthorization(completion, {
          signal,
          deadlineAt,
          receipt: verified.receipt,
        }), "Guard completion");
        if (acknowledgment === false || acknowledgment?.ok === false) throw new Error("Guard completion was rejected");
      } catch (error) {
        await this.#outcomeStore.transition({
          idempotencyKey,
          callHash,
          from: "FORWARDING",
          to: "UNKNOWN",
          patch: { failure: safeFailure(error), phase: "completion", outcome_sha256: outcomeSha256 },
        });
        throw new AmbiguousOutcomeError("Upstream succeeded but signed completion is ambiguous; do not retry", { cause: error });
      }
    }
    await this.#outcomeStore.transition({
      idempotencyKey,
      callHash,
      from: "FORWARDING",
      to: "SUCCEEDED",
      patch: { outcome_sha256: outcomeSha256, payment_proof: null },
    });
    return result;
  }

  async guardMcpTool({ connectorId, tool, arguments: argumentsValue, idempotencyKey }) {
    const connector = this.#connector(connectorId, "mcp_tool");
    const configuredTool = connector.tools.find(({ name }) => name === tool);
    if (!configuredTool) throw new InvalidInputError("MCP tool is not in the operator-controlled connector");
    const rawCall = {
      kind: "mcp_tool",
      connector_id: connector.id,
      tool: configuredTool.name,
      input_schema_sha256: configuredTool.input_schema_sha256,
      arguments: argumentsValue,
    };
    return this.#execute({
      idempotencyKey,
      rawCall,
      expected: () => ({
        receipt: { connector_id: connector.id, kind: "mcp_tool" },
        evidence: {
          effect: configuredTool.effect,
          destination: "mcp://" + connector.server_id + "/" + configuredTool.name,
        },
      }),
      forward: ({ call, verified, signal, deadlineAt }) => {
        const argumentsBytes = canonicalBytes(call.arguments);
        return connector.invokeTool(Object.freeze({
          serverId: connector.server_id,
          tool: call.tool,
          arguments: call.arguments,
          argumentsBytes,
          signal,
          deadlineAt,
          receipt: verified.receipt,
        }));
      },
    });
  }

  async guardHttps({ connectorId, operationId, query, body, idempotencyKey }) {
    const connector = this.#connector(connectorId, "https");
    const operation = connector.operations.find(({ id }) => id === operationId);
    if (!operation) throw new InvalidInputError("HTTPS operation is not in the operator-controlled connector");
    const rawCall = {
      kind: "https",
      connector_id: connector.id,
      operation_id: operation.id,
      ...(query === undefined ? {} : { query }),
      ...(body === undefined ? {} : { body }),
    };
    return this.#execute({
      idempotencyKey,
      rawCall,
      expected: () => ({
        receipt: { connector_id: connector.id, kind: "https" },
        evidence: { effect: operation.effect, destination: connector.origin + operation.path },
        details: { method: operation.method, operation_id: operation.id },
      }),
      prepare: async ({ call }) => {
        const addresses = await resolvePublicAddresses(new URL(connector.origin).hostname, {
          ...(this.#resolve4 ? { resolve4: this.#resolve4 } : {}),
          ...(this.#resolve6 ? { resolve6: this.#resolve6 } : {}),
        });
        return Object.freeze({
          request: buildHttpsRequest({ connector, operation, call }),
          pinnedAddress: addresses[0],
        });
      },
      forward: ({ prepared, signal }) => performPinnedHttpsRequest({
        ...prepared,
        ...(this.#httpsRequest ? { requestImpl: this.#httpsRequest } : {}),
        signal,
      }),
    });
  }

  async guardEvmTransaction({ connectorId, transaction, idempotencyKey }) {
    const connector = this.#connector(connectorId, "evm_transaction");
    const rawCall = {
      kind: "evm_transaction",
      connector_id: connector.id,
      transaction,
    };
    return this.#execute({
      idempotencyKey,
      rawCall,
      expected: (call) => {
        if (call.transaction.chain_id !== connector.chain_id || call.transaction.from !== connector.from) {
          throw new InvalidInputError("EVM transaction chain/from does not match the operator-controlled signer");
        }
        const destination = call.transaction.to
          ? "eip155:" + call.transaction.chain_id + ":" + call.transaction.to
          : "eip155:" + call.transaction.chain_id + ":contract_creation";
        return {
          receipt: { connector_id: connector.id, kind: "evm_transaction" },
          evidence: { effect: "payment", destination },
          details: { transaction_sha256: canonicalSha256(call.transaction) },
        };
      },
      validateAuthorization: ({ call, verified }) => assertEvmAllowEvidence({ call, verified, connector }),
      forward: async ({ call, verified, signal, deadlineAt }) => {
        const transactionBytes = canonicalBytes(call.transaction);
        const caps = Object.freeze({
          max_estimated_network_fee_atomic: connector.max_estimated_network_fee_atomic,
          max_wallet_native_exposure_atomic: connector.max_wallet_native_exposure_atomic,
        });
        const rawFeeState = await connector.recheckFeeExposure(Object.freeze({
          transaction: deepFreeze(call.transaction),
          transactionBytes,
          caps,
          signal,
          deadlineAt,
          receipt: verified.receipt,
        }));
        const feeExposure = assertEvmPreBroadcastFeeState({ call, verified, connector, state: rawFeeState });
        if (signal.aborted || this.#clock() >= deadlineAt) {
          throw new DeadlineExceededError("EVM fee recheck completed after the enforcement deadline");
        }
        this.#authorizer.assertReceiptFresh(verified.receipt);
        return connector.signAndBroadcast(Object.freeze({
          transaction: deepFreeze(call.transaction),
          transactionBytes,
          feeExposure,
          signal,
          deadlineAt,
          receipt: verified.receipt,
        }));
      },
    });
  }
}

Object.freeze(GoldKeyEnforcer.prototype);
