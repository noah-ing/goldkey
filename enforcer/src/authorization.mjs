import { x402Client } from "@x402/core/client";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { x402HTTPClient } from "@x402/fetch";
import { getAddress, isAddress } from "viem";
import { canonicalBytes, deepFreeze, isCanonicalSha256 } from "./canonical.mjs";
import { SqlitePaymentBudgetStore } from "./payment-budget.mjs";
import {
  AuthorizationServiceError,
  DeadlineExceededError,
  InvalidInputError,
  LocalStateError,
  PaymentPolicyError,
  ReceiptVerificationError,
  ResponseLimitError,
} from "./errors.mjs";
import {
  createSignedGuardRequest,
  hashGuardCall,
  normalizeGuardCall,
  normalizeReceiptKeyset,
  verifyGuardAuthorizationEnvelope,
} from "./protocol.mjs";

const AUTHORIZATION_RESPONSE_LIMIT = 64 * 1024;
const PAYMENT_REQUIRED_HEADER_LIMIT = 64 * 1024;
const PAYMENT_PROOF_LIMIT = 64 * 1024;
const MAX_AUTHORIZATION_TIMEOUT_MS = 30_000;
export const BASE_MAINNET_X402_NETWORK = "eip155:8453";
export const BASE_MAINNET_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
export const GUARD_NETWORK_PAYMENT_ATOMIC = "50000";
export const GUARD_EVM_PAYMENT_ATOMIC = "100000";
const ATOMIC = /^(0|[1-9]\d{0,77})$/;
const TRANSACTION_HASH = /^0x[0-9a-f]{64}$/;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const EXACT_EXTRA_KEYS = new Set(["name", "version", "assetTransferMethod"]);
const EIP3009_NONCE = /^0x[0-9a-fA-F]{64}$/;

async function boundedJsonResponse(response) {
  const rawLength = response.headers?.get?.("content-length");
  if (rawLength !== null && rawLength !== undefined && rawLength !== "") {
    const length = Number(rawLength);
    if (!Number.isSafeInteger(length) || length < 0 || length > AUTHORIZATION_RESPONSE_LIMIT) {
      throw new ResponseLimitError(`Authorization response exceeds ${AUTHORIZATION_RESPONSE_LIMIT} bytes`);
    }
  }
  let bytes;
  const reader = response.body?.getReader?.();
  if (reader) {
    const chunks = [];
    let length = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = Buffer.from(value);
        length += chunk.byteLength;
        if (length > AUTHORIZATION_RESPONSE_LIMIT) {
          await reader.cancel().catch(() => {});
          throw new ResponseLimitError(`Authorization response exceeds ${AUTHORIZATION_RESPONSE_LIMIT} bytes`);
        }
        chunks.push(chunk);
      }
    } finally {
      reader.releaseLock?.();
    }
    bytes = Buffer.concat(chunks, length);
  } else {
    bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.byteLength > AUTHORIZATION_RESPONSE_LIMIT) throw new ResponseLimitError(`Authorization response exceeds ${AUTHORIZATION_RESPONSE_LIMIT} bytes`);
  }
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new AuthorizationServiceError("Authorization service returned invalid JSON");
  }
}

function deadlineSignal(deadlineAt, clock, timeoutMs = MAX_AUTHORIZATION_TIMEOUT_MS) {
  const remaining = Math.min(deadlineAt - clock(), timeoutMs);
  if (remaining <= 0) throw new DeadlineExceededError();
  const controller = new AbortController();
  let rejectExpired;
  const expired = new Promise((_, reject) => { rejectExpired = reject; });
  const timeout = setTimeout(() => {
    const error = new DeadlineExceededError();
    controller.abort(error);
    rejectExpired(error);
  }, remaining);
  timeout.unref?.();
  return { signal: controller.signal, expired, clear: () => clearTimeout(timeout) };
}

function withinDeadline(operation, deadline) {
  if (deadline.signal.aborted) return Promise.reject(deadline.signal.reason ?? new DeadlineExceededError());
  return Promise.race([Promise.resolve().then(operation), deadline.expired]);
}

function paymentConfig(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new InvalidInputError("payment must be an object when x402 settlement is enabled");
  const allowed = new Set(["signer", "treasuryAddress", "maxAmountAtomic", "timeoutMs", "budgetStore"]);
  const extras = Object.keys(value).filter((key) => !allowed.has(key));
  if (extras.length > 0) throw new InvalidInputError("payment contains unsupported fields", { fields: extras.sort() });
  const { signer } = value;
  if (!signer || typeof signer !== "object" || !isAddress(signer.address) || getAddress(signer.address) === ZERO_ADDRESS || typeof signer.signTypedData !== "function") {
    throw new InvalidInputError("payment.signer must be a local EVM signer with address and signTypedData");
  }
  if (!isAddress(value.treasuryAddress) || getAddress(value.treasuryAddress) === ZERO_ADDRESS) throw new InvalidInputError("payment.treasuryAddress must be a nonzero EVM address");
  if (typeof value.maxAmountAtomic !== "string" || !ATOMIC.test(value.maxAmountAtomic)) {
    throw new InvalidInputError("payment.maxAmountAtomic must be a canonical atomic-unit integer string");
  }
  if (!(value.budgetStore instanceof SqlitePaymentBudgetStore)) {
    throw new InvalidInputError("payment.budgetStore must be an operator-owned SqlitePaymentBudgetStore");
  }
  const timeoutMs = value.timeoutMs ?? MAX_AUTHORIZATION_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_AUTHORIZATION_TIMEOUT_MS) {
    throw new InvalidInputError(`payment.timeoutMs must be 1-${MAX_AUTHORIZATION_TIMEOUT_MS}`);
  }
  // The original signer/private key is retained solely in this closure and is
  // never returned to an agent connector or fetch callback.
  const signTypedData = signer.signTypedData.bind(signer);
  return Object.freeze({
    treasuryAddress: getAddress(value.treasuryAddress),
    payerAddress: getAddress(signer.address),
    maxAmountAtomic: value.maxAmountAtomic,
    timeoutMs,
    budgetStore: value.budgetStore,
    signTypedData,
  });
}

function safeBigInt(value, name) {
  try {
    return BigInt(value);
  } catch {
    throw new PaymentPolicyError(`${name} must be a canonical integer`);
  }
}

function eip3009PaymentIdentity(typedData, { payment, amountAtomic }) {
  if (!typedData || typeof typedData !== "object" || Array.isArray(typedData)) {
    throw new PaymentPolicyError("x402 signer received invalid EIP-712 typed data");
  }
  const { domain, message, primaryType } = typedData;
  if (
    primaryType !== "TransferWithAuthorization"
    || !domain || typeof domain !== "object"
    || domain.name !== "USD Coin"
    || domain.version !== "2"
    || safeBigInt(domain.chainId, "EIP-712 domain.chainId") !== 8453n
    || !sameAddress(domain.verifyingContract, BASE_MAINNET_USDC)
  ) throw new PaymentPolicyError("x402 signer received a non-canonical Base USDC EIP-3009 domain");
  if (
    !message || typeof message !== "object" || Array.isArray(message)
    || !sameAddress(message.from, payment.payerAddress)
    || !sameAddress(message.to, payment.treasuryAddress)
    || safeBigInt(message.value, "EIP-3009 value") !== BigInt(amountAtomic)
    || safeBigInt(message.validAfter, "EIP-3009 validAfter") < 0n
    || typeof message.nonce !== "string"
    || !EIP3009_NONCE.test(message.nonce)
  ) throw new PaymentPolicyError("x402 signer received an EIP-3009 authorization outside the exact local payment binding");
  const validBeforeSeconds = safeBigInt(message.validBefore, "EIP-3009 validBefore");
  const validBeforeMsBigInt = validBeforeSeconds * 1000n;
  if (validBeforeSeconds <= 0n || validBeforeMsBigInt > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new PaymentPolicyError("EIP-3009 validBefore exceeds safe local budget bounds");
  }
  return Object.freeze({
    validBeforeMs: Number(validBeforeMsBigInt),
    paymentNonce: message.nonce.toLowerCase(),
  });
}

function createBudgetedPaymentAttempt(payment, binding) {
  let reservation;
  let transmissionPossible = false;
  const restrictedSigner = Object.freeze({
    address: payment.payerAddress,
    async signTypedData(typedData) {
      if (reservation) throw new PaymentPolicyError("x402 attempted more than one signature for one authorization payment");
      const { validBeforeMs, paymentNonce } = eip3009PaymentIdentity(typedData, { payment, amountAtomic: binding.amountAtomic });
      reservation = await payment.budgetStore.reserve({
        installationId: binding.installationId,
        idempotencyKey: binding.idempotencyKey,
        callSha256: binding.callSha256,
        amountAtomic: binding.amountAtomic,
        payer: payment.payerAddress,
        payee: payment.treasuryAddress,
        network: BASE_MAINNET_X402_NETWORK,
        asset: BASE_MAINNET_USDC,
        paymentNonce,
        validBeforeMs,
      });
      try {
        return await payment.signTypedData(typedData);
      } catch (cause) {
        await payment.budgetStore.releaseUntransmitted({
          reservationId: reservation.reservationId,
          installationId: binding.installationId,
          idempotencyKey: binding.idempotencyKey,
          callSha256: binding.callSha256,
        });
        reservation = undefined;
        throw cause;
      }
    },
  });
  const client = new x402Client().register(BASE_MAINNET_X402_NETWORK, new ExactEvmScheme(restrictedSigner));
  const httpClient = new x402HTTPClient(client);
  const reservationBinding = () => ({
    reservationId: reservation.reservationId,
    installationId: binding.installationId,
    idempotencyKey: binding.idempotencyKey,
    callSha256: binding.callSha256,
  });
  return Object.freeze({
    client,
    httpClient,
    async releaseIfDefinitelyUntransmitted() {
      if (!reservation || transmissionPossible) return;
      await payment.budgetStore.releaseUntransmitted(reservationBinding());
      reservation = undefined;
    },
    async markTransmitted() {
      if (!reservation) throw new PaymentPolicyError("x402 payment was not durably reserved before transmission");
      // Set this first. If the durable transition itself has an indeterminate
      // failure, automatic release could undercount a payment that was sent by
      // a concurrently continuing operation.
      transmissionPossible = true;
      await payment.budgetStore.markTransmitted(reservationBinding());
    },
    async commitSettlement(transaction) {
      if (!reservation || !transmissionPossible) throw new PaymentPolicyError("x402 settlement has no transmitted payment reservation");
      await payment.budgetStore.commitSettlement({ ...reservationBinding(), transaction });
    },
  });
}

function frozenPaymentPayload(value) {
  let bytes;
  let jsonValue;
  try {
    // The x402 header encoder uses JSON.stringify, which intentionally omits
    // optional undefined fields. Persist the exact JSON value that crossed the
    // wire, then canonicalize that value for bounded recovery storage.
    jsonValue = JSON.parse(JSON.stringify(value));
    bytes = canonicalBytes(jsonValue);
  } catch (cause) {
    throw new AuthorizationServiceError("x402 client produced a non-canonical payment payload", { cause });
  }
  if (bytes.byteLength > PAYMENT_PROOF_LIMIT) {
    throw new ResponseLimitError(`x402 payment payload exceeds ${PAYMENT_PROOF_LIMIT} bytes`);
  }
  return deepFreeze(JSON.parse(bytes.toString("utf8")));
}

function settlementProof(response, { payment, paymentPayload, expectedAmount }) {
  let settlement;
  try {
    settlement = payment.httpClient.getPaymentSettleResponse((name) => response.headers?.get?.(name));
  } catch (cause) {
    throw new AuthorizationServiceError("Paid authorization response omitted a valid PAYMENT-RESPONSE", { cause });
  }
  if (!settlement || typeof settlement !== "object" || Array.isArray(settlement) || settlement.success !== true) {
    throw new AuthorizationServiceError("Paid authorization did not include a successful settlement receipt");
  }
  if (settlement.network !== BASE_MAINNET_X402_NETWORK) {
    throw new PaymentPolicyError(`Settlement network must be ${BASE_MAINNET_X402_NETWORK}`);
  }
  if (typeof settlement.transaction !== "string" || !TRANSACTION_HASH.test(settlement.transaction.toLowerCase())) {
    throw new AuthorizationServiceError("Settlement transaction must be one canonical Base transaction hash");
  }
  if (settlement.payer !== undefined && !sameAddress(settlement.payer, payment.payerAddress)) {
    throw new PaymentPolicyError("Settlement payer does not match the local x402 signer");
  }
  if (settlement.amount !== undefined && settlement.amount !== expectedAmount) {
    throw new PaymentPolicyError("Settlement amount does not match the exact authorization price");
  }
  return Object.freeze({
    transaction: settlement.transaction.toLowerCase(),
    payment_payload: frozenPaymentPayload(paymentPayload),
  });
}

function expectedPaymentAmount(call) {
  return call.kind === "evm_transaction" ? GUARD_EVM_PAYMENT_ATOMIC : GUARD_NETWORK_PAYMENT_ATOMIC;
}

function sameAddress(actual, expected) {
  return typeof actual === "string" && isAddress(actual) && getAddress(actual) === getAddress(expected);
}

function assertExactPaymentRequired(paymentRequired, { authorizeUrl, call, payment }) {
  if (!paymentRequired || typeof paymentRequired !== "object" || paymentRequired.x402Version !== 2) {
    throw new PaymentPolicyError("Authorization challenge must use x402 v2");
  }
  if (paymentRequired.resource?.url !== authorizeUrl) {
    throw new PaymentPolicyError("Authorization challenge resource does not match the exact authorization URL");
  }
  if (!Array.isArray(paymentRequired.accepts) || paymentRequired.accepts.length !== 1) {
    throw new PaymentPolicyError("Authorization challenge must contain exactly one payment option");
  }
  const option = paymentRequired.accepts[0];
  const expectedAmount = expectedPaymentAmount(call);
  if (option.scheme !== "exact") throw new PaymentPolicyError("Authorization challenge scheme must be exact");
  if (option.network !== BASE_MAINNET_X402_NETWORK) throw new PaymentPolicyError(`Authorization challenge network must be ${BASE_MAINNET_X402_NETWORK}`);
  if (!sameAddress(option.asset, BASE_MAINNET_USDC)) throw new PaymentPolicyError("Authorization challenge asset must be canonical Base USDC");
  if (!sameAddress(option.payTo, payment.treasuryAddress)) throw new PaymentPolicyError("Authorization challenge payee does not match the configured treasury");
  if (option.amount !== expectedAmount) throw new PaymentPolicyError(`Authorization challenge amount must be exactly ${expectedAmount} atomic USDC`);
  if (BigInt(option.amount) > BigInt(payment.maxAmountAtomic)) throw new PaymentPolicyError("Authorization challenge exceeds the local per-call payment maximum");
  if (!Number.isSafeInteger(option.maxTimeoutSeconds) || option.maxTimeoutSeconds < 1 || option.maxTimeoutSeconds > 30) {
    throw new PaymentPolicyError("Authorization challenge maxTimeoutSeconds must be 1-30");
  }
  const extra = option.extra;
  if (!extra || typeof extra !== "object" || Array.isArray(extra)) throw new PaymentPolicyError("Authorization challenge must bind the canonical USDC EIP-712 domain");
  const extraKeys = Object.keys(extra);
  if (extraKeys.some((key) => !EXACT_EXTRA_KEYS.has(key))) {
    throw new PaymentPolicyError("Authorization challenge contains unsupported exact-scheme parameters");
  }
  if (extra.name !== "USD Coin" || extra.version !== "2" || (extra.assetTransferMethod !== undefined && extra.assetTransferMethod !== "eip3009")) {
    throw new PaymentPolicyError("Authorization challenge must use canonical USDC EIP-3009 parameters");
  }
  return option;
}

export class RemoteAuthorizer {
  #authorizeUrl;
  #fetchImpl;
  #installationIdentity;
  #keyset;
  #policyHash;
  #clock;
  #payment;

  constructor({
    authorizeUrl,
    fetchImpl,
    installationIdentity,
    receiptKeyset,
    receiptPublicJwk,
    receiptKeyId,
    policyHash,
    payment,
    clock = () => Date.now(),
  }) {
    let parsed;
    try {
      parsed = new URL(authorizeUrl);
    } catch {
      throw new InvalidInputError("authorizeUrl must be an absolute URL");
    }
    if (parsed.protocol !== "https:") throw new InvalidInputError("authorizeUrl must use HTTPS");
    if (typeof fetchImpl !== "function") throw new InvalidInputError("An injected authorization fetch implementation is required");
    if (!installationIdentity?.installationId || typeof installationIdentity.signMessage !== "function") throw new InvalidInputError("A proxy-local Ed25519 installation identity is required");
    if (!isCanonicalSha256(policyHash)) throw new InvalidInputError("policyHash must be a lowercase SHA-256 hex digest");
    this.#authorizeUrl = parsed.toString();
    this.#fetchImpl = fetchImpl;
    this.#installationIdentity = installationIdentity;
    this.#keyset = normalizeReceiptKeyset({ receiptKeyset, receiptPublicJwk, receiptKeyId });
    this.#policyHash = policyHash;
    this.#payment = payment === undefined ? null : paymentConfig(payment);
    this.#clock = clock;
    Object.freeze(this);
  }

  callHash(call) {
    return hashGuardCall(call);
  }

  async authorize({ call: rawCall, idempotencyKey, deadlineAt }) {
    const call = normalizeGuardCall(rawCall);
    const callHash = hashGuardCall(call);
    const request = createSignedGuardRequest({
      installationIdentity: this.#installationIdentity,
      idempotencyKey,
      call,
      issuedAt: this.#clock(),
    });
    const deadline = deadlineSignal(deadlineAt, this.#clock, this.#payment?.timeoutMs ?? MAX_AUTHORIZATION_TIMEOUT_MS);
    let paymentProof = null;
    try {
      const requestInit = {
        method: "POST",
        headers: { accept: "application/json", "content-type": "application/json" },
        body: canonicalBytes(request),
        redirect: "error",
        signal: deadline.signal,
      };
      let response = await withinDeadline(() => this.#fetchImpl(this.#authorizeUrl, requestInit), deadline);
      if (!response || typeof response.status !== "number" || typeof response.arrayBuffer !== "function") throw new AuthorizationServiceError("Injected authorization fetch returned an invalid response");
      if (response.status === 402) {
        if (!this.#payment) throw new PaymentPolicyError("Authorization requires x402 payment but no local payer is configured");
        const expectedAmount = expectedPaymentAmount(call);
        const paymentAttempt = createBudgetedPaymentAttempt(this.#payment, {
          installationId: this.#installationIdentity.installationId,
          idempotencyKey,
          callSha256: callHash,
          amountAtomic: expectedAmount,
        });
        const paymentRequiredHeader = response.headers?.get?.("payment-required");
        if (typeof paymentRequiredHeader !== "string" || paymentRequiredHeader.length < 1) {
          throw new PaymentPolicyError("HTTP 402 response omitted PAYMENT-REQUIRED");
        }
        if (paymentRequiredHeader.length > PAYMENT_REQUIRED_HEADER_LIMIT) {
          throw new PaymentPolicyError(`PAYMENT-REQUIRED exceeds ${PAYMENT_REQUIRED_HEADER_LIMIT} characters`);
        }
        let paymentRequired;
        try {
          paymentRequired = paymentAttempt.httpClient.getPaymentRequiredResponse((name) => response.headers.get(name));
        } catch (cause) {
          throw new PaymentPolicyError("PAYMENT-REQUIRED is not a valid x402 challenge", { cause: cause.message });
        }
        assertExactPaymentRequired(paymentRequired, { authorizeUrl: this.#authorizeUrl, call, payment: this.#payment });
        response.body?.cancel?.().catch(() => {});
        if (deadline.signal.aborted) throw deadline.signal.reason ?? new DeadlineExceededError();
        let paymentPayload;
        try {
          paymentPayload = await withinDeadline(() => paymentAttempt.client.createPaymentPayload(paymentRequired), deadline);
        } catch (cause) {
          await paymentAttempt.releaseIfDefinitelyUntransmitted();
          if (cause instanceof DeadlineExceededError || cause instanceof PaymentPolicyError || cause instanceof LocalStateError) throw cause;
          throw new AuthorizationServiceError("Unable to create the exact x402 payment payload", { cause });
        }
        let paymentHeaders;
        try {
          paymentHeaders = paymentAttempt.httpClient.encodePaymentSignatureHeader(paymentPayload);
        } catch (cause) {
          await paymentAttempt.releaseIfDefinitelyUntransmitted();
          throw new AuthorizationServiceError("Unable to encode the exact x402 payment payload", { cause });
        }
        if (typeof paymentHeaders["PAYMENT-SIGNATURE"] !== "string" && typeof paymentHeaders["payment-signature"] !== "string") {
          await paymentAttempt.releaseIfDefinitelyUntransmitted();
          throw new AuthorizationServiceError("x402 client did not produce a v2 PAYMENT-SIGNATURE header");
        }
        if (Object.keys(paymentHeaders).some((name) => name.toLowerCase() === "x-payment")) {
          await paymentAttempt.releaseIfDefinitelyUntransmitted();
          throw new AuthorizationServiceError("x402 client attempted a legacy payment header");
        }
        await paymentAttempt.markTransmitted();
        response = await withinDeadline(() => this.#fetchImpl(this.#authorizeUrl, {
          ...requestInit,
          headers: { ...requestInit.headers, ...paymentHeaders },
        }), deadline);
        if (!response || typeof response.status !== "number" || typeof response.arrayBuffer !== "function") throw new AuthorizationServiceError("Injected authorization fetch returned an invalid paid response");
        if (response.status === 402) throw new AuthorizationServiceError("Authorization remained payment-required after the single permitted x402 retry");
        paymentProof = settlementProof(response, {
          payment: { ...this.#payment, httpClient: paymentAttempt.httpClient },
          paymentPayload,
          expectedAmount,
        });
        await paymentAttempt.commitSettlement(paymentProof.transaction);
      }
      if (response.status < 200 || response.status >= 300) throw new AuthorizationServiceError(`Authorization service returned HTTP ${response.status}`);
      const envelope = await withinDeadline(() => boundedJsonResponse(response), deadline);
      const verified = verifyGuardAuthorizationEnvelope(envelope, { keyset: this.#keyset, now: this.#clock() });
      const { receipt } = verified;
      const expected = {
        installation_id: this.#installationIdentity.installationId,
        idempotency_key: idempotencyKey,
        connector_id: call.connector_id,
        kind: call.kind,
        policy_sha256: this.#policyHash,
        call_sha256: callHash,
      };
      for (const [field, value] of Object.entries(expected)) {
        if (receipt[field] !== value) throw new ReceiptVerificationError(`Receipt ${field} does not match the exact guard request`);
      }
      return Object.freeze({ request, call, callHash, envelope, paymentProof, ...verified });
    } catch (cause) {
      if (cause instanceof ReceiptVerificationError || cause instanceof AuthorizationServiceError || cause instanceof PaymentPolicyError || cause instanceof ResponseLimitError || cause instanceof LocalStateError) throw cause;
      if (deadline.signal.aborted || cause?.name === "AbortError") throw new DeadlineExceededError("Authorization service did not respond before the enforcement deadline", { cause });
      throw new AuthorizationServiceError("Authorization service request failed", { cause });
    } finally {
      deadline.clear();
    }
  }

  assertReceiptFresh(receipt, now = this.#clock()) {
    if (Date.parse(receipt.expires_at) <= now) throw new ReceiptVerificationError("Receipt expired before forwarding began");
  }
}

Object.freeze(RemoteAuthorizer.prototype);
