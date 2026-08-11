import { canonicalize, hashCanonical } from "./canonical.mjs";
import { ServiceError, assert } from "./errors.mjs";
import { getAddress, isAddressEqual } from "viem";

export const GUARD_RECONCILED_COMMIT_SCHEMA = "goldkey.guard-reconciled-commit.v1";
export const BASE_MAINNET_NETWORK = "eip155:8453";
export const BASE_MAINNET_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

const PAYMENT_PATHS = Object.freeze({
  "/v1/guard/paygo/authorize/network": "guardNetworkPriceUsd",
  "/v1/guard/paygo/authorize/evm": "guardEvmPriceUsd",
});
const TX_HASH_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const ATOMIC_PATTERN = /^(0|[1-9][0-9]{0,77})$/;
const BYTES32_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const ECDSA_SIGNATURE_PATTERN = /^0x[0-9a-fA-F]{130}$/;
const MAX_PAYMENT_PAYLOAD_BYTES = 64 * 1024;

function exactKeys(value, allowed, name) {
  assert(value && typeof value === "object" && !Array.isArray(value), 400, "invalid_guard_payment_proof", `${name} must be an object`);
  const extras = Object.keys(value).filter((key) => !allowed.has(key));
  assert(extras.length === 0, 400, "invalid_guard_payment_proof", `${name} contains unsupported fields`, { fields: extras.sort() });
}

function canonicalAddress(value, name) {
  try {
    return getAddress(value);
  } catch {
    throw new ServiceError(400, "invalid_guard_payment_proof", `${name} must be an EVM address`);
  }
}

function canonicalAtomic(value, name) {
  assert(typeof value === "string" && ATOMIC_PATTERN.test(value), 400, "invalid_guard_payment_proof", `${name} must be a canonical atomic-unit integer`);
  return value;
}

function usdToUsdcAtomic(value, name) {
  assert(typeof value === "string" && /^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,6})?$/.test(value), 500, "guard_price_invalid", `${name} must be a positive USD amount with at most six decimals`);
  const [whole, fraction = ""] = value.split(".");
  const atomic = BigInt(whole) * 1_000_000n + BigInt(fraction.padEnd(6, "0"));
  assert(atomic > 0n, 500, "guard_price_invalid", `${name} must be greater than zero`);
  return atomic.toString();
}

function expectedPayment(config, path) {
  const priceField = PAYMENT_PATHS[path];
  assert(priceField, 500, "guard_payment_path_invalid", "Guard payment path is not eligible for reconciliation");
  assert(config?.chainId === 8453, 500, "guard_payment_network_invalid", "Guard payment reconciliation is restricted to Base mainnet");
  assert(
    isAddressEqual(canonicalAddress(config.usdcAddress, "USDC_ADDRESS"), BASE_MAINNET_USDC),
    500,
    "guard_payment_asset_invalid",
    "Guard payment reconciliation requires canonical Base mainnet USDC",
  );
  return Object.freeze({
    network: BASE_MAINNET_NETWORK,
    asset: getAddress(BASE_MAINNET_USDC),
    amount: usdToUsdcAtomic(config[priceField], priceField),
    payTo: canonicalAddress(config.treasuryAddress, "TREASURY_ADDRESS"),
    resource: `${config.publicOrigin}${path}`,
  });
}

/**
 * Validate the exact v2 Base-USDC EIP-3009 payload already verified by x402.
 * The full payload is hashed, while a second globally unique identity excludes
 * the unsigned resource wrapper so one authorization nonce cannot be rebound to
 * another resource or Guard execution.
 */
export function guardPaymentBinding(rawPayload, { config, path, requirements } = {}) {
  const expected = expectedPayment(config, path);
  exactKeys(rawPayload, new Set(["x402Version", "resource", "accepted", "payload", "extensions"]), "payment payload");
  assert(rawPayload.x402Version === 2, 400, "invalid_guard_payment_proof", "Guard payments require x402 v2");
  exactKeys(rawPayload.resource, new Set(["url", "description", "mimeType", "serviceName", "tags", "iconUrl"]), "payment resource");
  assert(rawPayload.resource.url === expected.resource, 409, "guard_payment_resource_mismatch", "Payment resource does not match this Guard authorization route");

  exactKeys(rawPayload.accepted, new Set(["scheme", "network", "asset", "amount", "payTo", "maxTimeoutSeconds", "extra"]), "accepted payment requirements");
  const accepted = rawPayload.accepted;
  assert(accepted.scheme === "exact", 400, "invalid_guard_payment_proof", "Guard payments require the exact scheme");
  assert(accepted.network === expected.network, 409, "guard_payment_network_mismatch", "Payment network is not Base mainnet");
  assert(isAddressEqual(canonicalAddress(accepted.asset, "payment asset"), expected.asset), 409, "guard_payment_asset_mismatch", "Payment asset is not canonical Base USDC");
  assert(canonicalAtomic(accepted.amount, "payment amount") === expected.amount, 409, "guard_payment_amount_mismatch", "Payment amount does not match the Guard route price");
  assert(isAddressEqual(canonicalAddress(accepted.payTo, "payment recipient"), expected.payTo), 409, "guard_payment_recipient_mismatch", "Payment recipient does not match the configured treasury");
  assert(accepted.maxTimeoutSeconds === 30, 409, "guard_payment_timeout_mismatch", "Guard payment timeout must be exactly 30 seconds");
  exactKeys(accepted.extra, new Set(["name", "version"]), "accepted payment extra");
  assert(accepted.extra.name === "USD Coin" && accepted.extra.version === "2", 409, "guard_payment_domain_mismatch", "Payment EIP-712 domain does not match canonical Base USDC");
  if (requirements !== undefined) {
    assert(canonicalize(requirements) === canonicalize(accepted), 409, "guard_payment_requirements_mismatch", "Settled payment requirements differ from the verified payload");
  }

  exactKeys(rawPayload.payload, new Set(["authorization", "signature"]), "EIP-3009 payment payload");
  exactKeys(rawPayload.payload.authorization, new Set(["from", "to", "value", "validAfter", "validBefore", "nonce"]), "EIP-3009 authorization");
  const authorization = rawPayload.payload.authorization;
  const from = canonicalAddress(authorization.from, "authorization.from");
  const to = canonicalAddress(authorization.to, "authorization.to");
  const value = canonicalAtomic(authorization.value, "authorization.value");
  const validAfter = canonicalAtomic(authorization.validAfter, "authorization.validAfter");
  const validBefore = canonicalAtomic(authorization.validBefore, "authorization.validBefore");
  assert(isAddressEqual(to, expected.payTo), 409, "guard_payment_recipient_mismatch", "EIP-3009 authorization recipient does not match the treasury");
  assert(value === expected.amount, 409, "guard_payment_amount_mismatch", "EIP-3009 authorization value does not match the Guard route price");
  assert(BigInt(validBefore) > BigInt(validAfter), 400, "invalid_guard_payment_proof", "EIP-3009 authorization validity window is empty");
  assert(typeof authorization.nonce === "string" && BYTES32_PATTERN.test(authorization.nonce), 400, "invalid_guard_payment_proof", "EIP-3009 nonce must be bytes32");
  assert(typeof rawPayload.payload.signature === "string" && ECDSA_SIGNATURE_PATTERN.test(rawPayload.payload.signature), 400, "invalid_guard_payment_proof", "Guard reconciliation currently requires a 65-byte EOA EIP-3009 signature");

  const canonical = canonicalize(rawPayload);
  assert(Buffer.byteLength(canonical) <= MAX_PAYMENT_PAYLOAD_BYTES, 413, "guard_payment_proof_too_large", `Canonical payment payload exceeds ${MAX_PAYMENT_PAYLOAD_BYTES} bytes`);
  const paymentSha256 = hashCanonical(JSON.parse(canonical)).sha256;
  const paymentIdentitySha256 = hashCanonical({
    schema: "goldkey.guard-payment-identity.v1",
    network: expected.network,
    asset: expected.asset.toLowerCase(),
    from: from.toLowerCase(),
    nonce: authorization.nonce.toLowerCase(),
  }).sha256;
  return Object.freeze({
    payment_sha256: paymentSha256,
    payment_identity_sha256: paymentIdentitySha256,
    payment_payload: Object.freeze(JSON.parse(canonical)),
    expected,
    authorization: Object.freeze({
      from,
      to,
      value,
      validAfter,
      validBefore,
      nonce: authorization.nonce.toLowerCase(),
      signature: rawPayload.payload.signature.toLowerCase(),
    }),
  });
}

export function validateGuardReconciledCommit(value) {
  exactKeys(value, new Set(["schema", "commit", "payment_proof"]), "reconciled commit");
  assert(value.schema === GUARD_RECONCILED_COMMIT_SCHEMA, 400, "invalid_guard_payment_proof", `schema must be ${GUARD_RECONCILED_COMMIT_SCHEMA}`);
  exactKeys(value.payment_proof, new Set(["transaction", "payment_payload"]), "payment_proof");
  assert(typeof value.payment_proof.transaction === "string" && TX_HASH_PATTERN.test(value.payment_proof.transaction), 400, "invalid_guard_payment_proof", "payment_proof.transaction must be a Base transaction hash");
  assert(value.commit && typeof value.commit === "object" && !Array.isArray(value.commit), 400, "invalid_guard_payment_proof", "commit must be an installation-signed Guard commit");
  assert(value.payment_proof.payment_payload && typeof value.payment_proof.payment_payload === "object" && !Array.isArray(value.payment_proof.payment_payload), 400, "invalid_guard_payment_proof", "payment_proof.payment_payload must be an x402 payment payload");
  return Object.freeze({
    schema: GUARD_RECONCILED_COMMIT_SCHEMA,
    commit: value.commit,
    payment_proof: Object.freeze({
      transaction: value.payment_proof.transaction.toLowerCase(),
      payment_payload: value.payment_proof.payment_payload,
    }),
  });
}
