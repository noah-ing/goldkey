import { getAddress, isAddress } from "viem";
import { EdgeError, assert } from "./errors.mjs";

function positiveInteger(value, name) {
  const parsed = Number(value);
  assert(Number.isSafeInteger(parsed) && parsed > 0, 503, "edge_not_configured", `${name} must be a positive integer`);
  return parsed;
}

function address(value, name) {
  assert(typeof value === "string" && isAddress(value), 503, "edge_not_configured", `${name} must be an EVM address`);
  const parsed = getAddress(value);
  assert(parsed !== "0x0000000000000000000000000000000000000000", 503, "edge_not_configured", `${name} must not be the zero address`);
  return parsed;
}

function httpsUrl(value, name, { originOnly = false } = {}) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new EdgeError(503, "edge_not_configured", `${name} must be an absolute URL`);
  }
  assert(parsed.protocol === "https:", 503, "edge_not_configured", `${name} must use HTTPS`);
  assert(!parsed.username && !parsed.password, 503, "edge_not_configured", `${name} must not contain credentials`);
  if (originOnly) {
    assert(parsed.pathname === "/" && !parsed.search && !parsed.hash, 503, "edge_not_configured", `${name} must be an origin without a path, query, or fragment`);
  }
  return parsed;
}

export function publicOrigin(request, env) {
  const derived = new URL(request.url).origin;
  if (!env.PUBLIC_ORIGIN) return derived;
  return httpsUrl(env.PUBLIC_ORIGIN, "PUBLIC_ORIGIN", { originOnly: true }).origin;
}

export function commerceConfig(request, env) {
  const termsHash = String(env.TERMS_HASH ?? "");
  assert(/^0x[0-9a-fA-F]{64}$/.test(termsHash), 503, "edge_not_configured", "TERMS_HASH must be a bytes32 hex value");
  assert(!/^0x0{64}$/i.test(termsHash), 503, "edge_not_configured", "TERMS_HASH must not be zero");
  return Object.freeze({
    publicOrigin: publicOrigin(request, env),
    chainId: positiveInteger(env.CHAIN_ID, "CHAIN_ID"),
    rpcUrl: httpsUrl(env.RPC_URL, "RPC_URL").toString(),
    contractAddress: address(env.GOLDKEY_CONTRACT, "GOLDKEY_CONTRACT"),
    usdcAddress: address(env.USDC_ADDRESS, "USDC_ADDRESS"),
    treasuryAddress: address(env.TREASURY_ADDRESS, "TREASURY_ADDRESS"),
    expectedTermsHash: termsHash.toLowerCase(),
    callsPerTerm: 10_000,
    termDays: 365,
  });
}

export function originUrl(env) {
  assert(env.ORIGIN_API, 503, "origin_not_configured", "The stateful utility origin is not configured");
  return httpsUrl(env.ORIGIN_API, "ORIGIN_API", { originOnly: true });
}

export function isGuardEnabled(env) {
  return env.GUARD_ENABLED === "true";
}

export function isCommerceConfigured(request, env) {
  try {
    commerceConfig(request, env);
    return true;
  } catch {
    return false;
  }
}
