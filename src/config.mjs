import path from "node:path";
import { getAddress, isAddress } from "viem";
import { validateCdpApiKeySecret } from "./cdp-auth.mjs";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

function boolean(name, fallback = false) {
  const value = process.env[name];
  if (value === undefined || value === "") return fallback;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${name} must be true or false`);
}

function integer(name, fallback) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`);
  return value;
}

function address(name, value, { allowZero = false } = {}) {
  if (!isAddress(value)) throw new Error(`${name} must be an EVM address`);
  const checksummed = getAddress(value);
  if (!allowZero && checksummed === ZERO_ADDRESS) throw new Error(`${name} must not be the zero address`);
  return checksummed;
}

function explicit(overrides, overrideName, environmentName) {
  return Object.hasOwn(overrides, overrideName) || Boolean(process.env[environmentName]);
}

function optionalText(name, value, { maxLength = 256 } = {}) {
  if (value === undefined || value === null || value === "") return "";
  if (typeof value !== "string" || value.length > maxLength || /[\r\n]/.test(value)) {
    throw new Error(`${name} must be a single-line string of at most ${maxLength} characters`);
  }
  return value;
}

function parsedHttpUrl(name, value, { requireHttps = false } = {}) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute URL`);
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error(`${name} must use http or https`);
  if (requireHttps && parsed.protocol !== "https:") throw new Error(`${name} must use https in production`);
  return parsed;
}

function parsedPostgresUrl(name, value, { requireTls = false } = {}) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute PostgreSQL URL`);
  }
  if (!["postgres:", "postgresql:"].includes(parsed.protocol)) throw new Error(`${name} must use postgres or postgresql`);
  if (!parsed.hostname || parsed.pathname === "/") throw new Error(`${name} must include a host and database name`);
  if (requireTls) {
    const sslMode = parsed.searchParams.get("sslmode")?.toLowerCase();
    if (!["require", "verify-ca", "verify-full"].includes(sslMode)) {
      throw new Error(`${name} must require TLS in production with sslmode=require, verify-ca, or verify-full`);
    }
  }
  return parsed;
}

function normalizedHostname(url) {
  return url.hostname.toLowerCase().replace(/\.$/, "");
}

function authHeaders() {
  const raw = process.env.X402_AUTH_HEADERS_JSON;
  if (!raw) return undefined;
  let headers;
  try {
    headers = JSON.parse(raw);
  } catch {
    throw new Error("X402_AUTH_HEADERS_JSON must be valid JSON");
  }
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) throw new Error("X402_AUTH_HEADERS_JSON must be an object");
  for (const [key, value] of Object.entries(headers)) {
    if (typeof value !== "string" || /[\r\n]/.test(key + value)) throw new Error("X402 auth headers must be single-line strings");
  }
  return headers;
}

function guardPreviousPublicKeys(override) {
  const raw = override ?? process.env.GUARD_RECEIPT_PREVIOUS_PUBLIC_KEYS_JSON ?? "";
  if (raw === "") return Object.freeze([]);
  let keys = raw;
  if (typeof raw === "string") {
    if (raw.length > 32_768) throw new Error("GUARD_RECEIPT_PREVIOUS_PUBLIC_KEYS_JSON is too large");
    try {
      keys = JSON.parse(raw);
    } catch {
      throw new Error("GUARD_RECEIPT_PREVIOUS_PUBLIC_KEYS_JSON must be valid JSON");
    }
  }
  if (!Array.isArray(keys) || keys.length > 31) {
    throw new Error("GUARD_RECEIPT_PREVIOUS_PUBLIC_KEYS_JSON must contain at most 31 public keys");
  }
  for (const key of keys) {
    if (!key || typeof key !== "object" || Array.isArray(key) || Object.hasOwn(key, "d")) {
      throw new Error("GUARD_RECEIPT_PREVIOUS_PUBLIC_KEYS_JSON must contain public-only JWKs");
    }
  }
  return Object.freeze(keys.map((key) => Object.freeze({ ...key })));
}

function parsedGuardAllowedOperatorWallets(override) {
  const values = Array.isArray(override)
    ? override
    : String(override ?? process.env.GUARD_ALLOWED_OPERATOR_WALLETS ?? "").split(",").map((value) => value.trim()).filter(Boolean);
  if (values.length > 100) throw new Error("GUARD_ALLOWED_OPERATOR_WALLETS must contain at most 100 addresses");
  const normalized = values.map((value) => address("GUARD_ALLOWED_OPERATOR_WALLETS", value).toLowerCase());
  if (new Set(normalized).size !== normalized.length) throw new Error("GUARD_ALLOWED_OPERATOR_WALLETS must not contain duplicates");
  return Object.freeze(normalized);
}

export function loadConfig(overrides = {}) {
  const nodeEnv = overrides.nodeEnv ?? process.env.NODE_ENV ?? "development";
  const x402Enabled = overrides.x402Enabled ?? boolean("X402_ENABLED", false);
  const guardEnabled = overrides.guardEnabled ?? boolean("GUARD_ENABLED", false);
  const pilotApplicationsEnabled = overrides.pilotApplicationsEnabled ?? boolean("PILOT_APPLICATIONS_ENABLED", false);
  const guardAllowedOperatorWallets = parsedGuardAllowedOperatorWallets(overrides.guardAllowedOperatorWallets);
  const devAuthBypass = overrides.devAuthBypass ?? boolean("DEV_AUTH_BYPASS", false);
  if (nodeEnv === "production" && devAuthBypass) throw new Error("DEV_AUTH_BYPASS cannot be enabled in production");
  if (guardEnabled && !x402Enabled) throw new Error("GUARD_ENABLED requires X402_ENABLED because Guard authorizations are premium paygo services");

  if (nodeEnv === "production") {
    const required = [
      ["chainId", "CHAIN_ID"],
      ["rpcUrl", "RPC_URL"],
      ["contractAddress", "GOLDKEY_CONTRACT"],
      ["usdcAddress", "USDC_ADDRESS"],
      ["treasuryAddress", "TREASURY_ADDRESS"],
    ];
    for (const [overrideName, environmentName] of required) {
      if (!explicit(overrides, overrideName, environmentName)) {
        throw new Error(`${environmentName} must be explicitly configured in production`);
      }
    }
    if (x402Enabled && !explicit(overrides, "x402FacilitatorUrl", "X402_FACILITATOR_URL")) {
      throw new Error("X402_FACILITATOR_URL must be explicitly configured in production when x402 is enabled");
    }
    if (!explicit(overrides, "databaseUrl", "DATABASE_URL") && !explicit(overrides, "databasePath", "DATABASE_PATH")) {
      throw new Error("DATABASE_URL or DATABASE_PATH must be explicitly configured in production");
    }
    if (guardEnabled) {
      if (!explicit(overrides, "guardReceiptKeyId", "GUARD_RECEIPT_KEY_ID")) {
        throw new Error("GUARD_RECEIPT_KEY_ID must be explicitly configured in production when Guard is enabled");
      }
      if (!explicit(overrides, "guardReceiptPrivateKey", "GUARD_RECEIPT_PRIVATE_KEY")) {
        throw new Error("GUARD_RECEIPT_PRIVATE_KEY must be explicitly configured in production when Guard is enabled");
      }
    }
  }
  if (guardEnabled && guardAllowedOperatorWallets.length === 0) throw new Error("GUARD_ENABLED requires at least one GUARD_ALLOWED_OPERATOR_WALLETS design-partner address");

  const publicOrigin = overrides.publicOrigin ?? process.env.PUBLIC_ORIGIN ?? process.env.RENDER_EXTERNAL_URL ?? "http://localhost:8402";
  const parsedOrigin = parsedHttpUrl("PUBLIC_ORIGIN", publicOrigin, { requireHttps: nodeEnv === "production" });

  const x402FacilitatorUrl = overrides.x402FacilitatorUrl ?? process.env.X402_FACILITATOR_URL ?? "https://x402.org/facilitator";
  const parsedFacilitator = parsedHttpUrl("X402_FACILITATOR_URL", x402FacilitatorUrl, { requireHttps: nodeEnv === "production" && x402Enabled });
  const chainId = overrides.chainId ?? integer("CHAIN_ID", 84532);
  const rpcUrl = overrides.rpcUrl ?? process.env.RPC_URL ?? "https://sepolia.base.org";
  parsedHttpUrl("RPC_URL", rpcUrl, { requireHttps: nodeEnv === "production" });
  if (nodeEnv === "production" && chainId === 84532) throw new Error("Base Sepolia chain 84532 is forbidden in production");
  const facilitatorHost = normalizedHostname(parsedFacilitator);
  if (nodeEnv === "production" && x402Enabled && (facilitatorHost === "x402.org" || facilitatorHost.endsWith(".x402.org"))) {
    throw new Error("x402.org is testnet-only and forbidden in production");
  }

  const databaseUrl = overrides.databaseUrl ?? process.env.DATABASE_URL ?? "";
  if (databaseUrl) parsedPostgresUrl("DATABASE_URL", databaseUrl, { requireTls: nodeEnv === "production" });

  const contractAddress = address(
    "GOLDKEY_CONTRACT",
    overrides.contractAddress ?? process.env.GOLDKEY_CONTRACT ?? ZERO_ADDRESS,
    { allowZero: nodeEnv !== "production" },
  );
  const usdcAddress = address(
    "USDC_ADDRESS",
    overrides.usdcAddress ?? process.env.USDC_ADDRESS ?? ZERO_ADDRESS,
    { allowZero: nodeEnv !== "production" },
  );
  const treasuryAddress = address(
    "TREASURY_ADDRESS",
    overrides.treasuryAddress ?? process.env.TREASURY_ADDRESS ?? ZERO_ADDRESS,
    { allowZero: nodeEnv !== "production" },
  );
  const x402AuthHeaders = overrides.x402AuthHeaders ?? authHeaders();
  const cdpApiKeyId = overrides.cdpApiKeyId ?? process.env.CDP_API_KEY_ID ?? "";
  const cdpApiKeySecret = overrides.cdpApiKeySecret ?? process.env.CDP_API_KEY_SECRET ?? "";
  if (Boolean(cdpApiKeyId) !== Boolean(cdpApiKeySecret)) throw new Error("CDP_API_KEY_ID and CDP_API_KEY_SECRET must be set together");
  if (cdpApiKeySecret) validateCdpApiKeySecret(cdpApiKeySecret);
  if (nodeEnv === "production" && x402Enabled && facilitatorHost === "api.cdp.coinbase.com" && !cdpApiKeyId && !x402AuthHeaders) {
    throw new Error("Production CDP x402 requires CDP credentials or explicit facilitator auth headers");
  }
  const devAuthToken = overrides.devAuthToken ?? process.env.DEV_AUTH_TOKEN ?? "";
  if (devAuthBypass && devAuthToken.length < 20) throw new Error("DEV_AUTH_TOKEN must be at least 20 characters when bypass is enabled");
  const guardReceiptKeyId = optionalText(
    "GUARD_RECEIPT_KEY_ID",
    overrides.guardReceiptKeyId ?? process.env.GUARD_RECEIPT_KEY_ID,
    { maxLength: 80 },
  );
  const guardReceiptPrivateKey = optionalText(
    "GUARD_RECEIPT_PRIVATE_KEY",
    overrides.guardReceiptPrivateKey ?? process.env.GUARD_RECEIPT_PRIVATE_KEY,
    { maxLength: 16_384 },
  );
  if (Boolean(guardReceiptKeyId) !== Boolean(guardReceiptPrivateKey)) {
    throw new Error("GUARD_RECEIPT_KEY_ID and GUARD_RECEIPT_PRIVATE_KEY must be set together");
  }
  const guardReceiptPreviousPublicKeys = guardPreviousPublicKeys(overrides.guardReceiptPreviousPublicKeys);
  const pilotAdminTokenSha256 = optionalText(
    "PILOT_ADMIN_TOKEN_SHA256",
    overrides.pilotAdminTokenSha256 ?? process.env.PILOT_ADMIN_TOKEN_SHA256,
    { maxLength: 64 },
  ).toLowerCase();
  const pilotAbuseSecret = optionalText(
    "PILOT_ABUSE_SECRET",
    overrides.pilotAbuseSecret ?? process.env.PILOT_ABUSE_SECRET,
    { maxLength: 512 },
  );
  const pilotEdgeSecret = optionalText(
    "PILOT_EDGE_SECRET",
    overrides.pilotEdgeSecret ?? process.env.PILOT_EDGE_SECRET,
    { maxLength: 512 },
  );
  if (pilotApplicationsEnabled) {
    if (!/^[0-9a-f]{64}$/.test(pilotAdminTokenSha256)) {
      throw new Error("PILOT_ADMIN_TOKEN_SHA256 must be a lowercase SHA-256 hex digest when pilot applications are enabled");
    }
    if (pilotAbuseSecret.length < 32) throw new Error("PILOT_ABUSE_SECRET must contain at least 32 characters when pilot applications are enabled");
    if (pilotEdgeSecret.length < 32) throw new Error("PILOT_EDGE_SECRET must contain at least 32 characters when pilot applications are enabled");
  }

  return Object.freeze({
    nodeEnv,
    port: overrides.port ?? integer("PORT", 8402),
    publicOrigin: parsedOrigin.origin,
    databaseUrl,
    databasePoolMax: overrides.databasePoolMax ?? integer("DATABASE_POOL_MAX", 5),
    databasePath: overrides.databasePath ?? path.resolve(process.env.DATABASE_PATH ?? "./data/goldkey.sqlite"),
    chainId,
    rpcUrl,
    contractAddress,
    usdcAddress,
    treasuryAddress,
    x402Enabled,
    guardEnabled,
    guardReceiptKeyId,
    guardReceiptPrivateKey,
    guardReceiptPreviousPublicKeys,
    guardAllowedOperatorWallets,
    pilotApplicationsEnabled,
    pilotAdminTokenSha256,
    pilotAbuseSecret,
    pilotEdgeSecret,
    pilotRetentionDays: overrides.pilotRetentionDays ?? integer("PILOT_RETENTION_DAYS", 90),
    guardAuthorizationTtlMs: 60_000,
    guardNetworkPriceUsd: "0.05",
    guardEvmPriceUsd: "0.10",
    x402FacilitatorUrl: parsedFacilitator.toString().replace(/\/+$/, ""),
    x402AuthHeaders,
    cdpApiKeyId,
    cdpApiKeySecret,
    devAuthBypass,
    devAuthToken,
    bodyLimit: "64kb",
    challengeTtlMs: 5 * 60 * 1000,
    sessionTtlMs: 15 * 60 * 1000,
    callsPerTerm: 10_000,
    termDays: 365,
  });
}

export { ZERO_ADDRESS };
