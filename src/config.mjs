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

export function loadConfig(overrides = {}) {
  const nodeEnv = overrides.nodeEnv ?? process.env.NODE_ENV ?? "development";
  const x402Enabled = overrides.x402Enabled ?? boolean("X402_ENABLED", false);
  const devAuthBypass = overrides.devAuthBypass ?? boolean("DEV_AUTH_BYPASS", false);
  if (nodeEnv === "production" && devAuthBypass) throw new Error("DEV_AUTH_BYPASS cannot be enabled in production");

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
  }

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
