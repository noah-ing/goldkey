#!/usr/bin/env node

const RELEASE_BASE_URL = "{{GOLDKEY_PUBLIC_ORIGIN}}";

function fail(message) {
  throw new Error(message);
}

export function normalizeBaseUrl(value) {
  if (typeof value !== "string" || value.includes("{{")) {
    fail("GoldKey public origin is not configured; set GOLDKEY_API_URL to the live HTTPS Worker URL");
  }
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
    fail("GOLDKEY_API_URL must be a credential-free HTTPS origin");
  }
  if (url.pathname !== "/") fail("GOLDKEY_API_URL must not contain a path");
  return url.origin;
}

function baseUrl() {
  return normalizeBaseUrl(process.env.GOLDKEY_API_URL || RELEASE_BASE_URL);
}

function parseFlags(argv) {
  const flags = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) fail(`Unexpected argument: ${item}`);
    const key = item.slice(2);
    if (key === "authorized") {
      flags.set(key, true);
      continue;
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) fail(`Missing value for --${key}`);
    flags.set(key, value);
    index += 1;
  }
  return flags;
}

function required(flags, name) {
  const value = flags.get(name);
  if (value === undefined || value === "") fail(`--${name} is required`);
  return value;
}

function integerFlag(flags, name, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const raw = required(flags, name);
  if (!/^\d+$/.test(raw)) fail(`--${name} must be an integer`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) fail(`--${name} is out of range`);
  return value;
}

function jsonFlag(flags, name) {
  const raw = required(flags, name);
  try {
    const parsed = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) fail(`--${name} must be a JSON object`);
    return parsed;
  } catch (error) {
    if (error.message.includes(`--${name}`)) throw error;
    fail(`--${name} must be valid JSON`);
  }
}

async function request(path, { method = "GET", body, token, headers = {} } = {}) {
  const response = await fetch(`${baseUrl()}${path}`, {
    method,
    redirect: "error",
    headers: {
      accept: "application/json",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let payload;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    fail(`GoldKey returned non-JSON HTTP ${response.status}`);
  }
  if (!response.ok) {
    const code = payload?.error?.code || "request_failed";
    const message = payload?.error?.message || `HTTP ${response.status}`;
    fail(`${code}: ${message}`);
  }
  return payload;
}

async function paymentProbe(tool, input) {
  const response = await fetch(`${baseUrl()}/v1/paygo/execute`, {
    method: "POST",
    redirect: "error",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({ tool, input }),
  });
  const text = await response.text();
  let body;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text || null;
  }
  if (response.status !== 402) {
    if (response.ok) fail("Paygo executed without an x402 payment challenge; no payment was authorized");
    const code = body?.error?.code || "paygo_probe_failed";
    const message = body?.error?.message || `HTTP ${response.status}`;
    fail(`${code}: ${message}`);
  }
  const paymentRequired = response.headers.get("payment-required");
  if (!paymentRequired) fail("HTTP 402 response omitted the PAYMENT-REQUIRED header");
  return { http_status: 402, payment_required: paymentRequired, body };
}

function accessToken() {
  const value = process.env.GOLDKEY_ACCESS_TOKEN;
  if (!value) fail("Set GOLDKEY_ACCESS_TOKEN through the agent secret store for this authenticated command");
  return value;
}

function quoteBody(flags) {
  const body = {
    forecast_calls: integerFlag(flags, "forecast", { max: 10_000_000 }),
    pass_purchase_budget_usdc: flags.get("budget") || "50.00",
    switching_cost_usdc: flags.get("switching-cost") || "0.00",
    risk_reserve_usdc: flags.get("risk-reserve") || "0.00",
    purchase_authority: flags.get("authorized") === true,
  };
  if (flags.has("wallet")) body.wallet = flags.get("wallet");
  return body;
}

const help = `GoldKey client

Commands:
  offer
  catalog
  demo
  openapi
  quote --forecast N [--wallet 0x...] [--budget 50.00] [--switching-cost 0.00] [--risk-reserve 0.00] [--authorized]
  renew --token-id N --forecast N [--wallet 0x...] [--switching-cost 0.00] [--risk-reserve 0.00] [--authorized]
  challenge --token-id N --wallet 0x...
  verify --challenge-id UUID --signature 0x...
  quota
  tool --name TOOL --idempotency KEY --input JSON_OBJECT
  keys-list
  key-issue --body JSON_OBJECT
  key-revoke --id KEY_ID
  keys-revoke-all
  paygo-probe --name TOOL --input JSON_OBJECT
  self-test

Set GOLDKEY_API_URL to the live HTTPS Worker URL until the release URL is embedded.
Inject authenticated credentials through GOLDKEY_ACCESS_TOKEN; never pass them as arguments.`;

export async function run(argv) {
  const [command, ...rest] = argv;
  const flags = parseFlags(rest);
  if (command === "offer") return request("/.well-known/goldkey.json");
  if (command === "catalog") return request("/v1/catalog");
  if (command === "demo") return request("/v1/demo");
  if (command === "openapi") return request("/openapi.json");
  if (command === "quote") return request("/v1/commerce/respond", { method: "POST", body: quoteBody(flags) });
  if (command === "renew") {
    const body = {
      token_id: required(flags, "token-id"),
      forecast_calls: integerFlag(flags, "forecast", { max: 10_000_000 }),
      switching_cost_usdc: flags.get("switching-cost") || "0.00",
      risk_reserve_usdc: flags.get("risk-reserve") || "0.00",
      purchase_authority: flags.get("authorized") === true,
    };
    if (flags.has("wallet")) body.wallet = flags.get("wallet");
    return request("/v1/renewal/quote", {
      method: "POST",
      body,
    });
  }
  if (command === "challenge") {
    return request("/v1/auth/challenge", {
      method: "POST",
      body: { token_id: required(flags, "token-id"), wallet: required(flags, "wallet") },
    });
  }
  if (command === "verify") {
    return request("/v1/auth/verify", {
      method: "POST",
      body: { challenge_id: required(flags, "challenge-id"), signature: required(flags, "signature") },
    });
  }
  if (command === "quota") return request("/v1/quota", { token: accessToken() });
  if (command === "tool") {
    return request(`/v1/tools/${encodeURIComponent(required(flags, "name"))}`, {
      method: "POST",
      token: accessToken(),
      headers: { "idempotency-key": required(flags, "idempotency") },
      body: jsonFlag(flags, "input"),
    });
  }
  if (command === "keys-list") return request("/v1/keys", { token: accessToken() });
  if (command === "key-issue") {
    return request("/v1/keys", { method: "POST", token: accessToken(), body: jsonFlag(flags, "body") });
  }
  if (command === "key-revoke") {
    return request(`/v1/keys/${encodeURIComponent(required(flags, "id"))}`, { method: "DELETE", token: accessToken() });
  }
  if (command === "keys-revoke-all") return request("/v1/keys", { method: "DELETE", token: accessToken() });
  if (command === "paygo-probe") return paymentProbe(required(flags, "name"), jsonFlag(flags, "input"));
  if (command === "self-test") {
    if (normalizeBaseUrl("https://goldkey.example") !== "https://goldkey.example") fail("origin normalization failed");
    const sample = quoteBody(new Map([["forecast", "7200"], ["budget", "50.00"]]));
    if (sample.forecast_calls !== 7200 || sample.purchase_authority !== false) fail("quote construction failed");
    return { ok: true };
  }
  if (!command || command === "help" || command === "--help") return { help };
  fail(`Unknown command: ${command}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  run(process.argv.slice(2))
    .then((result) => {
      if (result?.help) process.stdout.write(`${result.help}\n`);
      else process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    })
    .catch((error) => {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 1;
    });
}
