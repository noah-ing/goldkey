#!/usr/bin/env node

import { spawnSync } from "node:child_process";

const ORIGIN = "https://goldkey-edge-sepolia.noah-ing.workers.dev";
const OWNER = "0xd6b7E00FcD46966676F554fE0455BfF739e85b1b";
const TOKEN_ID = "1";
const CAST_BIN = "/Users/noah-ing/.foundry/bin/cast";
const KEYSTORE_ACCOUNT = process.env.GOLDKEY_DEPLOYER_ACCOUNT || "goldkey-deployer";
const IDEMPOTENCY_KEY = "acceptance.token1.term1.epoch0.urlcheck.v1";
const TOOL_INPUT = Object.freeze({ url: "https://example.com" });

function check(condition, message, details) {
  if (!condition) {
    const suffix = details === undefined ? "" : `: ${JSON.stringify(details)}`;
    throw new Error(`${message}${suffix}`);
  }
}

async function request(path, { method = "GET", body, token, headers = {} } = {}) {
  const response = await fetch(`${ORIGIN}${path}`, {
    method,
    redirect: "error",
    signal: AbortSignal.timeout(120_000),
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
    throw new Error(`${path} returned non-JSON HTTP ${response.status}`);
  }
  if (!response.ok) {
    const code = payload?.error?.code ?? "request_failed";
    const message = payload?.error?.message ?? `HTTP ${response.status}`;
    throw new Error(`${path} failed with ${code}: ${message}`);
  }
  return payload;
}

function signMessage(message) {
  check(typeof message === "string" && message.length > 0, "challenge message is missing");
  const result = spawnSync(CAST_BIN, ["wallet", "sign", "--account", KEYSTORE_ACCOUNT, message], {
    encoding: "utf8",
    stdio: ["inherit", "pipe", "inherit"],
  });
  check(result.error === undefined, "could not start cast wallet sign", result.error?.message);
  check(result.status === 0, "cast wallet sign failed", { status: result.status, signal: result.signal });
  const signature = result.stdout.trim();
  check(/^0x[0-9a-fA-F]{130}$/.test(signature), "cast returned an invalid Ethereum signature");
  return signature;
}

async function main() {
  const challenge = await request("/v1/auth/challenge", {
    method: "POST",
    body: { token_id: TOKEN_ID, wallet: OWNER },
  });
  check(typeof challenge.challenge_id === "string", "challenge ID is missing");
  check(challenge.message.includes("ownership epoch 0"), "challenge ownership epoch mismatch");
  check(challenge.message.includes(`/${TOKEN_ID}?ownership_epoch=0`), "challenge resource mismatch");

  process.stdout.write("Challenge verified. Enter the encrypted keystore password to sign it.\n");
  const signature = signMessage(challenge.message);
  const session = await request("/v1/auth/verify", {
    method: "POST",
    body: { challenge_id: challenge.challenge_id, signature },
  });
  check(typeof session.access_token === "string" && session.access_token.startsWith("gks_"), "session token is missing");
  check(session.goldkey?.tokenId === TOKEN_ID, "verified token ID mismatch", session.goldkey);
  check(session.goldkey?.term === "1", "verified term mismatch", session.goldkey);
  check(session.goldkey?.ownershipEpoch === "0", "verified ownership epoch mismatch", session.goldkey);
  check(session.goldkey?.active === true, "verified pass is not active", session.goldkey);

  const token = session.access_token;
  const quotaBefore = await request("/v1/quota", { token });
  check(quotaBefore.token_id === TOKEN_ID && quotaBefore.term === "1", "initial quota identity mismatch", quotaBefore);
  check(quotaBefore.allowance === 10_000, "initial quota allowance mismatch", quotaBefore);
  check(Number.isSafeInteger(quotaBefore.used), "initial quota usage is invalid", quotaBefore);

  const toolPath = "/v1/tools/security.url_check";
  const toolHeaders = { "idempotency-key": IDEMPOTENCY_KEY };
  const first = await request(toolPath, {
    method: "POST",
    body: TOOL_INPUT,
    token,
    headers: toolHeaders,
  });
  check(first.tool === "security.url_check", "tool identity mismatch", first);
  check(first.result?.verdict === "requires_dns_resolution", "unexpected URL-check verdict", first.result);
  check(first.quota?.charged === true, "first call was not quota-accounted", first.quota);
  check(first.quota.allowance === 10_000, "first call allowance mismatch", first.quota);
  const expectedUsed = first.idempotent_replay === true ? quotaBefore.used : quotaBefore.used + 1;
  check(first.quota.used === expectedUsed, "first call quota delta mismatch", { quotaBefore, first: first.quota, replay: first.idempotent_replay });

  const replay = await request(toolPath, {
    method: "POST",
    body: TOOL_INPUT,
    token,
    headers: toolHeaders,
  });
  check(replay.idempotent_replay === true, "exact retry was not identified as an idempotent replay", replay);
  check(replay.request_id === first.request_id, "idempotent replay request ID changed", { first: first.request_id, replay: replay.request_id });
  check(replay.quota?.used === first.quota.used, "idempotent replay consumed quota", { first: first.quota, replay: replay.quota });
  check(replay.quota?.remaining === first.quota.remaining, "idempotent replay changed remaining quota", { first: first.quota, replay: replay.quota });

  const quotaAfter = await request("/v1/quota", { token });
  check(quotaAfter.used === first.quota.used, "final quota does not match the accounted call", { first: first.quota, quotaAfter });
  check(quotaAfter.remaining === 10_000 - quotaAfter.used, "final remaining quota mismatch", quotaAfter);

  process.stdout.write(`${JSON.stringify({
    ok: true,
    token_id: TOKEN_ID,
    term: session.goldkey.term,
    ownership_epoch: session.goldkey.ownershipEpoch,
    owner: session.goldkey.owner,
    authentication: "passed",
    tool: first.tool,
    verdict: first.result.verdict,
    idempotency_key: IDEMPOTENCY_KEY,
    exact_retry_was_replay: replay.idempotent_replay,
    quota_before_used: quotaBefore.used,
    quota_after_used: quotaAfter.used,
    quota_remaining: quotaAfter.remaining,
    access_token_printed_or_persisted: false,
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`SEPOLIA AUTH ACCEPTANCE FAILED: ${error.message}\n`);
  process.exitCode = 1;
});
