import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";
import { getAddress } from "viem";
import { createApp } from "../src/app.mjs";
import { createAuthService } from "../src/auth.mjs";
import { loadConfig } from "../src/config.mjs";
import { GoldKeyDatabase } from "../src/database.mjs";

const OWNER = getAddress("0x000000000000000000000000000000000000dEaD");
const PUBLIC_ORIGIN = "http://127.0.0.1:8402";

async function fixture(t, overrides = {}) {
  const config = loadConfig({
    nodeEnv: "test",
    port: 8402,
    publicOrigin: PUBLIC_ORIGIN,
    databasePath: ":memory:",
    chainId: 8453,
    rpcUrl: "http://unused",
    contractAddress: "0x0000000000000000000000000000000000000001",
    usdcAddress: "0x0000000000000000000000000000000000000002",
    treasuryAddress: "0x0000000000000000000000000000000000000003",
    x402Enabled: overrides.x402Enabled ?? false,
    devAuthBypass: true,
    devAuthToken: "test-owner-token-that-is-long",
  });
  let owner = OWNER;
  let ownershipEpoch = 0;
  let expiresAt = Date.now() + 86_400_000;
  const chain = {
    passState: async (tokenId) => ({ tokenId: String(tokenId), owner, term: "1", ownershipEpoch: String(ownershipEpoch), expiresAt, active: expiresAt > Date.now() }),
    verifyWalletMessage: async () => true,
    supplyState: async () => ({ totalMinted: "7", remaining: "9993", termsHash: "0xterms", termsUri: "http://example.test/terms", blockNumber: "100", mintPriceAtomic: "50000000", paymentToken: "0x0000000000000000000000000000000000000002", paymentTokenDecimals: 6, salesPaused: false }),
    purchaseTransactions: (_wallet, quantity) => [{ quantity: Number(quantity) }],
    renewalTransactions: (tokenId) => [{ tokenId: String(tokenId) }],
  };
  const db = new GoldKeyDatabase();
  const auth = createAuthService({ config, db, chain });
  const app = createApp({ config, db, chain, auth, x402Middleware: overrides.x402Middleware });
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(() => { server.close(); db.close(); });
  return {
    base,
    setOwner: (value) => { const next = getAddress(value); if (next !== owner) ownershipEpoch += 1; owner = next; },
    expire: () => { expiresAt = Date.now() - 1000; },
  };
}

async function json(response) {
  const body = await response.json();
  return { response, body };
}

test("public offer exposes the half-million cap and deterministic decision rule", async (t) => {
  const { base } = await fixture(t);
  const { response, body } = await json(await fetch(`${base}/.well-known/goldkey.json`));
  assert.equal(response.status, 200);
  assert.equal(body.economics.gross_primary_sale_cap_usdc, "500000.00");
  assert.equal(body.economics.break_even_calls_excluding_gas_and_switching_cost, 5000);
  assert.equal(body.contract.state.remaining, "9993");
});

test("owner calls are charged once and idempotent retries are free", async (t) => {
  const { base } = await fixture(t);
  const headers = { authorization: "Bearer test-owner-token-that-is-long", "x-goldkey-token-id": "1", "idempotency-key": "call-00000001", "content-type": "application/json" };
  const first = await json(await fetch(`${base}/v1/tools/json.canonicalize`, { method: "POST", headers, body: JSON.stringify({ value: { b: 2, a: 1 } }) }));
  assert.equal(first.response.status, 200);
  assert.equal(first.body.quota.used, 1);
  const replay = await json(await fetch(`${base}/v1/tools/json.canonicalize`, { method: "POST", headers, body: JSON.stringify({ value: { b: 2, a: 1 } }) }));
  assert.equal(replay.body.idempotent_replay, true);
  const invalid = await json(await fetch(`${base}/v1/tools/unknown.tool`, { method: "POST", headers: { ...headers, "idempotency-key": "call-00000002" }, body: JSON.stringify({ value: 1 }) }));
  assert.equal(invalid.response.status, 404);
  const quota = await json(await fetch(`${base}/v1/quota`, { headers: { authorization: headers.authorization, "x-goldkey-token-id": "1" } }));
  assert.equal(quota.body.used, 1);
});

test("owner can issue a capped child-agent key and transfer invalidates it", async (t) => {
  const { base, setOwner } = await fixture(t);
  const ownerHeaders = { authorization: "Bearer test-owner-token-that-is-long", "x-goldkey-token-id": "1", "content-type": "application/json" };
  const issued = await json(await fetch(`${base}/v1/keys`, { method: "POST", headers: ownerHeaders, body: JSON.stringify({ label: "swarm-worker", max_calls: 1, tools: ["security.prompt_scan"] }) }));
  assert.equal(issued.response.status, 201);
  const childHeaders = { authorization: `Bearer ${issued.body.access_key}`, "idempotency-key": "child-000001", "content-type": "application/json" };
  const call = await json(await fetch(`${base}/v1/tools/security.prompt_scan`, { method: "POST", headers: childHeaders, body: JSON.stringify({ text: "hello" }) }));
  assert.equal(call.response.status, 200);
  const deniedTool = await json(await fetch(`${base}/v1/tools/json.canonicalize`, { method: "POST", headers: { ...childHeaders, "idempotency-key": "child-000002" }, body: JSON.stringify({ value: 1 }) }));
  assert.equal(deniedTool.response.status, 403);
  setOwner("0x0000000000000000000000000000000000000004");
  const oldKey = await json(await fetch(`${base}/v1/quota`, { headers: { authorization: childHeaders.authorization } }));
  assert.equal(oldKey.response.status, 403);
  assert.equal(oldKey.body.error.code, "not_current_owner");
  setOwner(OWNER);
  const returnedKey = await json(await fetch(`${base}/v1/quota`, { headers: { authorization: childHeaders.authorization } }));
  assert.equal(returnedKey.response.status, 401);
  assert.equal(returnedKey.body.error.code, "stale_access_key");
});

test("wallet challenge is single-use and produces a usable owner session", async (t) => {
  const { base, setOwner } = await fixture(t);
  const challenge = await json(await fetch(`${base}/v1/auth/challenge`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ wallet: OWNER, token_id: "1" }) }));
  assert.equal(challenge.response.status, 200);
  const verifyRequest = async () => json(await fetch(`${base}/v1/auth/verify`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ challenge_id: challenge.body.challenge_id, signature: "0x01" }) }));
  const attempts = await Promise.all([verifyRequest(), verifyRequest()]);
  assert.deepEqual(attempts.map(({ response }) => response.status).sort(), [200, 409]);
  const verification = attempts.find(({ response }) => response.status === 200);
  const sessionQuota = await json(await fetch(`${base}/v1/quota`, { headers: { authorization: `Bearer ${verification.body.access_token}` } }));
  assert.equal(sessionQuota.response.status, 200);
  setOwner("0x0000000000000000000000000000000000000004");
  setOwner(OWNER);
  const staleSession = await json(await fetch(`${base}/v1/quota`, { headers: { authorization: `Bearer ${verification.body.access_token}` } }));
  assert.equal(staleSession.response.status, 401);
  assert.equal(staleSession.body.error.code, "stale_session");
});

test("bodyless authentication probes return field errors instead of internal errors", async (t) => {
  const { base } = await fixture(t);
  const challenge = await json(await fetch(`${base}/v1/auth/challenge`, { method: "POST" }));
  assert.equal(challenge.response.status, 400);
  assert.equal(challenge.body.error.code, "invalid_wallet");

  const verify = await json(await fetch(`${base}/v1/auth/verify`, { method: "POST" }));
  assert.equal(verify.response.status, 400);
  assert.equal(verify.body.error.code, "invalid_challenge");
});

test("commerce endpoint sells only above break-even and disabled paygo never leaks free calls", async (t) => {
  const { base } = await fixture(t);
  const quote = await json(await fetch(`${base}/v1/commerce/respond`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ forecast_calls: 7200 }) }));
  assert.equal(quote.response.status, 200);
  assert.equal(quote.body.recommendation, "BUY_1_KEY");
  assert.equal(quote.body.next_action, "PROVIDE_WALLET");
  assert.match(quote.body.sales_message, /Projected savings are 22\.00 USDC/);
  const paygo = await json(await fetch(`${base}/v1/paygo/execute`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ tool: "json.canonicalize", input: { value: 1 } }) }));
  assert.equal(paygo.response.status, 503);
  assert.equal(paygo.body.error.code, "paygo_disabled");
  const actionGate = await json(await fetch(`${base}/v1/action-gate`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: { name: "read account balance", effect: "read" } }) }));
  assert.equal(actionGate.response.status, 503);
  assert.equal(actionGate.body.error.code, "paygo_disabled");
});

test("x402 discovery probes and semantic work remain behind payment verification", async (t) => {
  let challenges = 0;
  const x402Middleware = (req, res, next) => {
    if (req.method !== "POST" || req.path !== "/v1/paygo/execute") return next();
    challenges += 1;
    res
      .status(402)
      .set("payment-required", Buffer.from(JSON.stringify({ x402Version: 2, resource: { url: `${PUBLIC_ORIGIN}/v1/paygo/execute` }, extensions: { bazaar: {} } })).toString("base64"))
      .json({});
  };
  const { base } = await fixture(t, { x402Enabled: true, x402Middleware });

  const probe = await fetch(`${base}/v1/paygo/execute`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
  });
  assert.equal(probe.status, 402);
  assert.ok(probe.headers.get("payment-required"));
  assert.equal(challenges, 1);

  const bodylessProbe = await fetch(`${base}/v1/paygo/execute`, { method: "POST" });
  assert.equal(bodylessProbe.status, 402);
  assert.ok(bodylessProbe.headers.get("payment-required"));
  assert.equal(challenges, 2);

  for (const paymentHeader of ["payment-signature", "x-payment"]) {
    const malformedPaid = await json(await fetch(`${base}/v1/paygo/execute`, {
      method: "POST",
      headers: { "content-type": "application/json", [paymentHeader]: "invalid-payment" },
      body: "{}",
    }));
    assert.equal(malformedPaid.response.status, 404);
    assert.equal(malformedPaid.body.error.code, "unknown_tool");
    assert.equal(malformedPaid.response.headers.get("payment-required"), null);
  }
  assert.equal(challenges, 2);

  for (const paymentHeader of ["payment-signature", "x-payment"]) {
    const malformedPaid = await json(await fetch(`${base}/v1/paygo/execute`, {
      method: "POST",
      headers: { [paymentHeader]: "invalid-payment" },
    }));
    assert.equal(malformedPaid.response.status, 400);
    assert.equal(malformedPaid.body.error.code, "invalid_input");
    assert.equal(malformedPaid.response.headers.get("payment-required"), null);
  }
  assert.equal(challenges, 2);

  const unknown = await json(await fetch(`${base}/v1/paygo/execute`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ tool: "unknown.tool", input: {} }),
  }));
  assert.equal(unknown.response.status, 404);
  assert.equal(unknown.body.error.code, "unknown_tool");
  assert.equal(challenges, 2);

  const malformedToolInput = await json(await fetch(`${base}/v1/paygo/execute`, {
    method: "POST",
    headers: { "content-type": "application/json", "payment-signature": "invalid-payment" },
    body: JSON.stringify({ tool: "security.url_check", input: { url: "not-an-absolute-url" } }),
  }));
  assert.equal(malformedToolInput.response.status, 402);
  assert.ok(malformedToolInput.response.headers.get("payment-required"));
  assert.equal(challenges, 3);

  const validUnpaid = await fetch(`${base}/v1/paygo/execute`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ tool: "json.canonicalize", input: { value: 1 } }),
  });
  assert.equal(validUnpaid.status, 402);
  assert.equal(challenges, 4);
});

test("dedicated Action Gate validates a bounded envelope before x402 and evaluates after verification", async (t) => {
  let middlewareCalls = 0;
  const x402Middleware = (req, res, next) => {
    if (req.method !== "POST" || req.path !== "/v1/action-gate") return next();
    middlewareCalls += 1;
    if (req.get("payment-signature") === "accepted") return next();
    res
      .status(402)
      .set("payment-required", Buffer.from(JSON.stringify({ x402Version: 2, resource: { url: `${PUBLIC_ORIGIN}/v1/action-gate` }, extensions: { bazaar: {} } })).toString("base64"))
      .json({});
  };
  const { base } = await fixture(t, { x402Enabled: true, x402Middleware });

  for (const probeOptions of [
    { method: "POST" },
    { method: "POST", headers: { "content-type": "application/json" }, body: "{}" },
  ]) {
    const probe = await fetch(`${base}/v1/action-gate`, probeOptions);
    assert.equal(probe.status, 402);
    const challenge = JSON.parse(Buffer.from(probe.headers.get("payment-required"), "base64").toString("utf8"));
    assert.equal(challenge.resource.url, `${PUBLIC_ORIGIN}/v1/action-gate`);
  }
  assert.equal(middlewareCalls, 2);

  for (const paymentHeader of ["payment-signature", "x-payment"]) {
    const malformed = await json(await fetch(`${base}/v1/action-gate`, {
      method: "POST",
      headers: { "content-type": "application/json", [paymentHeader]: "invalid-payment" },
      body: "{}",
    }));
    assert.equal(malformed.response.status, 400);
    assert.equal(malformed.body.error.code, "invalid_action_gate_input");
    assert.equal(malformed.response.headers.get("payment-required"), null);
  }

  const invalidComposite = await json(await fetch(`${base}/v1/action-gate`, {
    method: "POST",
    headers: { "content-type": "application/json", "payment-signature": "invalid-payment" },
    body: JSON.stringify({ action: { name: "store record", effect: "write" }, payload: { id: 1 } }),
  }));
  assert.equal(invalidComposite.response.status, 400);
  assert.equal(invalidComposite.body.error.code, "invalid_action_gate_input");

  const invalidUrl = await json(await fetch(`${base}/v1/action-gate`, {
    method: "POST",
    headers: { "content-type": "application/json", "payment-signature": "invalid-payment" },
    body: JSON.stringify({ action: { name: "fetch quote", effect: "network" }, url: "not-an-absolute-url" }),
  }));
  assert.equal(invalidUrl.response.status, 402);
  assert.ok(invalidUrl.response.headers.get("payment-required"));
  assert.equal(middlewareCalls, 3);

  const verifiedInvalidUrl = await json(await fetch(`${base}/v1/action-gate`, {
    method: "POST",
    headers: { "content-type": "application/json", "payment-signature": "accepted" },
    body: JSON.stringify({ action: { name: "fetch quote", effect: "network" }, url: "not-an-absolute-url" }),
  }));
  assert.equal(verifiedInvalidUrl.response.status, 400);
  assert.equal(verifiedInvalidUrl.body.error.code, "malformed_url");
  assert.equal(middlewareCalls, 4);

  const validInput = {
    action: { name: "submit approved vendor payment", effect: "payment" },
    spend: {
      proposal: { amount_atomic: "1000000", asset: "USDC", counterparty: "vendor-17" },
      mandate: {
        max_per_tx_atomic: "5000000",
        max_period_atomic: "20000000",
        spent_period_atomic: "2000000",
        allowed_assets: ["USDC"],
        allowed_counterparties: ["vendor-17"],
        expires_at: "2099-01-01T00:00:00.000Z",
      },
      now: "2026-01-01T00:00:00.000Z",
    },
  };
  const validUnpaid = await fetch(`${base}/v1/action-gate`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(validInput),
  });
  assert.equal(validUnpaid.status, 402);
  assert.equal(middlewareCalls, 5);

  const paid = await json(await fetch(`${base}/v1/action-gate`, {
    method: "POST",
    headers: { "content-type": "application/json", "payment-signature": "accepted" },
    body: JSON.stringify(validInput),
  }));
  assert.equal(paid.response.status, 200);
  assert.equal(middlewareCalls, 6);
  assert.equal(paid.body.tool, "action.gate");
  assert.equal(paid.body.result.decision, "ALLOW");
  assert.match(paid.body.result.receipt_sha256, /^[0-9a-f]{64}$/);
  assert.equal(paid.body.result.receipt_format, "goldkey-action-gate-v1");
  assert.equal(paid.body.result.receipt_canonicalization, "goldkey-c14n-v1");
  assert.equal(paid.body.result.receipt_hash_algorithm, "SHA-256");
  assert.deepEqual(paid.body.result.receipt_preimage_fields, ["receipt_format", "request_sha256", "decision", "reason_codes", "checks"]);
  assert.equal(paid.body.payment.charged_usdc, "0.01");
  assert.equal(Object.hasOwn(paid.body.result, "signature"), false);
});

test("Action Gate is first-class in OpenAPI and the fixed demo", async (t) => {
  const { base } = await fixture(t);
  const openapi = await json(await fetch(`${base}/openapi.json`));
  assert.equal(openapi.response.status, 200);
  const actionOperation = openapi.body.paths["/v1/action-gate"].post;
  assert.equal(actionOperation.operationId, "goldkey_action_gate_ai_agent_tool_call_preflight");
  assert.match(actionOperation.summary, /\$0\.01 AI-agent tool-call preflight/);
  assert.match(actionOperation.description, /not a cryptographic signature/);
  assert.deepEqual(actionOperation["x-payment-info"], {
    price: { mode: "fixed", currency: "USD", amount: "0.01" },
    protocols: [{ x402: {} }],
  });
  assert.deepEqual(openapi.body.components.schemas.ActionGateResponse.properties.result.properties.decision.enum, ["ALLOW", "REVIEW", "BLOCK"]);
  assert.deepEqual(openapi.body.components.schemas.ActionGateRequest.properties.action.required, ["name", "effect"]);

  const demo = await json(await fetch(`${base}/v1/demo`));
  const example = demo.body.examples.find(({ tool }) => tool === "action.gate");
  assert.equal(demo.body.free_fixed_examples, true);
  assert.equal(example.result.decision, "ALLOW");
  assert.match(example.result.receipt_sha256, /^[0-9a-f]{64}$/);
  assert.equal(example.result.receipt_canonicalization, "goldkey-c14n-v1");
});

test("terms, schema, and renewal quotes are machine-readable", async (t) => {
  const { base, expire } = await fixture(t);
  const terms = await fetch(`${base}/terms`);
  assert.equal(terms.status, 200);
  assert.match(await terms.text(), /50 USDC/);
  const schema = await json(await fetch(`${base}/schemas/commerce-response-v1.json`));
  assert.equal(schema.response.status, 200);
  assert.equal(schema.body.type, "object");

  const waiting = await json(await fetch(`${base}/v1/renewal/quote`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token_id: "1", forecast_calls: 7200 }) }));
  assert.equal(waiting.body.next_action, "WAIT_UNTIL_EXPIRY");
  expire();
  const ready = await json(await fetch(`${base}/v1/renewal/quote`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token_id: "1", forecast_calls: 7200, wallet: OWNER, purchase_authority: true }) }));
  assert.equal(ready.body.next_action, "SIGN_UNSIGNED_TRANSACTIONS");
  assert.equal(ready.body.unsigned_transactions.length, 1);
});
