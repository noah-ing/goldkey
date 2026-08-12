import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { once } from "node:events";
import test from "node:test";
import { getAddress } from "viem";
import { createApp, createGuardBeforeSettlementRecheck } from "../src/app.mjs";
import { createAuthService } from "../src/auth.mjs";
import { loadConfig } from "../src/config.mjs";
import { GoldKeyDatabase } from "../src/database.mjs";
import { ServiceError } from "../src/errors.mjs";
import { createPilotApplicationsService } from "../src/pilot-applications.mjs";
import { createGuardBeforeSettlementHook } from "../src/x402.mjs";

const OWNER = getAddress("0x000000000000000000000000000000000000dEaD");
const PUBLIC_ORIGIN = "http://127.0.0.1:8402";
const PILOT_ADMIN_TOKEN = "pilot-admin-token-for-app-route-tests-that-is-long-enough";
const PILOT_EDGE_SECRET = "pilot-edge-secret-for-app-route-tests-that-is-long-enough";

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
    guardEnabled: overrides.guardEnabled ?? false,
    guardAllowedOperatorWallets: overrides.guardAllowedOperatorWallets ?? (overrides.guardEnabled ? [OWNER] : []),
    devAuthBypass: true,
    devAuthToken: "test-owner-token-that-is-long",
    pilotApplicationsEnabled: overrides.pilotApplicationsEnabled ?? false,
    pilotAdminTokenSha256: overrides.pilotAdminTokenSha256 ?? (overrides.pilotApplicationsEnabled
      ? createHash("sha256").update(PILOT_ADMIN_TOKEN).digest("hex")
      : ""),
    pilotAbuseSecret: overrides.pilotAbuseSecret ?? (overrides.pilotApplicationsEnabled
      ? "pilot-abuse-secret-for-app-route-tests-that-is-long-enough"
      : ""),
    pilotEdgeSecret: overrides.pilotEdgeSecret ?? (overrides.pilotApplicationsEnabled ? PILOT_EDGE_SECRET : ""),
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
  const pilotApplications = overrides.pilotApplications ?? (config.pilotApplicationsEnabled
    ? createPilotApplicationsService({
        database: db,
        adminTokenSha256: config.pilotAdminTokenSha256,
        abuseSecret: config.pilotAbuseSecret,
        retentionDays: config.pilotRetentionDays,
      })
    : undefined);
  const app = createApp({ config, db, chain, auth, guard: overrides.guard, pilotApplications, x402Middleware: overrides.x402Middleware });
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

test("pilot applications accept only edge-authenticated submissions and keep applicant data behind the admin bearer", async (t) => {
  const { base } = await fixture(t, { pilotApplicationsEnabled: true });
  const application = {
    name: "Ada Operator",
    email: "ada@example.com",
    company: "Example Labs",
    agent_stack: "Claude Code with a private MCP server",
    connector: "Production billing MCP",
    action: "Create a refund only after operator-controlled policy approval.",
    timeline: "This month",
    website: "",
    budget_confirmed: true,
  };
  const submissionHeaders = {
    "content-type": "application/json",
    "idempotency-key": "pilot-app-route-0000000000000001",
    "x-goldkey-client-address": "203.0.113.7",
  };

  const direct = await json(await fetch(`${base}/v1/pilot/applications`, {
    method: "POST",
    headers: submissionHeaders,
    body: JSON.stringify(application),
  }));
  assert.equal(direct.response.status, 403);
  assert.equal(direct.body.error.code, "pilot_edge_required");

  const submitted = await json(await fetch(`${base}/v1/pilot/applications`, {
    method: "POST",
    headers: { ...submissionHeaders, "x-goldkey-pilot-edge": PILOT_EDGE_SECRET },
    body: JSON.stringify(application),
  }));
  assert.equal(submitted.response.status, 201);
  assert.equal(submitted.body.status, "received");
  assert.match(submitted.body.application_id, /^pil_[0-9a-f-]{36}$/);
  assert.equal(JSON.stringify(submitted.body).includes(application.email), false);

  const replay = await json(await fetch(`${base}/v1/pilot/applications`, {
    method: "POST",
    headers: { ...submissionHeaders, "x-goldkey-pilot-edge": PILOT_EDGE_SECRET },
    body: JSON.stringify(application),
  }));
  assert.equal(replay.response.status, 200);
  assert.equal(replay.body.idempotent_replay, true);
  assert.equal(replay.body.application_id, submitted.body.application_id);

  const unauthorizedSummary = await json(await fetch(`${base}/v1/admin/pilot/applications/summary`, {
    headers: { authorization: "Bearer incorrect-but-deliberately-long-admin-token" },
  }));
  assert.equal(unauthorizedSummary.response.status, 401);
  assert.equal(unauthorizedSummary.body.error.code, "pilot_admin_unauthorized");

  const adminHeaders = { authorization: `Bearer ${PILOT_ADMIN_TOKEN}` };
  const summary = await json(await fetch(`${base}/v1/admin/pilot/applications/summary`, { headers: adminHeaders }));
  assert.equal(summary.response.status, 200);
  assert.equal(summary.body.total_active, 1);
  assert.deepEqual(summary.body.newest, {
    application_id: submitted.body.application_id,
    submitted_at: summary.body.newest.submitted_at,
  });
  assert.match(summary.body.newest.submitted_at, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(JSON.stringify(summary.body).includes(application.email), false);

  const listed = await json(await fetch(`${base}/v1/admin/pilot/applications?limit=10`, { headers: adminHeaders }));
  assert.equal(listed.response.status, 200);
  assert.equal(listed.body.applications.length, 1);
  assert.equal(listed.body.applications[0].email, application.email);

  const reviewed = await json(await fetch(`${base}/v1/admin/pilot/applications/${submitted.body.application_id}`, {
    method: "PATCH",
    headers: { ...adminHeaders, "content-type": "application/json" },
    body: JSON.stringify({ status: "reviewing", admin_note: "Acceptance-route test" }),
  }));
  assert.equal(reviewed.response.status, 200);
  assert.equal(reviewed.body.application.status, "reviewing");
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

test("Guard rejects invalid installation signatures before x402 and authorizes only after verification", async (t) => {
  let middlewareCalls = 0;
  let preflightCalls = 0;
  let authorizeCalls = 0;
  const envelope = {
    schema: "goldkey.guard-authorization-envelope.v1",
    receipt: { receipt_id: "receipt-1", decision: "BLOCK", reason_codes: ["policy_denied"] },
    evidence: { schema: "goldkey.guard-evidence.v1", decision: "BLOCK", reason_codes: ["policy_denied"] },
    receipt_sha256: "1".repeat(64),
    signature: "A".repeat(86),
  };
  const guard = {
    keyset: { schema: "goldkey.guard-receipt-keyset.v1", keys: [{ kty: "OKP", crv: "Ed25519", x: "A".repeat(43), kid: "guard-key-1" }] },
    async preflight(body, expectedKinds) {
      preflightCalls += 1;
      if (body.signature === "valid-replay-signature") return { installation_id: "install-1", replay: true, payment_settled: true, replay_authorization: envelope };
      if (body.signature === "valid-unsettled-replay-signature") return { installation_id: "install-1", replay: true, payment_settled: false };
      if (body.signature !== "valid-installation-signature") throw new ServiceError(401, "invalid_guard_request_signature", "Invalid Guard request signature");
      if (!expectedKinds.includes(body.call?.kind)) throw new ServiceError(400, "guard_route_kind_mismatch", "Wrong Guard route");
      return { installation_id: "install-1" };
    },
    async authorize(body, expectedKinds) {
      authorizeCalls += 1;
      assert.ok(expectedKinds.includes(body.call.kind));
      return envelope;
    },
    async registerPolicy() { return { replay: false, policy_id: "policy-1" }; },
    async registerInstallation() { return { replay: false, installation_id: "install-1" }; },
    async revoke(body) { return { target_kind: body.target_kind, target_id: body.target_id, revoked_at: "2026-08-11T00:00:00.000Z" }; },
    async commit(body) { return { replay: false, execution_id: body.execution_id, status: "forwarding" }; },
    async complete(body) { return { replay: false, execution_id: body.execution_id, status: "completed", outcome_status: body.outcome_status }; },
  };
  const x402Middleware = (req, res, next) => {
    if (!req.path.startsWith("/v1/guard/paygo/authorize/")) return next();
    middlewareCalls += 1;
    if (req.get("payment-signature") === "accepted") return next();
    res.status(402).set("payment-required", "guard-challenge").json({});
  };
  const { base } = await fixture(t, { x402Enabled: true, guardEnabled: true, guard, x402Middleware });

  const invalid = await json(await fetch(`${base}/v1/guard/paygo/authorize/network`, {
    method: "POST",
    headers: { "content-type": "application/json", "payment-signature": "would-have-paid" },
    body: JSON.stringify({ signature: "invalid", call: { kind: "https" } }),
  }));
  assert.equal(invalid.response.status, 401);
  assert.equal(invalid.body.error.code, "invalid_guard_request_signature");
  assert.equal(middlewareCalls, 0);
  assert.equal(authorizeCalls, 0);

  const request = { signature: "valid-installation-signature", call: { kind: "https" } };
  const unpaid = await fetch(`${base}/v1/guard/paygo/authorize/network`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request),
  });
  assert.equal(unpaid.status, 402);
  assert.equal(middlewareCalls, 1);
  assert.equal(authorizeCalls, 0);

  const paid = await json(await fetch(`${base}/v1/guard/paygo/authorize/network`, {
    method: "POST",
    headers: { "content-type": "application/json", "payment-signature": "accepted" },
    body: JSON.stringify(request),
  }));
  assert.equal(paid.response.status, 200);
  assert.deepEqual(paid.body, envelope);
  assert.equal(paid.body.receipt.decision, "BLOCK");
  assert.equal(middlewareCalls, 2);
  assert.equal(preflightCalls, 3);
  assert.equal(authorizeCalls, 1);

  const failedSettlementReplay = await fetch(`${base}/v1/guard/paygo/authorize/network`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...request, signature: "valid-unsettled-replay-signature" }),
  });
  assert.equal(failedSettlementReplay.status, 402);
  assert.equal(middlewareCalls, 3);
  assert.equal(authorizeCalls, 1);

  const replay = await json(await fetch(`${base}/v1/guard/paygo/authorize/network`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...request, signature: "valid-replay-signature" }),
  }));
  assert.equal(replay.response.status, 200);
  assert.deepEqual(replay.body, envelope);
  assert.equal(replay.response.headers.get("x-goldkey-idempotent-replay"), "true");
  assert.equal(middlewareCalls, 3);
  assert.equal(authorizeCalls, 1);

  const wrongRoute = await json(await fetch(`${base}/v1/guard/paygo/authorize/evm`, {
    method: "POST",
    headers: { "content-type": "application/json", "payment-signature": "accepted" },
    body: JSON.stringify(request),
  }));
  assert.equal(wrongRoute.response.status, 400);
  assert.equal(wrongRoute.body.error.code, "guard_route_kind_mismatch");
  assert.equal(middlewareCalls, 3);
  assert.equal(authorizeCalls, 1);
  assert.equal(preflightCalls, 6);
});

test("Guard rechecks authoritative policy state immediately before settlement", async () => {
  const calls = [];
  const guard = {
    async beginPaymentSettlement(body, expectedKinds, claimId) {
      calls.push({ body, expectedKinds, claimId });
      if (body.state !== "active") {
        throw new ServiceError(409, `guard_${body.state}`, `Sensitive ${body.state} details`);
      }
      return { installation_id: "install-1" };
    },
  };
  const hook = createGuardBeforeSettlementHook(createGuardBeforeSettlementRecheck(guard));
  const activeBody = { state: "active", call: { kind: "https" } };
  const active = await hook({
    transportContext: {
      request: {
        path: "/v1/guard/paygo/authorize/network",
        adapter: { getBody: () => activeBody },
      },
    },
  });
  assert.equal(active, undefined);
  assert.equal(calls[0].body, activeBody);
  assert.deepEqual(calls[0].expectedKinds, ["mcp_tool", "https"]);
  assert.match(calls[0].claimId, /^[0-9a-f-]{36}$/);

  for (const state of ["revoked", "expired", "inactive"]) {
    const blocked = await hook({
      transportContext: {
        request: {
          path: "/v1/guard/paygo/authorize/evm",
          adapter: { getBody: () => ({ state, call: { kind: "evm_transaction" } }) },
        },
      },
    });
    assert.deepEqual(blocked, {
      abort: true,
      reason: "guard_authorization_inactive",
      message: "Guard authorization is no longer active",
    });
    if (state !== "inactive") assert.doesNotMatch(JSON.stringify(blocked), new RegExp(state));
    assert.doesNotMatch(JSON.stringify(blocked), /Sensitive|details/);
  }
  assert.deepEqual(calls.slice(1).map(({ expectedKinds }) => expectedKinds), [
    ["evm_transaction"],
    ["evm_transaction"],
    ["evm_transaction"],
  ]);
});

test("Guard exposes signed registration, keyset, lifecycle, catalog, and OpenAPI surfaces", async (t) => {
  const calls = [];
  const keyset = { schema: "goldkey.guard-receipt-keyset.v1", keys: [{ kty: "OKP", crv: "Ed25519", x: "A".repeat(43), kid: "guard-key-1" }] };
  const guard = {
    keyset,
    async preflight() { throw new Error("not used"); },
    async authorize() { throw new Error("not used"); },
    async registerPolicy(body) { calls.push(["policy", body]); return { replay: false, policy_id: "policy-1" }; },
    async registerInstallation(body) { calls.push(["installation", body]); return { replay: true, installation_id: "install-1" }; },
    async revoke(body) { calls.push(["revocation", body]); return { target_kind: body.target_kind, target_id: body.target_id, revoked_at: "2026-08-11T00:00:00.000Z" }; },
    async commit(body) { calls.push(["commit", body]); return { replay: false, execution_id: body.execution_id, status: "forwarding" }; },
    async reconcileCommit(body) { calls.push(["reconcile-commit", body]); return { replay: false, execution_id: body.commit.execution_id, status: "forwarding", payment_reconciled: true }; },
    async complete(body) { calls.push(["complete", body]); return { replay: false, execution_id: body.execution_id, status: "completed" }; },
  };
  const { base } = await fixture(t, { x402Enabled: true, guardEnabled: true, guard, x402Middleware: (_req, _res, next) => next() });

  const keys = await json(await fetch(`${base}/.well-known/goldkey-guard-keys.json`));
  assert.equal(keys.response.status, 200);
  assert.deepEqual(keys.body, keyset);
  assert.match(keys.response.headers.get("cache-control"), /max-age=60/);

  const guardTerms = await fetch(`${base}/guard/terms`);
  assert.equal(guardTerms.status, 200);
  assert.match(guardTerms.headers.get("content-type"), /^text\/markdown/);
  assert.match(await guardTerms.text(), /separate from the immutable GoldKey utility-pass terms/i);

  const policy = await json(await fetch(`${base}/v1/guard/policies`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ signed: "policy" }) }));
  assert.equal(policy.response.status, 201);
  const installation = await json(await fetch(`${base}/v1/guard/installations`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ signed: "installation" }) }));
  assert.equal(installation.response.status, 200);
  const revocation = await json(await fetch(`${base}/v1/guard/revocations`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ target_kind: "installation", target_id: "install-1" }) }));
  assert.equal(revocation.response.status, 200);
  assert.equal(revocation.body.target_id, "install-1");

  const executionId = "receipt-1";
  const commit = await json(await fetch(`${base}/v1/guard/executions/${executionId}/commit`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ execution_id: executionId }) }));
  assert.equal(commit.body.status, "forwarding");
  const reconciled = await json(await fetch(`${base}/v1/guard/executions/${executionId}/reconcile-commit`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ commit: { execution_id: executionId }, payment_proof: {} }) }));
  assert.equal(reconciled.body.payment_reconciled, true);
  const complete = await json(await fetch(`${base}/v1/guard/executions/${executionId}/complete`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ execution_id: executionId }) }));
  assert.equal(complete.body.status, "completed");
  const mismatch = await json(await fetch(`${base}/v1/guard/executions/${executionId}/commit`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ execution_id: "receipt-2" }) }));
  assert.equal(mismatch.response.status, 409);
  assert.equal(mismatch.body.error.code, "guard_lifecycle_mismatch");

  const catalogResponse = await json(await fetch(`${base}/v1/catalog`));
  assert.deepEqual(catalogResponse.body.pricing.guard, {
    mcp_or_https_authorization_usdc: "0.05",
    evm_authorization_usdc: "0.10",
    pass_included: false,
  });
  const openapi = await json(await fetch(`${base}/openapi.json`));
  const expectedGuardPaths = [
    "/guard/terms",
    "/.well-known/goldkey-guard-keys.json",
    "/v1/guard/policies",
    "/v1/guard/installations",
    "/v1/guard/revocations",
    "/v1/guard/paygo/authorize/network",
    "/v1/guard/paygo/authorize/evm",
    "/v1/guard/executions/{executionId}/commit",
    "/v1/guard/executions/{executionId}/reconcile-commit",
    "/v1/guard/executions/{executionId}/complete",
  ];
  const actualGuardPaths = Object.keys(openapi.body.paths)
    .filter((path) => path === "/guard/terms" || path === "/.well-known/goldkey-guard-keys.json" || path.startsWith("/v1/guard/"));
  assert.deepEqual(actualGuardPaths.sort(), expectedGuardPaths.sort());
  assert.equal(openapi.body.paths["/guard/terms"].get.operationId, "goldkey_guard_terms");
  assert.ok(openapi.body.paths["/guard/terms"].get.responses[200].content["text/markdown"]);
  assert.equal(openapi.body.paths["/v1/guard/revocations"].post.operationId, "goldkey_guard_revoke");
  assert.equal(openapi.body.paths["/v1/guard/revocations"].post.requestBody.content["application/json"].schema.$ref, "#/components/schemas/GuardRevocation");
  assert.equal(openapi.body.paths["/v1/guard/paygo/authorize/network"].post["x-payment-info"].price.amount, "0.05");
  assert.equal(openapi.body.paths["/v1/guard/paygo/authorize/evm"].post["x-payment-info"].price.amount, "0.10");
  assert.match(openapi.body.paths["/v1/guard/paygo/authorize/network"].post.description, /never forwards/i);
  assert.match(openapi.body.paths["/v1/guard/paygo/authorize/evm"].post.description, /never signs or broadcasts/i);
  assert.equal(openapi.body.paths["/v1/guard/executions/{executionId}/reconcile-commit"].post.requestBody.content["application/json"].schema.$ref, "#/components/schemas/GuardReconciledCommit");
  assert.equal(openapi.body.components.schemas.GuardReconciledCommit.properties.commit.$ref, "#/components/schemas/GuardCommit");
  assert.equal(openapi.body.components.schemas.GuardReconciledCommit.properties.payment_proof.properties.payment_payload.properties.accepted.properties.network.const, "eip155:8453");
  assert.ok(openapi.body.components.schemas.GuardInstallation.required.includes("key_proof"));
  assert.equal(openapi.body.components.schemas.GuardInstallation.properties.installation_id.pattern, "^gki_[A-Za-z0-9_-]{43}$");
  assert.deepEqual(openapi.body.components.schemas.GuardRevocation.required, ["schema", "target_kind", "target_id", "operator_wallet", "audience", "issued_at", "signature"]);
  assert.deepEqual(openapi.body.components.schemas.GuardRevocation.properties.target_kind.enum, ["policy", "installation"]);
  assert.equal(openapi.body.components.schemas.GuardRevocation.allOf[0].then.properties.target_id.pattern, "^[0-9a-f]{64}$");
  assert.equal(openapi.body.components.schemas.GuardRevocation.allOf[1].then.properties.target_id.pattern, "^gki_[A-Za-z0-9_-]{43}$");
  const policyConnectors = openapi.body.components.schemas.GuardPolicy.properties.connectors.items.oneOf;
  assert.equal(policyConnectors[0].properties.tools.items.properties.arguments_schema.type, "object");
  assert.equal(policyConnectors[1].properties.operations.items.properties.query_schema.type, "object");
  assert.equal(policyConnectors[1].properties.operations.items.properties.body_schema.type, "object");
  assert.deepEqual(calls.map(([name]) => name), ["policy", "installation", "revocation", "commit", "reconcile-commit", "complete"]);
});

test("terms, schema, and renewal quotes are machine-readable", async (t) => {
  const { base, expire } = await fixture(t);
  const terms = await fetch(`${base}/terms`);
  assert.equal(terms.status, 200);
  assert.match(await terms.text(), /50 USDC/);
  assert.equal((await fetch(`${base}/guard/terms`)).status, 404);
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
