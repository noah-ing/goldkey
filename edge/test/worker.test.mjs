import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { decodeFunctionData, encodeFunctionResult } from "viem";
import { ERC20_ABI, GOLDKEY_ABI } from "../src/chain.mjs";
import { createWorker } from "../src/index.mjs";

const EDGE_ROOT = fileURLToPath(new URL("..", import.meta.url));
const PACKAGE_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const CONTRACT = "0x1111111111111111111111111111111111111111";
const TREASURY = "0x2222222222222222222222222222222222222222";
const OWNER = "0x3333333333333333333333333333333333333333";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const TERMS_HASH = `0x${"ab".repeat(32)}`;

const termsAsset = readFileSync(`${EDGE_ROOT}/public/TERMS.md`);
const schemaAsset = readFileSync(`${EDGE_ROOT}/public/schemas/commerce-response-v1.json`);
const demoAsset = readFileSync(`${EDGE_ROOT}/public/demo.json`);

function env(overrides = {}) {
  return {
    PUBLIC_ORIGIN: "https://edge.example",
    ORIGIN_API: "https://origin.example",
    CHAIN_ID: "8453",
    RPC_URL: "https://rpc.example",
    GOLDKEY_CONTRACT: CONTRACT,
    USDC_ADDRESS: USDC,
    TREASURY_ADDRESS: TREASURY,
    TERMS_HASH,
    ASSETS: {
      async fetch(request) {
        const pathname = new URL(request.url).pathname;
        if (pathname === "/TERMS.md") return new Response(termsAsset);
        if (pathname === "/schemas/commerce-response-v1.json") return new Response(schemaAsset);
        if (pathname === "/demo.json") return new Response(demoAsset);
        return new Response("not found", { status: 404 });
      },
    },
    ...overrides,
  };
}

function decodeCall(data) {
  try {
    return decodeFunctionData({ abi: GOLDKEY_ABI, data });
  } catch {
    return decodeFunctionData({ abi: ERC20_ABI, data });
  }
}

function rpcValue(functionName, options) {
  const values = {
    totalMinted: options.totalMinted ?? 7n,
    LICENSE_TERMS_HASH: options.termsHash ?? TERMS_HASH,
    MINT_PRICE: options.mintPrice ?? 50_000_000n,
    USDC: options.usdc ?? USDC,
    treasury: options.treasury ?? TREASURY,
    MAX_SUPPLY: options.maxSupply ?? 10_000n,
    CALLS_PER_TERM: options.callsPerTerm ?? 10_000n,
    SERVICE_TERM_SECONDS: options.termSeconds ?? 31_536_000n,
    salesPaused: options.salesPaused ?? false,
    licenseTermsURI: options.termsUri ?? "https://edge.example/terms",
    decimals: options.decimals ?? 6,
  };
  return values[functionName];
}

function makeNetwork(options = {}) {
  const requests = [];
  const pass = {
    owner: options.owner ?? OWNER,
    term: options.term ?? 1n,
    expiresAt: options.expiresAt ?? 2_000_000_000n,
    epoch: options.epoch ?? 0n,
    active: options.active ?? true,
  };

  async function fetchImpl(input, init = {}) {
    const target = new URL(typeof input === "string" ? input : input.url);
    requests.push({ target, init });
    if (target.origin === "https://rpc.example") {
      if (options.rpcDown) throw new Error("rpc down");
      const batch = JSON.parse(init.body);
      assert.ok(Array.isArray(batch), "RPC must use a batch");
      const reply = batch.map((item) => {
        let result;
        if (item.method === "eth_chainId") result = options.chainIdHex ?? "0x2105";
        else if (item.method === "eth_blockNumber") result = "0x64";
        else if (item.method === "eth_getCode") result = options.missingCode ? "0x" : "0x60006000";
        else if (item.method === "eth_call") {
          const { functionName } = decodeCall(item.params[0].data);
          if (functionName === "accessState") {
            result = encodeFunctionResult({ abi: GOLDKEY_ABI, functionName, result: [pass.owner, pass.term, pass.expiresAt, pass.epoch, pass.active] });
          } else {
            const abi = functionName === "decimals" ? ERC20_ABI : GOLDKEY_ABI;
            result = encodeFunctionResult({ abi, functionName, result: rpcValue(functionName, options) });
          }
        } else throw new Error(`unexpected RPC method ${item.method}`);
        return { jsonrpc: "2.0", id: item.id, result };
      });
      return Response.json(reply);
    }

    if (target.origin === "https://origin.example") {
      if (options.originDown) throw new Error("origin down");
      const body = init.body ? new TextDecoder().decode(init.body) : "";
      return Response.json({
        path: target.pathname,
        query: target.search,
        method: init.method,
        authorization: init.headers.get("authorization"),
        idempotency_key: init.headers.get("idempotency-key"),
        payment_signature: init.headers.get("payment-signature"),
        body,
      }, { status: target.pathname === "/v1/auth/challenge" ? 201 : 200 });
    }
    throw new Error(`unexpected network target ${target}`);
  }

  return { fetchImpl, requests };
}

async function body(response) {
  return response.json();
}

function collectRefs(value, refs = []) {
  if (Array.isArray(value)) {
    for (const item of value) collectRefs(item, refs);
  } else if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (key === "$ref") refs.push(item);
      else collectRefs(item, refs);
    }
  }
  return refs;
}

function resolveLocalRef(document, ref) {
  return ref.slice(2).split("/").reduce((value, segment) => value?.[segment.replaceAll("~1", "/").replaceAll("~0", "~")], document);
}

test("deployed static artifacts are byte-identical to canonical terms and schema", () => {
  assert.deepEqual(termsAsset, readFileSync(`${PACKAGE_ROOT}/TERMS.md`));
  assert.deepEqual(schemaAsset, readFileSync(`${PACKAGE_ROOT}/agent/goldkey-commerce-response.schema.json`));
  assert.equal(JSON.parse(schemaAsset).$id, "urn:goldkey:schema:commerce-response:v1");
});

test("domain skill discovery serves only the exact index and integrity-pinned archive paths", async () => {
  const indexAsset = readFileSync(`${EDGE_ROOT}/public/.well-known/agent-skills/index.json`);
  const archiveAsset = readFileSync(`${EDGE_ROOT}/public/.well-known/agent-skills/goldkey-agent-utilities.tar.gz`);
  const assetRequests = [];
  const skillAssets = {
    async fetch(request) {
      const pathname = new URL(request.url).pathname;
      assetRequests.push(pathname);
      if (pathname === "/.well-known/agent-skills/index.json") return new Response(indexAsset);
      if (pathname === "/.well-known/agent-skills/goldkey-agent-utilities.tar.gz") return new Response(archiveAsset);
      return new Response("not found", { status: 404 });
    },
  };
  const worker = createWorker();
  const indexResponse = await worker.fetch(
    new Request("https://edge.example/.well-known/agent-skills/index.json"),
    env({ ASSETS: skillAssets }),
  );
  assert.equal(indexResponse.status, 200);
  assert.match(indexResponse.headers.get("content-type"), /^application\/json/);
  assert.deepEqual(Buffer.from(await indexResponse.arrayBuffer()), indexAsset);

  const archiveResponse = await worker.fetch(
    new Request("https://edge.example/.well-known/agent-skills/goldkey-agent-utilities.tar.gz"),
    env({ ASSETS: skillAssets }),
  );
  assert.equal(archiveResponse.status, 200);
  assert.equal(archiveResponse.headers.get("content-type"), "application/gzip");
  assert.deepEqual(Buffer.from(await archiveResponse.arrayBuffer()), archiveAsset);

  const nearMiss = await worker.fetch(
    new Request("https://edge.example/.well-known/agent-skills/unlisted.tar.gz"),
    env({ ASSETS: skillAssets }),
  );
  assert.equal(nearMiss.status, 404);
  assert.deepEqual(assetRequests, [
    "/.well-known/agent-skills/index.json",
    "/.well-known/agent-skills/goldkey-agent-utilities.tar.gz",
  ]);
});

test("health, terms, schema, OpenAPI, agent card, catalog, and demo never touch a network", async () => {
  const network = makeNetwork();
  const worker = createWorker({ fetchImpl: network.fetchImpl });
  const routes = ["/healthz", "/terms", "/schemas/commerce-response-v1.json", "/openapi.json", "/.well-known/agent.json", "/v1/catalog", "/v1/demo"];
  for (const path of routes) {
    const response = await worker.fetch(new Request(`https://edge.example${path}`), env());
    assert.equal(response.status, 200, path);
    assert.equal(response.headers.get("access-control-allow-origin"), "*");
  }
  assert.equal(network.requests.length, 0);

  const health = await body(await worker.fetch(new Request("https://edge.example/healthz"), env()));
  assert.equal(health.storefront, "ready");
  assert.equal(health.origin_checked, false);
  const openapi = await body(await worker.fetch(new Request("https://edge.example/openapi.json"), env()));
  const paygo = openapi.paths["/v1/paygo/execute"].post;
  assert.equal(paygo.tags[0], "origin");
  assert.match(openapi.info["x-guidance"], /POST \/v1\/paygo\/execute/);
  assert.match(openapi.info["x-guidance"], /0\.01 USDC/);
  assert.match(paygo.summary, /^\$0\.01-USDC Base x402 access to six deterministic tools:/);
  assert.match(paygo.description, /^For \$0\.01 USDC per x402 call on Base, execute one of six deterministic utilities:/);
  const deterministicTools = ["json.canonicalize", "json.validate", "security.prompt_scan", "security.url_check", "policy.spend_check", "text.normalize"];
  assert.deepEqual(paygo.requestBody.content["application/json"].schema.properties.tool.enum, deterministicTools);
  for (const tool of deterministicTools) {
    assert.match(paygo.summary, new RegExp(tool.replace(".", "\\.")));
    assert.match(paygo.description, new RegExp(tool.replace(".", "\\.")));
  }
  assert.match(paygo.description, /validates the envelope before payment verification/);
  assert.match(paygo.description, /settles payment, and only then releases the result/);
  assert.match(paygo.description, /failed validation or settlement does not return a tool result/);
  assert.match(paygo.description, /successfully settled retry is a new purchase/);
  assert.deepEqual(paygo["x-payment-info"], {
    price: { mode: "fixed", currency: "USD", amount: "0.01" },
    protocols: [{ x402: {} }],
  });
  assert.equal(paygo.responses[402].description, "Payment Required");
  assert.equal(paygo.responses[200].content["application/json"].schema.$ref, "#/components/schemas/PaygoResponse");
  assert.equal(openapi.paths["/v1/purchase/quote"].post.responses[200].content["application/json"].schema.$ref, "#/components/schemas/CommerceResponse");
  assert.ok(openapi.components.schemas.CommerceResponse.required.includes("recommendation"));
  assert.ok(openapi.components.schemas.CommerceResponse.required.includes("unsigned_transactions"));
  assert.deepEqual(openapi.components.schemas.AuthChallengeRequest.required, ["wallet", "token_id"]);
  assert.deepEqual(openapi.components.schemas.AuthVerifyRequest.required, ["challenge_id", "signature"]);
  assert.equal(openapi.paths["/v1/auth/challenge"].post.requestBody.content["application/json"].schema.$ref, "#/components/schemas/AuthChallengeRequest");
  assert.equal(openapi.paths["/v1/auth/verify"].post.requestBody.content["application/json"].schema.$ref, "#/components/schemas/AuthVerifyRequest");
  assert.deepEqual(openapi.components.schemas.PaygoResponse.required, ["request_id", "tool", "tool_version", "input_sha256", "result", "payment", "upgrade"]);
  for (const ref of collectRefs(openapi)) {
    assert.match(ref, /^#\//, `${ref} must be a local OpenAPI reference`);
    assert.ok(resolveLocalRef(openapi, ref), `${ref} must resolve within the OpenAPI document`);
  }
  assert.match(openapi.paths["/v1/purchase/quote"].post.description, /never signs or submits/);
  const demo = await body(await worker.fetch(new Request("https://edge.example/v1/demo"), env()));
  assert.equal(demo.free_fixed_examples, true);
  assert.equal(demo.examples[0].tool, "security.prompt_scan");
  assert.equal(demo.examples[1].tool, "policy.spend_check");
  assert.equal(network.requests.length, 0);
});

test("offer reads live onchain state, uses the short cache, and never contacts origin", async () => {
  const network = makeNetwork({ totalMinted: 7n });
  const worker = createWorker({ fetchImpl: network.fetchImpl });
  for (let index = 0; index < 2; index += 1) {
    const response = await worker.fetch(new Request("https://edge.example/.well-known/goldkey.json"), env());
    assert.equal(response.status, 200);
    const offer = await body(response);
    assert.equal(offer.contract.state.status, "live");
    assert.equal(offer.contract.state.remaining, "9993");
    assert.equal(offer.economics.break_even_calls_excluding_gas_and_switching_cost, 5000);
    assert.equal(offer.economics.gross_primary_sale_cap_usdc, "500000.00");
    assert.equal(offer.service_topology.utility_fulfillment, "stateful_origin_may_cold_start");
  }
  assert.equal(network.requests.filter(({ target }) => target.origin === "https://rpc.example").length, 1);
  assert.equal(network.requests.filter(({ target }) => target.origin === "https://origin.example").length, 0);
});

test("offer stays explicit and useful when RPC is down", async () => {
  const network = makeNetwork({ rpcDown: true });
  const worker = createWorker({ fetchImpl: network.fetchImpl });
  const response = await worker.fetch(new Request("https://edge.example/.well-known/goldkey.json"), env());
  assert.equal(response.status, 200);
  const offer = await body(response);
  assert.deepEqual(offer.contract.state, { status: "unavailable", error: "onchain_state_unavailable" });
  assert.equal(offer.price.amount, "50.00");
  assert.equal(network.requests.some(({ target }) => target.origin === "https://origin.example"), false);
});

test("purchase quote is live-supply-aware and returns exact unsigned transactions only", async () => {
  const network = makeNetwork();
  const worker = createWorker({ fetchImpl: network.fetchImpl });
  const request = new Request("https://edge.example/v1/purchase/quote", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ forecast_calls: 7200, wallet: OWNER, purchase_authority: true }),
  });
  const response = await worker.fetch(request, env());
  assert.equal(response.status, 200);
  const quote = await body(response);
  assert.equal(quote.recommendation, "BUY_1_KEY");
  assert.equal(quote.paygo_cost_usdc, "72.00");
  assert.equal(quote.key_purchase_cost_usdc, "50.00");
  assert.equal(quote.raw_savings_usdc, "22.00");
  assert.equal(quote.next_action, "SIGN_UNSIGNED_TRANSACTIONS");
  assert.equal(quote.unsigned_transactions.length, 2);
  assert.equal(quote.unsigned_transactions[0].asset_amount_atomic, "50000000");
  assert.equal(quote.unsigned_transactions[1].quantity, "1");
  assert.equal(network.requests.filter(({ target }) => target.origin === "https://rpc.example").length, 1);
  assert.equal(network.requests.some(({ target }) => target.origin === "https://origin.example"), false);
});

test("break-even is not presented as savings and malformed requests fail before RPC", async () => {
  const network = makeNetwork();
  const worker = createWorker({ fetchImpl: network.fetchImpl });
  const atBreakEven = await worker.fetch(new Request("https://edge.example/v1/commerce/respond", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ forecast_calls: 5000 }),
  }), env());
  assert.equal(atBreakEven.status, 200);
  const response = await body(atBreakEven);
  assert.equal(response.recommendation, "PAYGO");
  assert.equal(response.key_count, 0);
  assert.match(response.sales_message, /Do not buy GoldKey/);

  const before = network.requests.length;
  const invalid = await worker.fetch(new Request("https://edge.example/v1/purchase/quote", { method: "POST", body: "{" }), env());
  assert.equal(invalid.status, 400);
  assert.equal((await body(invalid)).error.code, "invalid_json");
  assert.equal(network.requests.length, before);
});

test("metadata and renewal use verified Base RPC state without touching origin", async () => {
  const network = makeNetwork({ active: true });
  const worker = createWorker({ fetchImpl: network.fetchImpl });
  const metadataResponse = await worker.fetch(new Request("https://edge.example/metadata/1"), env());
  assert.equal(metadataResponse.status, 200);
  const metadata = await body(metadataResponse);
  assert.equal(metadata.name, "GoldKey #1");
  assert.match(metadata.description, /not an investment/);
  assert.match(metadata.image, /^data:image\/svg\+xml;base64,/);

  const renewal = await worker.fetch(new Request("https://edge.example/v1/renewal/quote", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token_id: "1", forecast_calls: 9000, wallet: OWNER, purchase_authority: true }),
  }), env());
  assert.equal(renewal.status, 200);
  const renewalQuote = await body(renewal);
  assert.equal(renewalQuote.recommendation, "RENEW_AFTER_EXPIRY");
  assert.equal(renewalQuote.next_action, "WAIT_UNTIL_EXPIRY");
  assert.deepEqual(renewalQuote.unsigned_transactions, []);
  assert.equal(network.requests.some(({ target }) => target.origin === "https://origin.example"), false);
});

test("expired owner renewal returns ordered unsigned transactions", async () => {
  const network = makeNetwork({ active: false, expiresAt: 1_700_000_000n });
  const worker = createWorker({ fetchImpl: network.fetchImpl });
  const response = await worker.fetch(new Request("https://edge.example/v1/renewal/quote", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token_id: "1", forecast_calls: 9000, wallet: OWNER, purchase_authority: true }),
  }), env());
  assert.equal(response.status, 200);
  const quote = await body(response);
  assert.equal(quote.recommendation, "RENEW_NOW");
  assert.equal(quote.next_action, "SIGN_UNSIGNED_TRANSACTIONS");
  assert.deepEqual(quote.unsigned_transactions.map(({ sequence, depends_on }) => ({ sequence, depends_on })), [
    { sequence: 1, depends_on: [] },
    { sequence: 2, depends_on: [1] },
  ]);
});

test("nonexistent metadata is a 404 and malformed token IDs do not reach RPC", async () => {
  const nonexistent = makeNetwork({ owner: "0x0000000000000000000000000000000000000000", term: 0n, active: false });
  const worker = createWorker({ fetchImpl: nonexistent.fetchImpl });
  const response = await worker.fetch(new Request("https://edge.example/metadata/1"), env());
  assert.equal(response.status, 404);
  assert.equal((await body(response)).error.code, "goldkey_not_found");

  const invalidNetwork = makeNetwork();
  const invalidWorker = createWorker({ fetchImpl: invalidNetwork.fetchImpl });
  const invalid = await invalidWorker.fetch(new Request("https://edge.example/metadata/01"), env());
  assert.equal(invalid.status, 400);
  assert.equal((await body(invalid)).error.code, "invalid_token_id");
  assert.equal(invalidNetwork.requests.length, 0, "malformed token IDs fail before any RPC call");
});

test("only the exact stateful allowlist is proxied and important headers survive", async () => {
  const network = makeNetwork();
  const worker = createWorker({ fetchImpl: network.fetchImpl });
  const tool = await worker.fetch(new Request("https://edge.example/v1/tools/json.validate?trace=1", {
    method: "POST",
    headers: {
      authorization: "Bearer test-session",
      "content-type": "application/json",
      "idempotency-key": "abcdefgh",
      "payment-signature": "signed-payment",
    },
    body: JSON.stringify({ value: 1 }),
  }), env());
  assert.equal(tool.status, 200);
  const echo = await body(tool);
  assert.equal(echo.path, "/v1/tools/json.validate");
  assert.equal(echo.query, "?trace=1");
  assert.equal(echo.authorization, "Bearer test-session");
  assert.equal(echo.idempotency_key, "abcdefgh");
  assert.equal(echo.payment_signature, "signed-payment");
  assert.equal(echo.body, JSON.stringify({ value: 1 }));

  const before = network.requests.length;
  const unknown = await worker.fetch(new Request("https://edge.example/v1/admin/secrets"), env());
  assert.equal(unknown.status, 404);
  const wrongMethod = await worker.fetch(new Request("https://edge.example/v1/auth/challenge"), env());
  assert.equal(wrongMethod.status, 405);
  assert.equal(network.requests.length, before);
});

test("missing or unavailable origin fails safely without affecting storefront", async () => {
  const network = makeNetwork({ originDown: true });
  const worker = createWorker({ fetchImpl: network.fetchImpl });
  const storefront = await worker.fetch(new Request("https://edge.example/v1/catalog"), env({ ORIGIN_API: undefined }));
  assert.equal(storefront.status, 200);
  const missing = await worker.fetch(new Request("https://edge.example/v1/quota", { headers: { authorization: "Bearer x" } }), env({ ORIGIN_API: undefined }));
  assert.equal(missing.status, 503);
  assert.equal((await body(missing)).error.code, "origin_not_configured");
  const down = await worker.fetch(new Request("https://edge.example/v1/quota"), env());
  assert.equal(down.status, 502);
  assert.equal((await body(down)).error.code, "origin_unavailable");
});

test("a deployment identity mismatch blocks quotes and is never replaced by origin data", async () => {
  const network = makeNetwork({ mintPrice: 49_000_000n });
  const worker = createWorker({ fetchImpl: network.fetchImpl });
  const response = await worker.fetch(new Request("https://edge.example/v1/purchase/quote", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ forecast_calls: 8000 }),
  }), env());
  assert.equal(response.status, 503);
  const failure = await body(response);
  assert.equal(failure.error.code, "deployment_identity_mismatch");
  assert.ok(failure.error.details.mismatches.includes("mint_price=49000000"));
  assert.equal(network.requests.some(({ target }) => target.origin === "https://origin.example"), false);
});
