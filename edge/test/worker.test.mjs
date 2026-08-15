import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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
const PILOT_EDGE_SECRET = "pilot-edge-secret-for-tests-only-0000000000000000";

const termsAsset = readFileSync(`${EDGE_ROOT}/public/TERMS.md`);
const schemaAsset = readFileSync(`${EDGE_ROOT}/public/schemas/commerce-response-v1.json`);
const demoAsset = readFileSync(`${EDGE_ROOT}/public/demo.json`);
const homepageAsset = readFileSync(`${EDGE_ROOT}/public/index.html`);

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
        if (pathname === "/index.html") return new Response(homepageAsset);
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
        accept: init.headers.get("accept"),
        authorization: init.headers.get("authorization"),
        cookie: init.headers.get("cookie"),
        api_key: init.headers.get("x-api-key"),
        idempotency_key: init.headers.get("idempotency-key"),
        payment_signature: init.headers.get("payment-signature"),
        pilot_edge: init.headers.get("x-goldkey-pilot-edge"),
        client_address: init.headers.get("x-goldkey-client-address"),
        forwarded_for: init.headers.get("x-forwarded-for"),
        goldkey_edge: init.headers.get("x-goldkey-edge"),
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

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string" || typeof value === "number") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function canonicalSha256(value) {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

test("deployed static artifacts are byte-identical to canonical terms and schema", () => {
  assert.deepEqual(termsAsset, readFileSync(`${PACKAGE_ROOT}/TERMS.md`));
  assert.deepEqual(schemaAsset, readFileSync(`${PACKAGE_ROOT}/agent/goldkey-commerce-response.schema.json`));
  assert.equal(JSON.parse(schemaAsset).$id, "urn:goldkey:schema:commerce-response:v1");
});

test("root storefront serves the honest Guard founding offer for exact GET and HEAD only", async () => {
  const assetRequests = [];
  const homepageAssets = {
    async fetch(request) {
      assetRequests.push({ pathname: new URL(request.url).pathname, method: request.method });
      if (new URL(request.url).pathname === "/index.html") return new Response(homepageAsset);
      return new Response("not found", { status: 404 });
    },
  };
  const worker = createWorker();

  const getResponse = await worker.fetch(new Request("https://edge.example/"), env({ ASSETS: homepageAssets }));
  assert.equal(getResponse.status, 200);
  assert.equal(getResponse.headers.get("content-type"), "text/html; charset=utf-8");
  assert.equal(getResponse.headers.get("cache-control"), "public, max-age=300");
  assert.equal(getResponse.headers.get("x-frame-options"), "DENY");
  const contentSecurityPolicy = getResponse.headers.get("content-security-policy");
  assert.match(contentSecurityPolicy, /frame-ancestors 'none'/);
  assert.match(contentSecurityPolicy, /connect-src 'self'/);
  assert.doesNotMatch(contentSecurityPolicy, /script-src 'unsafe-inline'/);
  const html = await getResponse.text();
  assert.match(html, /Founding design-partner beta/i);
  assert.match(html, /No receipt[\s\S]*No execution/i);
  assert.match(html, /\$1,000/);
  assert.match(html, /\$10,000/);
  assert.match(html, /Two independently accepted \$5,000 milestones/i);
  assert.match(html, /Guarded integration:/i);
  assert.match(html, /\$0\.05/);
  assert.match(html, /\$0\.10/);
  assert.match(html, /must have no direct credential, signer, or network route that bypasses the local enforcer/i);
  assert.doesNotMatch(html, /github\.com\/noah-ing\/goldkey\/issues\/new/);
  assert.match(html, /<form class="application-form" id="pilot-form" action="\/v1\/pilot\/applications" method="post">/);
  for (const field of ["name", "email", "company", "agent_stack", "connector", "action", "timeline", "website", "budget_confirmed"]) {
    assert.match(html, new RegExp(`name="${field}"`));
  }
  for (const [field, maximum] of Object.entries({ name: 100, email: 254, company: 160, agent_stack: 500, connector: 240, action: 2000, timeline: 240, website: 500 })) {
    assert.match(html, new RegExp(`name="${field}"[^>]*maxlength="${maximum}"`));
  }
  assert.match(html, /fetch\("\/v1\/pilot\/applications"/);
  assert.match(html, /No payment is due with this application/);
  assert.match(html, /not posted publicly/);
  assert.doesNotMatch(html, /email notification|we(?:'|’)ll notify/i);
  const inlineScript = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
  assert.ok(inlineScript);
  const scriptHash = createHash("sha256").update(inlineScript).digest("base64");
  assert.ok(contentSecurityPolicy.includes(`script-src 'sha256-${scriptHash}'`));
  assert.doesNotMatch(html, /testimonial|trusted by|customers protected/i);

  const headResponse = await worker.fetch(new Request("https://edge.example/", { method: "HEAD" }), env({ ASSETS: homepageAssets }));
  assert.equal(headResponse.status, 200);
  assert.equal(headResponse.headers.get("content-type"), "text/html; charset=utf-8");
  assert.equal(await headResponse.text(), "");

  const postResponse = await worker.fetch(new Request("https://edge.example/", { method: "POST" }), env({ ASSETS: homepageAssets }));
  assert.equal(postResponse.status, 405);
  assert.equal(postResponse.headers.get("allow"), "GET, HEAD");

  const assetNearMiss = await worker.fetch(new Request("https://edge.example/index.html"), env({ ASSETS: homepageAssets }));
  assert.equal(assetNearMiss.status, 404);
  assert.deepEqual(assetRequests, [
    { pathname: "/index.html", method: "GET" },
    { pathname: "/index.html", method: "GET" },
  ]);
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

test("Guard enforcer distribution serves the current package and retains the prior pinned release", async () => {
  const publicRoot = `${EDGE_ROOT}/public/.well-known/goldkey-guard`;
  const artifactName = "goldkey-enforcer-0.2.0.tgz";
  const previousName = "goldkey-enforcer-0.1.0.tgz";
  const artifactAsset = readFileSync(`${publicRoot}/${artifactName}`);
  const manifestAsset = readFileSync(`${publicRoot}/${artifactName}.integrity.json`);
  const previousAsset = readFileSync(`${publicRoot}/${previousName}`);
  assert.deepEqual(artifactAsset, readFileSync(`${PACKAGE_ROOT}/enforcer/dist/${artifactName}`));
  assert.deepEqual(manifestAsset, readFileSync(`${PACKAGE_ROOT}/enforcer/dist/${artifactName}.integrity.json`));
  const manifest = JSON.parse(manifestAsset);
  assert.equal(manifest.schema, "goldkey-enforcer-package-integrity.v1");
  assert.equal(manifest.package, "@goldkey/enforcer");
  assert.equal(manifest.version, "0.2.0");
  assert.equal(manifest.filename, artifactName);
  assert.equal(manifest.size, artifactAsset.byteLength);
  assert.equal(manifest.sha256, createHash("sha256").update(artifactAsset).digest("hex"));
  assert.equal(manifest.integrity, `sha512-${createHash("sha512").update(artifactAsset).digest("base64")}`);
  assert.equal(manifest.download_url, `https://goldkey-edge-storefront.noah-ing.workers.dev/.well-known/goldkey-guard/${artifactName}`);

  const requested = [];
  const distributionAssets = {
    async fetch(request) {
      const pathname = new URL(request.url).pathname;
      requested.push(pathname);
      if (pathname === `/.well-known/goldkey-guard/${artifactName}`) return new Response(artifactAsset);
      if (pathname === `/.well-known/goldkey-guard/${artifactName}.integrity.json`) return new Response(manifestAsset);
      if (pathname === `/.well-known/goldkey-guard/${previousName}`) return new Response(previousAsset);
      return new Response("not found", { status: 404 });
    },
  };
  const worker = createWorker();
  const artifactResponse = await worker.fetch(
    new Request(`https://edge.example/.well-known/goldkey-guard/${artifactName}`),
    env({ ASSETS: distributionAssets }),
  );
  assert.equal(artifactResponse.status, 200);
  assert.equal(artifactResponse.headers.get("content-type"), "application/gzip");
  assert.deepEqual(Buffer.from(await artifactResponse.arrayBuffer()), artifactAsset);

  const manifestResponse = await worker.fetch(
    new Request(`https://edge.example/.well-known/goldkey-guard/${artifactName}.integrity.json`),
    env({ ASSETS: distributionAssets }),
  );
  assert.equal(manifestResponse.status, 200);
  assert.match(manifestResponse.headers.get("content-type"), /^application\/json/);
  assert.deepEqual(Buffer.from(await manifestResponse.arrayBuffer()), manifestAsset);

  const previousResponse = await worker.fetch(
    new Request(`https://edge.example/.well-known/goldkey-guard/${previousName}`),
    env({ ASSETS: distributionAssets }),
  );
  assert.equal(previousResponse.status, 200);
  assert.deepEqual(Buffer.from(await previousResponse.arrayBuffer()), previousAsset);

  const nearMiss = await worker.fetch(
    new Request("https://edge.example/.well-known/goldkey-guard/latest.tgz"),
    env({ ASSETS: distributionAssets }),
  );
  assert.equal(nearMiss.status, 404);
  assert.deepEqual(requested, [
    `/.well-known/goldkey-guard/${artifactName}`,
    `/.well-known/goldkey-guard/${artifactName}.integrity.json`,
    `/.well-known/goldkey-guard/${previousName}`,
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
  const postedCatalog = await body(await worker.fetch(new Request("https://edge.example/v1/catalog"), env()));
  const paygo = openapi.paths["/v1/paygo/execute"].post;
  const actionGate = openapi.paths["/v1/action-gate"].post;
  assert.equal(paygo.tags[0], "origin");
  assert.equal(actionGate.tags[0], "origin");
  assert.equal(actionGate.operationId, "goldkey_action_gate_ai_agent_tool_call_preflight");
  assert.match(openapi.info["x-guidance"], /POST \/v1\/action-gate/);
  assert.match(openapi.info["x-guidance"], /POST \/v1\/paygo\/execute/);
  assert.match(openapi.info["x-guidance"], /0\.01 USDC/);
  assert.match(paygo.summary, /^\$0\.01-USDC Base x402 access to seven deterministic tools:/);
  assert.match(paygo.description, /^For \$0\.01 USDC per x402 call on Base, execute one of seven deterministic utilities:/);
  const deterministicTools = ["json.canonicalize", "json.validate", "security.prompt_scan", "security.url_check", "policy.spend_check", "text.normalize", "action.gate"];
  assert.deepEqual(paygo.requestBody.content["application/json"].schema.properties.tool.enum, deterministicTools);
  assert.deepEqual(postedCatalog.tools.map(({ name }) => name), deterministicTools);
  assert.equal(postedCatalog.tools.length, 7);
  for (const tool of deterministicTools) {
    assert.match(paygo.summary, new RegExp(tool.replace(".", "\\.")));
    assert.match(paygo.description, new RegExp(tool.replace(".", "\\.")));
  }
  assert.match(paygo.description, /validates a fixed bounded envelope before payment verification/);
  assert.match(paygo.description, /settles payment, and only then releases it/);
  assert.match(paygo.description, /failed evaluation or settlement does not return a tool result/);
  assert.match(paygo.description, /successfully settled retry is a new purchase/);
  assert.deepEqual(paygo["x-payment-info"], {
    price: { mode: "fixed", currency: "USD", amount: "0.01" },
    protocols: [{ x402: {} }],
  });
  assert.equal(paygo.responses[402].description, "Payment Required");
  assert.equal(paygo.responses[200].content["application/json"].schema.$ref, "#/components/schemas/PaygoResponse");
  assert.match(actionGate.summary, /^\$0\.01 AI-agent tool-call preflight:/);
  assert.match(actionGate.summary, /ALLOW, REVIEW, or BLOCK/);
  assert.match(actionGate.description, /ALLOW, REVIEW, or BLOCK/);
  assert.match(actionGate.description, /does not execute the proposed action/);
  assert.match(actionGate.description, /validates a fixed bounded envelope before payment verification/);
  assert.match(actionGate.description, /settles payment, and only then releases it/);
  assert.doesNotMatch(`${actionGate.summary} ${actionGate.description}`, /signed receipt/i);
  assert.deepEqual(actionGate["x-payment-info"], paygo["x-payment-info"]);
  assert.equal(actionGate.requestBody.content["application/json"].schema.$ref, "#/components/schemas/ActionGateInput");
  assert.equal(actionGate.responses[200].content["application/json"].schema.$ref, "#/components/schemas/ActionGateResponse");
  assert.equal(actionGate.responses[402].description, "Payment Required");
  assert.equal(openapi.paths["/v1/purchase/quote"].post.responses[200].content["application/json"].schema.$ref, "#/components/schemas/CommerceResponse");
  assert.ok(openapi.components.schemas.CommerceResponse.required.includes("recommendation"));
  assert.ok(openapi.components.schemas.CommerceResponse.required.includes("unsigned_transactions"));
  assert.deepEqual(openapi.components.schemas.AuthChallengeRequest.required, ["wallet", "token_id"]);
  assert.deepEqual(openapi.components.schemas.AuthVerifyRequest.required, ["challenge_id", "signature"]);
  assert.equal(openapi.paths["/v1/auth/challenge"].post.requestBody.content["application/json"].schema.$ref, "#/components/schemas/AuthChallengeRequest");
  assert.equal(openapi.paths["/v1/auth/verify"].post.requestBody.content["application/json"].schema.$ref, "#/components/schemas/AuthVerifyRequest");
  assert.deepEqual(openapi.components.schemas.PaygoResponse.required, ["request_id", "tool", "tool_version", "input_sha256", "result", "payment", "upgrade"]);
  const catalogActionGate = postedCatalog.tools.find(({ name }) => name === "action.gate");
  assert.equal(catalogActionGate.version, "1.0.0");
  assert.equal(catalogActionGate.quota_units, 1);
  assert.equal(catalogActionGate.paygo_price_usdc, "0.01");
  assert.match(catalogActionGate.description, /reproducible receipt hash/);
  assert.deepEqual(catalogActionGate.input_schema, openapi.components.schemas.ActionGateInput);
  const gateSchema = openapi.components.schemas.ActionGateInput;
  assert.deepEqual(gateSchema.required, ["action"]);
  assert.deepEqual(gateSchema.properties.action.required, ["name", "effect"]);
  assert.deepEqual(gateSchema.dependentRequired, { payload: ["schema"], schema: ["payload"] });
  assert.deepEqual(gateSchema.properties.action.properties.effect.enum, ["read", "write", "network", "payment", "execute"]);
  assert.deepEqual(gateSchema.properties.spend.required, ["proposal", "mandate", "now"]);
  assert.deepEqual(gateSchema.properties.spend.properties.proposal.required, ["amount_atomic", "asset", "counterparty"]);
  assert.equal(gateSchema.properties.spend.properties.proposal.properties.amount_atomic.pattern, "^(0|[1-9]\\d*)$");
  assert.equal(gateSchema.properties.spend.properties.mandate.properties.max_per_tx_atomic.pattern, "^(0|[1-9]\\d*)$");
  assert.deepEqual(gateSchema.properties.spend.properties.mandate.required, ["max_per_tx_atomic", "max_period_atomic", "allowed_assets", "expires_at"]);
  assert.equal(gateSchema.additionalProperties, false);
  for (const ref of collectRefs(openapi)) {
    assert.match(ref, /^#\//, `${ref} must be a local OpenAPI reference`);
    assert.ok(resolveLocalRef(openapi, ref), `${ref} must resolve within the OpenAPI document`);
  }
  assert.match(openapi.paths["/v1/purchase/quote"].post.description, /never signs or submits/);
  const demo = await body(await worker.fetch(new Request("https://edge.example/v1/demo"), env()));
  assert.equal(demo.free_fixed_examples, true);
  assert.equal(demo.examples[0].tool, "security.prompt_scan");
  assert.equal(demo.examples[1].tool, "policy.spend_check");
  const actionGateDemo = demo.examples[2];
  assert.equal(actionGateDemo.tool, "action.gate");
  assert.equal(actionGateDemo.result.decision, "ALLOW");
  assert.deepEqual(actionGateDemo.result.reason_codes, []);
  assert.equal(actionGateDemo.result.receipt_format, "goldkey-action-gate-v1");
  assert.equal(actionGateDemo.result.receipt_canonicalization, "goldkey-c14n-v1");
  assert.equal(actionGateDemo.result.receipt_hash_algorithm, "SHA-256");
  assert.deepEqual(actionGateDemo.result.receipt_preimage_fields, ["receipt_format", "request_sha256", "decision", "reason_codes", "checks"]);
  assert.match(actionGateDemo.result.limitation, /ALLOW does not guarantee safety/);
  assert.equal(actionGateDemo.input_sha256, canonicalSha256({ tool: "action.gate", version: "1.0.0", input: actionGateDemo.input }));
  assert.equal(actionGateDemo.result.request_sha256, actionGateDemo.input_sha256);
  assert.equal(actionGateDemo.result.receipt_sha256, canonicalSha256({
    receipt_format: actionGateDemo.result.receipt_format,
    request_sha256: actionGateDemo.result.request_sha256,
    decision: actionGateDemo.result.decision,
    reason_codes: actionGateDemo.result.reason_codes,
    checks: actionGateDemo.result.checks,
  }));
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

  const gateInput = { action: { name: "inspect_before_fetch", effect: "network" }, url: "https://8.8.8.8/resource" };
  const gate = await worker.fetch(new Request("https://edge.example/v1/action-gate?trace=gate", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "payment-signature": "signed-gate-payment",
    },
    body: JSON.stringify(gateInput),
  }), env());
  assert.equal(gate.status, 200);
  const gateEcho = await body(gate);
  assert.equal(gateEcho.path, "/v1/action-gate");
  assert.equal(gateEcho.query, "?trace=gate");
  assert.equal(gateEcho.payment_signature, "signed-gate-payment");
  assert.equal(gateEcho.body, JSON.stringify(gateInput));

  const before = network.requests.length;
  const unknown = await worker.fetch(new Request("https://edge.example/v1/admin/secrets"), env());
  assert.equal(unknown.status, 404);
  const wrongMethod = await worker.fetch(new Request("https://edge.example/v1/auth/challenge"), env());
  assert.equal(wrongMethod.status, 405);
  const wrongGateMethod = await worker.fetch(new Request("https://edge.example/v1/action-gate"), env());
  assert.equal(wrongGateMethod.status, 405);
  assert.equal(network.requests.length, before);
});

test("pilot applications proxy only the exact enabled POST and replace spoofable source headers", async () => {
  const network = makeNetwork();
  const worker = createWorker({ fetchImpl: network.fetchImpl });
  const configured = env({
    PILOT_APPLICATIONS_ENABLED: "true",
    PILOT_EDGE_SECRET,
  });
  const application = {
    name: "Ada Operator",
    email: "ada@example.com",
    company: "Example Labs",
    agent_stack: "Custom MCP client",
    connector: "Billing MCP",
    action: "Create a refund only below an operator-controlled limit",
    timeline: "This month",
    website: "",
    budget_confirmed: true,
  };
  const response = await worker.fetch(new Request("https://edge.example/v1/pilot/applications", {
    method: "POST",
    headers: {
      accept: "text/secret",
      authorization: "Bearer must-not-forward",
      cookie: "session=must-not-forward",
      "content-type": "application/json",
      "idempotency-key": "pilot-00000000-0000-4000-8000-000000000001",
      "x-api-key": "must-not-forward",
      "x-forwarded-for": "198.51.100.99",
      "x-goldkey-edge": "spoofed",
      "x-goldkey-pilot-edge": "spoofed-secret",
      "x-goldkey-client-address": "198.51.100.98",
      "cf-connecting-ip": "203.0.113.42",
    },
    body: JSON.stringify(application),
  }), configured);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("x-goldkey-pilot-edge"), null);
  assert.equal(response.headers.get("x-goldkey-client-address"), null);
  assert.equal(response.headers.get("access-control-allow-origin"), null);
  const echo = await body(response);
  assert.equal(echo.path, "/v1/pilot/applications");
  assert.equal(echo.query, "");
  assert.equal(echo.method, "POST");
  assert.equal(echo.authorization, null);
  assert.equal(echo.cookie, null);
  assert.equal(echo.api_key, null);
  assert.equal(echo.accept, null);
  assert.equal(echo.pilot_edge, PILOT_EDGE_SECRET);
  assert.equal(echo.client_address, "203.0.113.42");
  assert.equal(echo.forwarded_for, null);
  assert.equal(echo.goldkey_edge, null);
  assert.equal(echo.idempotency_key, "pilot-00000000-0000-4000-8000-000000000001");
  assert.equal(echo.body, JSON.stringify(application));

  const originRequest = network.requests.at(-1);
  assert.equal(originRequest.target.origin, "https://origin.example");
  assert.deepEqual([...originRequest.init.headers.keys()].sort(), [
    "content-type",
    "idempotency-key",
    "x-goldkey-client-address",
    "x-goldkey-pilot-edge",
  ]);
  assert.equal(originRequest.init.headers.get("x-goldkey-pilot-edge"), PILOT_EDGE_SECRET);
  assert.equal(originRequest.init.headers.get("x-goldkey-client-address"), "203.0.113.42");
  assert.equal(originRequest.init.headers.get("x-forwarded-for"), null);

  const preflight = await worker.fetch(new Request("https://edge.example/v1/pilot/applications", { method: "OPTIONS" }), configured);
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get("access-control-allow-methods"), "POST,OPTIONS");
  assert.equal(preflight.headers.get("access-control-allow-headers"), "content-type,idempotency-key");
  assert.equal(preflight.headers.get("access-control-allow-origin"), null);

  const beforeFailures = network.requests.length;
  const wrongMethod = await worker.fetch(new Request("https://edge.example/v1/pilot/applications"), configured);
  assert.equal(wrongMethod.status, 405);
  assert.equal(wrongMethod.headers.get("allow"), "POST");
  for (const path of [
    "/v1/pilot/application",
    "/v1/pilot/applications/",
    "/v1/pilot/applications/anything",
  ]) {
    const nearMiss = await worker.fetch(new Request(`https://edge.example${path}`, { method: "POST" }), configured);
    assert.equal(nearMiss.status, 404, path);
    const nearMissPreflight = await worker.fetch(new Request(`https://edge.example${path}`, { method: "OPTIONS" }), configured);
    assert.equal(nearMissPreflight.status, 404, `OPTIONS ${path}`);
  }
  const query = await worker.fetch(new Request("https://edge.example/v1/pilot/applications?source=storefront", {
    method: "POST",
    headers: { "content-type": "application/json", "idempotency-key": "pilot-query-0000001" },
    body: JSON.stringify(application),
  }), configured);
  assert.equal(query.status, 400);
  assert.equal((await body(query)).error.code, "invalid_request");
  const wrongContentType = await worker.fetch(new Request("https://edge.example/v1/pilot/applications", {
    method: "POST",
    headers: { "content-type": "text/plain", "idempotency-key": "pilot-content-type-0001" },
    body: JSON.stringify(application),
  }), configured);
  assert.equal(wrongContentType.status, 415);
  assert.equal((await body(wrongContentType)).error.code, "unsupported_media_type");
  const missingIdempotency = await worker.fetch(new Request("https://edge.example/v1/pilot/applications", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(application),
  }), configured);
  assert.equal(missingIdempotency.status, 400);
  assert.equal((await body(missingIdempotency)).error.code, "invalid_idempotency_key");
  assert.equal(network.requests.length, beforeFailures);

  const oversizedNetwork = makeNetwork();
  const oversizedWorker = createWorker({ fetchImpl: oversizedNetwork.fetchImpl });
  const oversized = await oversizedWorker.fetch(new Request("https://edge.example/v1/pilot/applications", {
    method: "POST",
    headers: { "content-type": "application/json", "idempotency-key": "pilot-oversized-0001" },
    body: "x".repeat((16 * 1024) + 1),
  }), configured);
  assert.equal(oversized.status, 413);
  assert.equal((await body(oversized)).error.code, "request_too_large");
  assert.equal(oversizedNetwork.requests.length, 0);
});

test("pilot applications remain undiscoverable when disabled and never proxy without the edge secret", async () => {
  for (const flag of [undefined, "false", "TRUE", "1", true]) {
    const network = makeNetwork();
    const worker = createWorker({ fetchImpl: network.fetchImpl });
    const configured = env({ PILOT_APPLICATIONS_ENABLED: flag, PILOT_EDGE_SECRET });
    const response = await worker.fetch(new Request("https://edge.example/v1/pilot/applications", {
      method: "POST",
      headers: { "content-type": "application/json", "idempotency-key": "pilot-disabled-0001" },
      body: "{}",
    }), configured);
    assert.equal(response.status, 404, String(flag));
    assert.equal(response.headers.get("access-control-allow-origin"), null);
    const preflight = await worker.fetch(new Request("https://edge.example/v1/pilot/applications", { method: "OPTIONS" }), configured);
    assert.equal(preflight.status, 404, `OPTIONS ${String(flag)}`);
    assert.equal(preflight.headers.get("access-control-allow-origin"), null);
    assert.equal(network.requests.length, 0);
  }

  for (const secret of [undefined, "", "too-short"] ) {
    const network = makeNetwork();
    const worker = createWorker({ fetchImpl: network.fetchImpl });
    const response = await worker.fetch(new Request("https://edge.example/v1/pilot/applications", {
      method: "POST",
      headers: { "content-type": "application/json", "idempotency-key": "pilot-no-secret-0001" },
      body: "{}",
    }), env({ PILOT_APPLICATIONS_ENABLED: "true", PILOT_EDGE_SECRET: secret }));
    assert.equal(response.status, 503, String(secret));
    assert.equal(response.headers.get("access-control-allow-origin"), null);
    assert.equal((await body(response)).error.code, "pilot_applications_unavailable");
    assert.equal(network.requests.length, 0);
  }
});

test("pilot intake remains separate from public agent discovery", async () => {
  const worker = createWorker({ fetchImpl: makeNetwork().fetchImpl });
  const configured = env({ PILOT_APPLICATIONS_ENABLED: "true", PILOT_EDGE_SECRET });
  const openapi = await body(await worker.fetch(new Request("https://edge.example/openapi.json"), configured));
  const catalogResponse = await body(await worker.fetch(new Request("https://edge.example/v1/catalog"), configured));
  const agent = await body(await worker.fetch(new Request("https://edge.example/.well-known/agent.json"), configured));
  assert.equal(openapi.paths["/v1/pilot/applications"], undefined);
  assert.equal(JSON.stringify(catalogResponse).includes("/v1/pilot/applications"), false);
  assert.equal(JSON.stringify(agent).includes("/v1/pilot/applications"), false);
});

test("Guard discovery and proxy routes fail closed unless GUARD_ENABLED is exactly true", async () => {
  for (const flag of [undefined, "false", "TRUE", "1", true]) {
    const network = makeNetwork();
    const worker = createWorker({ fetchImpl: network.fetchImpl });
    const configured = env({ GUARD_ENABLED: flag });
    const openapi = await body(await worker.fetch(new Request("https://edge.example/openapi.json"), configured));
    const postedCatalog = await body(await worker.fetch(new Request("https://edge.example/v1/catalog"), configured));
    const agent = await body(await worker.fetch(new Request("https://edge.example/.well-known/agent.json"), configured));
    assert.equal(openapi.paths["/guard/terms"], undefined);
    assert.equal(openapi.paths["/.well-known/goldkey-guard-keys.json"], undefined);
    assert.equal(openapi.paths["/v1/guard/revocations"], undefined);
    assert.equal(openapi.paths["/v1/guard/paygo/authorize/network"], undefined);
    assert.equal(postedCatalog.guard, undefined);
    assert.equal(agent.guard, undefined);

    for (const [path, method] of [
      ["/guard/terms", "GET"],
      ["/.well-known/goldkey-guard-keys.json", "GET"],
      ["/v1/guard/policies", "POST"],
      ["/v1/guard/revocations", "POST"],
      ["/v1/guard/paygo/authorize/network", "POST"],
    ]) {
      const response = await worker.fetch(new Request(`https://edge.example${path}`, { method }), configured);
      assert.equal(response.status, 404, `${String(flag)} ${path}`);
      const preflight = await worker.fetch(new Request(`https://edge.example${path}`, { method: "OPTIONS" }), configured);
      assert.equal(preflight.status, 404, `${String(flag)} OPTIONS ${path}`);
    }
    for (const path of ["/guard/terms/", "/.well-known/goldkey-guard-keys.json/", "/v1/guard"]) {
      const preflight = await worker.fetch(new Request(`https://edge.example${path}`, { method: "OPTIONS" }), configured);
      assert.equal(preflight.status, 404, `${String(flag)} OPTIONS ${path}`);
    }
    assert.equal(network.requests.length, 0);
  }
});

test("enabled Guard discovery is beta-only and proxies only the exact control-plane routes", async () => {
  const network = makeNetwork();
  const worker = createWorker({ fetchImpl: network.fetchImpl });
  const configured = env({ GUARD_ENABLED: "true" });
  const openapi = await body(await worker.fetch(new Request("https://edge.example/openapi.json"), configured));
  const postedCatalog = await body(await worker.fetch(new Request("https://edge.example/v1/catalog"), configured));
  const agent = await body(await worker.fetch(new Request("https://edge.example/.well-known/agent.json"), configured));

  assert.equal(postedCatalog.guard.status, "beta");
  assert.equal(postedCatalog.guard.availability, "feature_gated");
  assert.equal(postedCatalog.guard.pass_included, false);
  assert.equal(postedCatalog.guard.pricing.mcp_or_https_authorization_usdc, "0.05");
  assert.equal(postedCatalog.guard.pricing.evm_authorization_usdc, "0.10");
  assert.equal(postedCatalog.guard.routes.terms, "https://edge.example/guard/terms");
  assert.equal(postedCatalog.guard.routes.revocation, "https://edge.example/v1/guard/revocations");
  assert.equal(postedCatalog.guard.routes.reconcile_commit_template, "https://edge.example/v1/guard/executions/{executionId}/reconcile-commit");
  assert.equal(postedCatalog.guard.distribution.artifact, "https://edge.example/.well-known/goldkey-guard/goldkey-enforcer-0.2.0.tgz");
  assert.equal(postedCatalog.guard.distribution.integrity_manifest, "https://edge.example/.well-known/goldkey-guard/goldkey-enforcer-0.2.0.tgz.integrity.json");
  assert.equal(postedCatalog.guard.distribution.size_bytes, 119159);
  assert.equal(postedCatalog.guard.distribution.sha256, "aeb3d11c02a1ac15ebc8a9c4541b9ca481a32fe1ac23b8668d99ffb88487fe36");
  assert.deepEqual(postedCatalog.guard.distribution.adapters, ["mcp_stdio", "agentcash", "base_wallet"]);
  assert.match(postedCatalog.guard.topology.hosted_authorizer, /never receives upstream credentials/i);
  assert.match(postedCatalog.guard.topology.local_enforcer, /operator-controlled execution-path/i);
  assert.equal(agent.guard.status, "beta");

  const exactPaths = [
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
  for (const path of exactPaths) assert.ok(openapi.paths[path], path);
  assert.equal(openapi.paths["/v1/guard/authorize/pass"], undefined);
  assert.equal(openapi.paths["/v1/guard/executions/{executionId}"]?.get, undefined);
  assert.equal(openapi.paths["/v1/guard/paygo/authorize/network"].post["x-payment-info"].price.amount, "0.05");
  assert.equal(openapi.paths["/v1/guard/paygo/authorize/evm"].post["x-payment-info"].price.amount, "0.10");
  const edgeEvmTransaction = openapi.components.schemas.GuardEvmRequest.properties.call.oneOf[0].properties.transaction;
  assert.deepEqual(edgeEvmTransaction.required, [
    "chain_id", "from", "value_atomic", "data", "nonce", "gas_limit",
    "max_fee_per_gas_atomic", "max_priority_fee_per_gas_atomic",
  ]);
  assert.equal(edgeEvmTransaction.properties.type.const, "eip1559");
  assert.equal(edgeEvmTransaction.properties.access_list.maxItems, 0);
  const installationPattern = "^gki_[A-Za-z0-9_-]{43}$";
  assert.equal(openapi.components.schemas.GuardInstallation.properties.installation_id.pattern, installationPattern);
  assert.equal(openapi.components.schemas.GuardNetworkRequest.properties.installation_id.pattern, installationPattern);
  assert.equal(openapi.components.schemas.GuardEvmRequest.properties.installation_id.pattern, installationPattern);
  assert.equal(openapi.components.schemas.GuardCommit.properties.installation_id.pattern, installationPattern);
  assert.equal(openapi.components.schemas.GuardReconciledCommit.properties.commit.$ref, "#/components/schemas/GuardCommit");
  assert.equal(openapi.components.schemas.GuardReconciledCommit.properties.payment_proof.properties.payment_payload.properties.accepted.properties.network.const, "eip155:8453");
  assert.equal(openapi.components.schemas.GuardCompletion.properties.installation_id.pattern, installationPattern);
  assert.ok(openapi.components.schemas.GuardInstallation.required.includes("key_proof"));
  const policyConnectors = openapi.components.schemas.GuardPolicy.properties.connectors.items.oneOf;
  assert.equal(policyConnectors[0].properties.tools.items.properties.arguments_schema.type, "object");
  assert.equal(policyConnectors[1].properties.operations.items.properties.query_schema.type, "object");
  assert.equal(policyConnectors[1].properties.operations.items.properties.body_schema.type, "object");
  assert.equal(openapi.paths["/v1/guard/revocations"].post.requestBody.content["application/json"].schema.$ref, "#/components/schemas/GuardRevocation");
  assert.deepEqual(openapi.components.schemas.GuardRevocation.required, ["schema", "target_kind", "target_id", "operator_wallet", "audience", "issued_at", "signature"]);
  assert.match(openapi.info.description, /feature-gated GoldKey Guard beta/);
  assert.match(openapi.info.description, /hosted authorizer never forwards calls/);

  const proxyCases = [
    ["/guard/terms", "GET"],
    ["/.well-known/goldkey-guard-keys.json", "GET"],
    ["/v1/guard/policies", "POST"],
    ["/v1/guard/installations", "POST"],
    ["/v1/guard/revocations", "POST"],
    ["/v1/guard/paygo/authorize/network", "POST"],
    ["/v1/guard/paygo/authorize/evm", "POST"],
    ["/v1/guard/executions/receipt-1/commit", "POST"],
    ["/v1/guard/executions/receipt-1/reconcile-commit", "POST"],
    ["/v1/guard/executions/receipt-1/complete", "POST"],
  ];
  for (const [path, method] of proxyCases) {
    const response = await worker.fetch(new Request(`https://edge.example${path}`, {
      method,
      headers: method === "POST" ? { authorization: "Bearer must-not-forward", cookie: "secret=session", "x-api-key": "must-not-forward", "content-type": "application/json", "payment-signature": "signed-guard-payment" } : undefined,
      body: method === "POST" ? JSON.stringify({ route: path }) : undefined,
    }), configured);
    assert.equal(response.status, 200, path);
    const echo = await body(response);
    assert.equal(echo.path, path);
    assert.equal(echo.method, method);
    if (method === "POST") assert.equal(echo.payment_signature, "signed-guard-payment");
    assert.equal(echo.authorization, null);
    assert.equal(echo.cookie, null);
    assert.equal(echo.api_key, null);
    assert.match(response.headers.get("access-control-expose-headers"), /x-goldkey-idempotent-replay/);
  }

  for (const path of proxyCases.map(([value]) => value)) {
    const preflight = await worker.fetch(new Request(`https://edge.example${path}`, { method: "OPTIONS" }), configured);
    assert.equal(preflight.status, 204, `OPTIONS ${path}`);
  }

  const before = network.requests.length;
  const lookup = await worker.fetch(new Request("https://edge.example/v1/guard/executions/receipt-1"), configured);
  assert.equal(lookup.status, 404);
  const wildcard = await worker.fetch(new Request("https://edge.example/v1/guard/anything", { method: "POST" }), configured);
  assert.equal(wildcard.status, 404);
  const wildcardPreflight = await worker.fetch(new Request("https://edge.example/v1/guard/anything", { method: "OPTIONS" }), configured);
  assert.equal(wildcardPreflight.status, 404);
  for (const path of ["/guard/terms/", "/.well-known/goldkey-guard-keys.json/", "/v1/guard"]) {
    const nearMissPreflight = await worker.fetch(new Request(`https://edge.example${path}`, { method: "OPTIONS" }), configured);
    assert.equal(nearMissPreflight.status, 404, `OPTIONS ${path}`);
  }
  const invalidExecution = await worker.fetch(new Request("https://edge.example/v1/guard/executions/%2F/commit", { method: "POST" }), configured);
  assert.equal(invalidExecution.status, 404);
  const wrongMethod = await worker.fetch(new Request("https://edge.example/v1/guard/policies"), configured);
  assert.equal(wrongMethod.status, 405);
  assert.equal(wrongMethod.headers.get("allow"), "POST");
  assert.equal(network.requests.length, before);
});

test("Wrangler keeps Sepolia Guard disabled and intentionally enables mainnet", () => {
  const wrangler = readFileSync(`${EDGE_ROOT}/wrangler.toml`, "utf8");
  assert.equal((wrangler.match(/^GUARD_ENABLED = "false"$/gm) ?? []).length, 1);
  assert.equal((wrangler.match(/^GUARD_ENABLED = "true"$/gm) ?? []).length, 1);
  assert.match(wrangler, /\[env\.mainnet\.vars\][\s\S]*?GUARD_ENABLED = "true"/);
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
