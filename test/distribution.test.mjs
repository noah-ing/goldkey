import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

import {
  RELEASE_IDENTITY_SOURCE,
  isDirectExecution,
  resolveRuntimeConfig,
  run,
  runCli,
  validateIdentityPayload,
  validateReleaseIdentity,
} from "../distribution/goldkey-agent-utilities/scripts/goldkey-client.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const skillPath = resolve(here, "../distribution/goldkey-agent-utilities/SKILL.md");
const openaiMetadataPath = resolve(here, "../distribution/goldkey-agent-utilities/agents/openai.yaml");
const guardReferencePath = resolve(here, "../distribution/goldkey-agent-utilities/references/guard-beta.md");
const passReferencePath = resolve(here, "../distribution/goldkey-agent-utilities/references/pass-and-keys.md");
const CONTRACT = "0x1111111111111111111111111111111111111111";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const TERMS_HASH = `0x${"ab".repeat(32)}`;
const RELEASE = Object.freeze({
  origin: "https://goldkey.example",
  chainId: 8453,
  contract: CONTRACT,
  usdc: USDC,
  termsHash: TERMS_HASH,
});

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function paymentRequiredResponse(overrides = {}, resourcePath = "/v1/paygo/execute", challengeOverrides = {}) {
  const challenge = {
    x402Version: 2,
    resource: { url: `https://goldkey.example${resourcePath}` },
    accepts: [{
      scheme: "exact",
      network: "eip155:8453",
      amount: "10000",
      asset: USDC,
      payTo: "0xd6b7E00FcD46966676F554fE0455BfF739e85b1b",
      maxTimeoutSeconds: 300,
      ...overrides,
    }],
    ...challengeOverrides,
  };
  return new Response("{}", {
    status: 402,
    headers: {
      "content-type": "application/json",
      "payment-required": Buffer.from(JSON.stringify(challenge)).toString("base64"),
    },
  });
}

function offer(overrides = {}) {
  return {
    schema: "goldkey.offer.v1",
    price: { chain_id: 8453, token_address: USDC },
    contract: { address: CONTRACT, terms_hash: TERMS_HASH, terms_uri: "https://goldkey.example/terms" },
    alternative: { endpoint: "https://goldkey.example/v1/paygo/execute" },
    discovery: {
      catalog_url: "https://goldkey.example/v1/catalog",
      quote_url: "https://goldkey.example/v1/purchase/quote",
    },
    ...overrides,
  };
}

function commerce(overrides = {}) {
  return {
    schema: "goldkey.commerce-response.v1",
    chain_id: 8453,
    contract: CONTRACT,
    payment_token: USDC,
    terms_hash: TERMS_HASH,
    terms_uri: "https://goldkey.example/terms",
    response_schema_url: "https://goldkey.example/schemas/commerce-response-v1.json",
    unsigned_transactions: [],
    ...overrides,
  };
}

test("distribution skill uses portable paths and documented single-line metadata", async () => {
  const source = await readFile(skillPath, "utf8");
  const references = `${await readFile(guardReferencePath, "utf8")}\n${await readFile(passReferencePath, "utf8")}`;
  const bundle = `${source}\n${references}`;
  assert.doesNotMatch(source, /node scripts\//);
  assert.doesNotMatch(references, /node scripts\//);
  const commands = bundle.match(/^\s*node .*goldkey-client\.mjs.*$/gm) ?? [];
  assert.ok(commands.length >= 10);
  for (const command of commands) assert.match(command, /^\s*node "\{baseDir\}\/scripts\/goldkey-client\.mjs"/);

  const metadataLines = source.split("\n").filter((line) => line.startsWith("metadata:"));
  assert.equal(metadataLines.length, 1);
  const metadata = JSON.parse(metadataLines[0].slice("metadata: ".length));
  assert.deepEqual(metadata.openclaw.requires.bins, ["node"]);
  assert.equal(metadata.openclaw.homepage, "https://github.com/noah-ing/goldkey");
  assert.equal(metadata.openclaw.envVars.some(({ name }) => name === "GOLDKEY_API_URL"), false);
  assert.match(source, /Node\.js \*\*22 or newer\*\*/);
  assert.ok(source.split("\n").length < 150, "SKILL.md should keep variant details in references");
  assert.doesNotMatch(bundle, /\baudited (?:local |beta )?(?:enforcer|artifact|SDK)\b/i);
});

test("distribution skill leads with Action Gate and keeps interface metadata aligned", async () => {
  const source = await readFile(skillPath, "utf8");
  const metadata = await readFile(openaiMetadataPath, "utf8");

  assert.match(source, /^# GoldKey Action Gate & Guard Beta$/m);
  assert.match(source, /GoldKey has two paid security layers/);
  assert.match(source, /returns `ALLOW`, `REVIEW`, or `BLOCK`/);
  assert.match(source, /One settled x402 call costs exactly \*\*0\.01 USDC\*\*/);
  assert.match(source, /The hash is deterministic but is not a signature, payment proof, attestation, or proof of execution/);
  assert.match(source, /Reproduce `receipt_sha256` with `goldkey-c14n-v1` canonical JSON/);
  assert.match(source, /`receipt_format`, `request_sha256`, `decision`, `reason_codes`, and `checks`/);
  assert.doesNotMatch(source, /\bsigned receipt\b/i);
  assert.match(source, /Read \[references\/pass-and-keys\.md\]/);
  assert.match(source, /\*\*\$10,000 guarded integration pilot\*\*/);
  assert.match(source, /two independently accepted \*\*\$5,000 milestones\*\*/);
  assert.match(source, /https:\/\/goldkey-edge-storefront\.noah-ing\.workers\.dev\/#pilot-application/);
  assert.match(source, /not a penetration-test report, certification, production guarantee, or substitute for an independent audit/);

  assert.match(metadata, /display_name: "GoldKey Action Gate & Guard Beta"/);
  assert.match(metadata, /short_description: "Preflight and enforce MCP, HTTPS, and Base-wallet actions"/);
  assert.match(metadata, /default_prompt: "Use \$goldkey-agent-utilities to preflight a proposed action or enforce a real MCP, HTTPS, or Base-wallet call\."/);
});

test("distribution skill describes Guard as feature-gated hosted authorization plus local enforcement", async () => {
  const source = await readFile(skillPath, "utf8");
  const guard = await readFile(guardReferencePath, "utf8");
  const bundle = `${source}\n${guard}`;

  assert.match(source, /Read \[references\/guard-beta\.md\].*before installing the enforcer/);
  assert.match(bundle, /Treat Guard as unavailable unless both live `\/v1\/catalog` and `\/openapi\.json` advertise the `guard` beta/);
  assert.match(bundle, /Read live `\/guard\/terms`/);
  assert.match(bundle, /50-USDC utility pass does not include Guard/);
  assert.match(bundle, /hosted authorizer.*never receives upstream credentials, holds a wallet signer, forwards an actual request, signs a transaction, or broadcasts it/s);
  assert.match(bundle, /operator-controlled local enforcer alone holds the connector credential or execution signer/);
  assert.match(bundle, /restricted to explicitly approved design-partner operator wallets/);
  assert.match(bundle, /installation-key Ed25519 `key_proof`/);
  assert.match(bundle, /MCP `arguments_schema` and HTTPS `query_schema` or `body_schema`/);
  assert.match(bundle, /Guard is advisory rather than enforcement/);
  assert.match(bundle, /`POST \/v1\/guard\/revocations`/);
  assert.match(bundle, /MCP, HTTPS, or AgentCash costs exactly 0\.05 USDC/);
  assert.match(bundle, /supported Base\/EVM decision costs exactly 0\.10 USDC/);
  assert.match(bundle, /There is no pass-funded Guard route and no execution-lookup route in v1/);
  assert.match(bundle, /`ALLOW`, `REVIEW`, and `BLOCK` are billable/);
  assert.match(bundle, /stored authorization without another settlement/);
  assert.match(bundle, /DNS-rebinding-safe resolution and connection pinning/);
  assert.match(bundle, /Durably persist `FORWARDING`/);
  assert.match(bundle, /`outcome_unknown` and never retry them automatically/);
  assert.match(bundle, /Only the exact `guard_payment_not_settled` response may trigger `\/reconcile-commit`/);
  assert.match(bundle, /hard process death after transmitting payment but before receiving the transaction hash remains fail-closed/);
  assert.match(bundle, /Node\.js 22 or newer/);
  assert.match(bundle, /integrity-pinned and tested enforcer artifact/);
  assert.match(bundle, /62dbeb10684e075a9ca7d08862eaa99b30f2c2f958bba3f9cc8ecbd7c212d3e5/);
  assert.match(bundle, /sha512-y0qBohVxB\/5F9DkzXBDKeerlpudXlpHaewj7D4coqLyC9IbBbH7vtZ1bBYyck31hdXiTaNTQOYvwAa\/enm54wQ==/);
  assert.match(bundle, /npm install --ignore-scripts \/absolute\/private\/goldkey-enforcer-0\.2\.1\.tgz/);
  assert.match(bundle, /config-driven `goldkey-mcp-stdio`, `goldkey-agentcash`, `goldkey-wallet`, and `goldkey-wallet-mcp` launchers/);
  assert.match(bundle, /No separate customer authorization client is required/);
  assert.match(bundle, /durable caller-supplied `_meta\["com\.goldkey\/idempotency-key"\]`/);
  assert.match(bundle, /AgentCash 0\.17\.1 lacks socket pinning and redirect control/);
  assert.match(bundle, /different Guard payer wallet/);
  assert.match(bundle, /guard-network-probe --request SIGNED_SYNTHETIC_GUARD_REQUEST_JSON/);
  assert.match(bundle, /Use probes only with a non-secret synthetic request because command arguments may enter shell history/);
  assert.match(bundle, /probe deliberately does not return or verify its authorization/);
  assert.match(bundle, /Use the local enforcer, not these probes, for real calls, registration, revocation, receipt verification, or lifecycle transitions/);
});

test("distribution skill keeps pass economics and credential handling in a focused reference", async () => {
  const source = await readFile(skillPath, "utf8");
  const pass = await readFile(passReferencePath, "utf8");

  assert.match(source, /Read \[references\/pass-and-keys\.md\].*before evaluating a purchase/);
  assert.match(pass, /up to 64 active, revocable, tool-scoped child agents/);
  assert.match(pass, /one shared 10,000-call quota/);
  assert.match(pass, /At exactly 5,000 calls, paygo and one pass both cost 50 USDC/);
  assert.match(pass, /That is not positive savings/);
  assert.match(pass, /Never request, expose, transmit, or store a seed phrase or private key/);
  assert.match(pass, /`GOLDKEY_WALLET_SIGNATURE` through the secret store or provide it on standard input/);
  assert.match(pass, /mode `0600`/);
  assert.match(pass, /fresh, stable idempotency key for each distinct pass-gated request/);
  assert.match(pass, /A child key starts with `gk_`/);
  assert.match(pass, /pass covers Action Gate and component-tool calls, not GoldKey Guard/);
});

test("distribution skill exposes a zero-spend probe and bounded opt-in AgentCash settlement path", async () => {
  const source = await readFile(skillPath, "utf8");
  const endpoint = "https://goldkey-edge-storefront.noah-ing.workers.dev/v1/action-gate";

  assert.match(source, /https:\/\/www\.x402scan\.com\/server\/8447beac-d24b-434a-bd01-5abfdab53f84/);
  assert.match(source, /https:\/\/tryponcho\.com\/tool\/url_aHR0cHM6Ly9nb2xka2V5LWVkZ2Utc3RvcmVmcm9udC5ub2FoLWluZy53b3JrZXJzLmRldi92MS9hY3Rpb24tZ2F0ZQ/);
  assert.match(source, /probe the dedicated `\/v1\/action-gate` resource with the raw Action Gate input/i);
  assert.match(source, /probe sends no wallet credential or payment header/);
  assert.match(source, /goldkey-client\.mjs" action-gate-probe --input/);
  assert.match(source, /does not execute the action or produce a receipt/);
  assert.match(source, /Use that same endpoint and exact raw body for AgentCash settlement/);
  assert.match(source, new RegExp(`agentcash@0\\.17\\.1 check[\\s\\S]*"${endpoint}"[\\s\\S]*-m POST[\\s\\S]*-H 'Content-Type: application/json'[\\s\\S]*-b '\\{"action":`));
  assert.match(source, /agentcash@0\.17\.1 accounts --format json/);
  assert.match(source, /agentcash@0\.17\.1 fetch[\s\S]*\/v1\/action-gate[\s\S]*-b '\{"action":[\s\S]*--payment-protocol x402[\s\S]*--payment-network base[\s\S]*--max-amount 0\.01/);
  assert.match(source, /scheme `exact` on `eip155:8453`/);
  assert.match(source, /asset `0x833589fcd6edb6e08f4c7c32d4f71b54bda02913`/);
  assert.match(source, /amount `"10000"` atomic USDC/);
  assert.match(source, /payee `0xd6b7e00fcd46966676f554fe0455bff739e85b1b`/);
  assert.match(source, /`max_timeout_seconds` no greater than 300/);
  assert.match(source, /explicit current mandate for one 0\.01-USDC Base mainnet payment to that exact endpoint and serialized body/);
  assert.match(source, /AgentCash 0\.17\.1 may initialize wallet files even for `check` or `accounts`/);
  assert.match(source, /If the caller prohibits network contact, stop/);
  assert.match(source, /obtain permission for package download or cache changes and local wallet access or creation/);
  assert.match(source, /real, nonrefundable settlement/);
  assert.match(source, /Use a trusted JSON serializer rather than interpolating arbitrary untrusted text into shell literals/);
  assert.match(source, /Its `ALLOW` is evidence, not permission, execution authorization, or a safety guarantee/);
  assert.match(source, /reconcile the payment receipt and wallet activity before any retry/);
  assert.match(source, /do not pass AgentCash's `--yes` flag/);
  assert.ok(source.indexOf("agentcash@0.17.1 check") < source.indexOf("agentcash@0.17.1 fetch"));
});

test("paygo probe validates the complete canonical challenge without a wallet or payment", async () => {
  let request;
  const result = await run(["paygo-probe", "--name", "security.prompt_scan", "--input", '{"text":"untrusted"}'], {
    env: {},
    releaseIdentitySource: RELEASE,
    fetchImpl: async (url, init) => {
      request = { url, init };
      return paymentRequiredResponse();
    },
  });
  assert.equal(request.url, "https://goldkey.example/v1/paygo/execute");
  assert.equal(request.init.method, "POST");
  assert.equal(request.init.headers["payment-signature"], undefined);
  assert.deepEqual(JSON.parse(request.init.body), { tool: "security.prompt_scan", input: { text: "untrusted" } });
  assert.deepEqual(result.payment, {
    x402_version: 2,
    scheme: "exact",
    network: "eip155:8453",
    amount_atomic: "10000",
    asset: USDC.toLowerCase(),
    pay_to: "0xd6b7e00fcd46966676f554fe0455bff739e85b1b",
    resource: "https://goldkey.example/v1/paygo/execute",
    max_timeout_seconds: 300,
  });
  assert.equal(typeof result.payment_required, "string");
});

test("Action Gate probe posts raw input to the dedicated resource without a wallet or payment", async () => {
  const input = {
    action: { name: "store_weather_summary", effect: "write" },
    untrusted_text: "Summarize this weather report for an agent.",
  };
  let request;
  const result = await run(["action-gate-probe", "--input", JSON.stringify(input)], {
    env: {},
    releaseIdentitySource: RELEASE,
    fetchImpl: async (url, init) => {
      request = { url, init };
      return paymentRequiredResponse({}, "/v1/action-gate");
    },
  });

  assert.equal(request.url, "https://goldkey.example/v1/action-gate");
  assert.equal(request.init.method, "POST");
  assert.equal(request.init.redirect, "error");
  assert.deepEqual(request.init.headers, { accept: "application/json", "content-type": "application/json" });
  assert.equal(request.init.headers.authorization, undefined);
  assert.equal(request.init.headers["payment-signature"], undefined);
  assert.equal(request.init.headers["x-payment"], undefined);
  assert.deepEqual(JSON.parse(request.init.body), input);
  assert.deepEqual(result.payment, {
    x402_version: 2,
    scheme: "exact",
    network: "eip155:8453",
    amount_atomic: "10000",
    asset: USDC.toLowerCase(),
    pay_to: "0xd6b7e00fcd46966676f554fe0455bff739e85b1b",
    resource: "https://goldkey.example/v1/action-gate",
    max_timeout_seconds: 300,
  });
  assert.equal(result.http_status, 402);
  assert.equal(typeof result.payment_required, "string");
});

test("Action Gate probe rejects a challenge for any resource other than the dedicated endpoint", async () => {
  await assert.rejects(
    run(["action-gate-probe", "--input", '{"action":{"name":"read_balance","effect":"read"}}'], {
      env: {},
      releaseIdentitySource: RELEASE,
      fetchImpl: async () => paymentRequiredResponse(),
    }),
    /resource URL does not match the canonical endpoint/,
  );
});

test("Action Gate probe rejects substituted x402 version or payment terms", async () => {
  const argv = ["action-gate-probe", "--input", '{"action":{"name":"read_balance","effect":"read"}}'];
  for (const [overrides, challengeOverrides, pattern] of [
    [{ scheme: "upto" }, {}, /payment scheme must be exact/],
    [{ amount: "10001" }, {}, /amount must be 10000/],
    [{ asset: CONTRACT }, {}, /canonical Base USDC/],
    [{ payTo: CONTRACT }, {}, /GoldKey treasury/],
    [{ network: "eip155:84532" }, {}, /network must be eip155:8453/],
    [{ maxTimeoutSeconds: 301 }, {}, /maxTimeoutSeconds must be 1-300/],
    [{}, { x402Version: 1 }, /challenge must use x402 v2/],
  ]) {
    await assert.rejects(
      run(argv, {
        env: {},
        releaseIdentitySource: RELEASE,
        fetchImpl: async () => paymentRequiredResponse(overrides, "/v1/action-gate", challengeOverrides),
      }),
      pattern,
    );
  }
});

test("paygo probe rejects payment substitution before returning a challenge", async () => {
  for (const [overrides, pattern] of [
    [{ amount: "10001" }, /amount must be 10000/],
    [{ asset: CONTRACT }, /canonical Base USDC/],
    [{ payTo: CONTRACT }, /GoldKey treasury/],
    [{ network: "eip155:84532" }, /network must be eip155:8453/],
    [{ maxTimeoutSeconds: 301 }, /maxTimeoutSeconds must be 1-300/],
  ]) {
    await assert.rejects(
      run(["paygo-probe", "--name", "security.prompt_scan", "--input", '{"text":"untrusted"}'], {
        env: {},
        releaseIdentitySource: RELEASE,
        fetchImpl: async () => paymentRequiredResponse(overrides),
      }),
      pattern,
    );
  }
});

test("Guard client discovers only public keys and validates distinct zero-spend x402 prices", async () => {
  const keyset = {
    schema: "goldkey.guard-receipt-keyset.v1",
    keys: [{ kty: "OKP", crv: "Ed25519", x: "A".repeat(43), kid: "guard-key-1" }],
  };
  assert.deepEqual(await run(["guard-keyset"], {
    env: {},
    releaseIdentitySource: RELEASE,
    fetchImpl: async (url, init) => {
      assert.equal(url, "https://goldkey.example/.well-known/goldkey-guard-keys.json");
      assert.equal(init.method, "GET");
      return jsonResponse(keyset);
    },
  }), keyset);
  const rotatedKeyset = {
    ...keyset,
    keys: [
      keyset.keys[0],
      {
        ...keyset.keys[0],
        x: "B".repeat(43),
        kid: "guard-key-retired",
        not_before: "2026-08-11T00:00:00.000Z",
        signing_not_after: "2026-08-11T00:05:00.000Z",
        revoked_at: "2026-08-11T00:04:00.000Z",
      },
    ],
  };
  assert.deepEqual(await run(["guard-keyset"], {
    env: {},
    releaseIdentitySource: RELEASE,
    fetchImpl: async () => jsonResponse(rotatedKeyset),
  }), rotatedKeyset);
  await assert.rejects(
    run(["guard-keyset"], {
      env: {},
      releaseIdentitySource: RELEASE,
      fetchImpl: async () => jsonResponse({ ...keyset, keys: [keyset.keys[0], { ...keyset.keys[0], x: "B".repeat(43), kid: "unbounded-retired" }] }),
    }),
    /Guard keyset signing interval/,
  );
  await assert.rejects(
    run(["guard-keyset"], {
      env: {},
      releaseIdentitySource: RELEASE,
      fetchImpl: async () => jsonResponse({ ...keyset, keys: [{ ...keyset.keys[0], d: "private" }] }),
    }),
    /Guard keyset public Ed25519 key/,
  );
  await assert.rejects(
    run(["guard-keyset"], {
      env: {},
      releaseIdentitySource: RELEASE,
      fetchImpl: async () => jsonResponse({ ...keyset, private_key: "must-not-be-accepted" }),
    }),
    /Guard keyset fields/,
  );
  await assert.rejects(
    run(["guard-keyset"], {
      env: {},
      releaseIdentitySource: RELEASE,
      fetchImpl: async () => jsonResponse({ ...keyset, keys: [keyset.keys[0], {
        ...keyset.keys[0],
        x: "B".repeat(43),
        not_before: "2026-08-11T00:00:00.000Z",
        signing_not_after: "2026-08-11T00:05:00.000Z",
      }] }),
    }),
    /Guard keyset distinct key IDs/,
  );

  const requestBase = { schema: "goldkey.guard-request.v1", installation_id: "install-1", idempotency_key: "request-0001", issued_at: "2026-08-11T00:00:00.000Z", signature: "A".repeat(86) };
  for (const [command, path, amount, call] of [
    ["guard-network-probe", "/v1/guard/paygo/authorize/network", "50000", { kind: "https", connector_id: "crm", operation_id: "create" }],
    ["guard-evm-probe", "/v1/guard/paygo/authorize/evm", "100000", { kind: "evm_transaction", connector_id: "base", transaction: { chain_id: 8453, from: CONTRACT, to: USDC, value_atomic: "0", data: "0x", nonce: "0", gas_limit: "21000", max_fee_per_gas_atomic: "1000000", max_priority_fee_per_gas_atomic: "100000", type: "eip1559", access_list: [] } }],
  ]) {
    const signedRequest = { ...requestBase, call };
    let request;
    const result = await run([command, "--request", JSON.stringify(signedRequest)], {
      env: {},
      releaseIdentitySource: RELEASE,
      fetchImpl: async (url, init) => {
        request = { url, init };
        return paymentRequiredResponse({ amount }, path);
      },
    });
    assert.equal(request.url, `https://goldkey.example${path}`);
    assert.equal(request.init.headers["payment-signature"], undefined);
    assert.deepEqual(JSON.parse(request.init.body), signedRequest);
    assert.equal(result.http_status, 402);
    assert.equal(result.payment.amount_atomic, amount);
    await assert.rejects(
      run([command, "--request", JSON.stringify(signedRequest)], {
        env: {},
        releaseIdentitySource: RELEASE,
        fetchImpl: async () => paymentRequiredResponse({ amount: "10000" }, path),
      }),
      new RegExp(`amount must be ${amount}`),
    );
  }
});

test("Guard probe recognizes an exact unexpired replay without treating it as a new purchase", async () => {
  const signedRequest = { schema: "goldkey.guard-request.v1", installation_id: "install-1", idempotency_key: "request-0001", issued_at: "2026-08-11T00:00:00.000Z", call: { kind: "https", connector_id: "crm", operation_id: "create" }, signature: "A".repeat(86) };
  const authorization = { schema: "goldkey.guard-authorization-envelope.v1", receipt: { decision: "BLOCK" } };
  const result = await run(["guard-network-probe", "--request", JSON.stringify(signedRequest)], {
    env: {},
    releaseIdentitySource: RELEASE,
    fetchImpl: async () => new Response(JSON.stringify(authorization), {
      status: 200,
      headers: { "content-type": "application/json", "x-goldkey-idempotent-replay": "true" },
    }),
  });
  assert.deepEqual(result, { http_status: 200, idempotent_replay: true, payment_required: false, authorization_verified: false });
  assert.equal(JSON.stringify(result).includes("BLOCK"), false);
});

test("client recognizes direct execution through a symlinked install path", async () => {
  const directory = await mkdtemp(join(tmpdir(), "goldkey-entrypoint-"));
  const realDirectory = join(directory, "real");
  const linkedDirectory = join(directory, "linked");
  const entry = join(realDirectory, "goldkey-client.mjs");
  const linkedEntry = join(linkedDirectory, "goldkey-client.mjs");
  try {
    await mkdir(realDirectory);
    await writeFile(entry, "// entry\n", { encoding: "utf8", flag: "wx" });
    await symlink(realDirectory, linkedDirectory, "dir");
    assert.equal(await isDirectExecution(pathToFileURL(entry).href, linkedEntry), true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("published release pins the verified mainnet identity", async () => {
  const published = validateReleaseIdentity(RELEASE_IDENTITY_SOURCE);
  assert.deepEqual(published, {
    origin: "https://goldkey-edge-storefront.noah-ing.workers.dev",
    chainId: 8453,
    contract: "0x220fe98c77ce79baa00d47c5896be05c2a7d3db0",
    usdc: USDC.toLowerCase(),
    termsHash: "0xd1fb20b0e28b63e18b660a2710f1b69b356bc87829a01cf5d75e572ae7de3750",
  });
  assert.equal((await run(["self-test"])).contract, published.contract);
  const checked = validateReleaseIdentity(RELEASE);
  assert.equal(checked.chainId, 8453);
  assert.equal(checked.usdc, USDC.toLowerCase());
  assert.equal((await run(["self-test"], { releaseIdentitySource: RELEASE })).contract, CONTRACT.toLowerCase());
  assert.throws(() => validateReleaseIdentity({ ...RELEASE, chainId: 84532 }), /Base mainnet 8453/);
  assert.throws(() => validateReleaseIdentity({ ...RELEASE, usdc: CONTRACT }), /canonical Base mainnet USDC/);
});

test("development origins require explicit opt-in and can never receive authentication secrets", async () => {
  assert.throws(
    () => resolveRuntimeConfig({ env: { GOLDKEY_DEV_API_URL: "https://staging.example" }, releaseIdentitySource: RELEASE }),
    /unless GOLDKEY_ALLOW_DEV_ORIGIN=1/,
  );
  const runtime = resolveRuntimeConfig({
    env: { GOLDKEY_ALLOW_DEV_ORIGIN: "1", GOLDKEY_DEV_API_URL: "https://staging.example" },
    releaseIdentitySource: RELEASE,
  });
  assert.equal(runtime.canonical, false);

  let fetched = false;
  await assert.rejects(
    run(["quota"], {
      env: {
        GOLDKEY_ALLOW_DEV_ORIGIN: "1",
        GOLDKEY_DEV_API_URL: "https://staging.example",
        GOLDKEY_ACCESS_TOKEN: "gks_secret",
      },
      releaseIdentitySource: RELEASE,
      fetchImpl: async () => {
        fetched = true;
        return jsonResponse({});
      },
    }),
    /Refusing to send GOLDKEY_ACCESS_TOKEN/,
  );
  assert.equal(fetched, false);

  for (const argv of [
    ["challenge", "--token-id", "1", "--wallet", "0x1111111111111111111111111111111111111111"],
    ["verify", "--challenge-id", "challenge"],
  ]) {
    let authenticationFetched = false;
    let signatureRead = false;
    await assert.rejects(
      run(argv, {
        env: {
          GOLDKEY_ALLOW_DEV_ORIGIN: "1",
          GOLDKEY_DEV_API_URL: "https://staging.example",
        },
        releaseIdentitySource: RELEASE,
        readStdinImpl: async () => {
          signatureRead = true;
          return "0x1234";
        },
        fetchImpl: async () => {
          authenticationFetched = true;
          return jsonResponse({});
        },
      }),
      /Refusing wallet authentication against a noncanonical development origin/,
    );
    assert.equal(authenticationFetched, false);
    assert.equal(signatureRead, false);
  }
});

test("legacy origin override is ignored and live offer identity is pinned", async () => {
  let requestedUrl;
  const result = await run(["offer"], {
    env: { GOLDKEY_API_URL: "https://goldkey-edge-sepolia.example" },
    releaseIdentitySource: RELEASE,
    fetchImpl: async (url) => {
      requestedUrl = url;
      return jsonResponse(offer());
    },
  });
  assert.equal(requestedUrl, "https://goldkey.example/.well-known/goldkey.json");
  assert.equal(result.contract.address, CONTRACT);
  await assert.rejects(
    run(["offer"], {
      env: {},
      releaseIdentitySource: RELEASE,
      fetchImpl: async () => jsonResponse(offer({ contract: { ...offer().contract, address: "0x2222222222222222222222222222222222222222" } })),
    }),
    /identity mismatch: offer contract address/,
  );
});

test("commerce validation rejects identity and transaction-target substitution", () => {
  const identity = validateReleaseIdentity(RELEASE);
  assert.equal(validateIdentityPayload("commerce", commerce(), identity).chain_id, 8453);
  assert.throws(() => validateIdentityPayload("commerce", commerce({ terms_hash: `0x${"cd".repeat(32)}` }), identity), /commerce terms hash/);
  assert.throws(
    () => validateIdentityPayload("commerce", commerce({
      unsigned_transactions: [{ to: "0x3333333333333333333333333333333333333333", value: "0" }],
    }), identity),
    /unsigned transaction target/,
  );
});

test("verify rejects argv signatures and accepts secret-store or stdin input", async () => {
  let fetched = false;
  await assert.rejects(
    run(["verify", "--challenge-id", "challenge", "--signature", "0x1234"], {
      env: {},
      releaseIdentitySource: RELEASE,
      fetchImpl: async () => {
        fetched = true;
        return jsonResponse({ access_token: "gks_secret" });
      },
    }),
    /--signature is disabled/,
  );
  assert.equal(fetched, false);

  let requestBody;
  await run(["verify", "--challenge-id", "challenge"], {
    env: {},
    releaseIdentitySource: RELEASE,
    readStdinImpl: async () => "0x1234\n",
    fetchImpl: async (_url, init) => {
      requestBody = JSON.parse(init.body);
      return jsonResponse({ access_token: "gks_secret" });
    },
  });
  assert.equal(requestBody.signature, "0x1234");
});

test("CLI writes verify and delegated-key credentials mode 0600 and redacts results", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "goldkey-distribution-"));
  t.after(() => rm(directory, { recursive: true, force: true }));

  const verifyPath = join(directory, "session.json");
  const verifyResult = await runCli(["verify", "--challenge-id", "challenge", "--secret-output", verifyPath], {
    env: { GOLDKEY_WALLET_SIGNATURE: "0x1234" },
    releaseIdentitySource: RELEASE,
    fetchImpl: async () => jsonResponse({ access_token: "gks_do_not_print", expires_at: "later" }),
  });
  assert.equal(verifyResult.access_token, "[REDACTED]");
  assert.doesNotMatch(JSON.stringify(verifyResult), /gks_do_not_print/);
  assert.deepEqual(JSON.parse(await readFile(verifyPath, "utf8")), { access_token: "gks_do_not_print" });
  assert.equal((await stat(verifyPath)).mode & 0o777, 0o600);

  const keyPath = join(directory, "child.json");
  const keyResult = await runCli([
    "key-issue",
    "--secret-output",
    keyPath,
    "--body",
    '{"label":"child","max_calls":1,"tools":["security.url_check"]}',
  ], {
    env: { GOLDKEY_ACCESS_TOKEN: "gks_owner" },
    releaseIdentitySource: RELEASE,
    fetchImpl: async (_url, init) => {
      assert.equal(init.headers.authorization, "Bearer gks_owner");
      return jsonResponse({ id: "key-id", access_key: "gk_do_not_print" });
    },
  });
  assert.equal(keyResult.access_key, "[REDACTED]");
  assert.doesNotMatch(JSON.stringify(keyResult), /gk_do_not_print/);
  assert.deepEqual(JSON.parse(await readFile(keyPath, "utf8")), { access_key: "gk_do_not_print" });
});
