import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { PassThrough, Writable } from "node:stream";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  AGENTCASH_ADAPTER_SCHEMA,
  AGENTCASH_MCP_PROTOCOL_VERSION,
  inspectAgentCashInvocation,
  loadAgentCashAdapterConfigFile,
  normalizeAgentCashAdapterConfig,
  prepareAgentCashAdapter,
  runAgentCashMcpRpc,
} from "../src/adapters/agentcash-mcp.mjs";
import { serveAgentCashGuardMcp } from "../src/adapters/agentcash-mcp-server.mjs";
import { runAgentCashCli } from "../bin/goldkey-agentcash.mjs";
import { GoldKeyEnforcer } from "../src/enforcer.mjs";
import { AmbiguousOutcomeError } from "../src/errors.mjs";
import { createInstallationIdentity } from "../src/identity.mjs";
import { FileOutcomeStore } from "../src/state-store.mjs";

const EVM_KEY = "0x" + "11".repeat(32);
const SOLANA_KEY = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const NOW = Date.parse("2026-08-11T16:00:00.000Z");

test("npm-style symlink invokes the AgentCash binary instead of silently importing it", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-agentcash-bin-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const link = path.join(directory, "goldkey-agentcash");
  await symlink(fileURLToPath(new URL("../bin/goldkey-agentcash.mjs", import.meta.url)), link);
  const result = spawnSync(process.execPath, [link, "--help"], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /goldkey-agentcash --inspect/);
});

function rawConfig(overrides = {}) {
  return {
    schema: AGENTCASH_ADAPTER_SCHEMA,
    connector_id: "agentcash-x402",
    server_id: "agentcash-local",
    guard_origin: "https://goldkey-edge-storefront.noah-ing.workers.dev",
    node_command: process.execPath,
    agentcash_command: process.execPath,
    agentcash_version: "0.17.1",
    credential_mode: "environment",
    working_directory: process.cwd(),
    request_timeout_ms: 8_000,
    max_response_bytes: 256 * 1024,
    operations: [{
      name: "people_enrich",
      url: "https://stableenrich.dev/api/pdl/people-enrich",
      method: "POST",
      payment_network: "base",
      max_amount_usd: "0.25",
      headers: { accept: "application/json" },
    }],
    ...overrides,
  };
}

function environment(home = "/operator") {
  return {
    HOME: home,
    PATH: "/usr/local/bin:/usr/bin:/bin",
    X402_PRIVATE_KEY: EVM_KEY,
    X402_SOLANA_PRIVATE_KEY: SOLANA_KEY,
    GOLDKEY_PAYER_PRIVATE_KEY: "must-not-reach-agentcash",
    DATABASE_URL: "must-not-reach-agentcash",
  };
}

function publicResolvers() {
  return {
    resolve4: async () => [{ address: "8.8.8.8", ttl: 30 }],
    resolve6: async () => [],
  };
}

function fetchToolList() {
  return {
    tools: [{
      name: "fetch",
      inputSchema: {
        type: "object",
        properties: {
          url: {}, method: {}, body: {}, headers: {}, timeout: {},
          paymentProtocol: {}, paymentNetwork: {}, maxAmount: {},
        },
      },
    }],
  };
}

function successfulMcpFetch({ network = "base", transactionHash = "0xabc" } = {}) {
  return {
    content: [
      { type: "text", text: JSON.stringify({ company: "Example" }) },
      {
        type: "text",
        text: JSON.stringify({
          protocol: "x402",
          network,
          price: "$0.03",
          payment: { success: true, transactionHash },
          headers: { "content-type": "application/json", "set-cookie": "secret=1", "x-request-id": "req-1" },
        }),
      },
    ],
  };
}

test("normalization pins destination, method, payment cap, and a canonical Guard schema", () => {
  const config = normalizeAgentCashAdapterConfig(rawConfig());
  const operation = config.operations[0];
  assert.equal(operation.url, "https://stableenrich.dev/api/pdl/people-enrich");
  assert.equal(operation.method, "POST");
  assert.equal(operation.max_amount_usd, "0.25");
  assert.match(operation.input_schema_sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(operation.input_schema.required, ["body"]);
  assert.equal(operation.input_schema["x-goldkey-agentcash-binding"].upstream_url, operation.url);
  assert.equal(operation.input_schema["x-goldkey-agentcash-binding"].max_amount_usd, "0.25");
  assert.throws(
    () => normalizeAgentCashAdapterConfig(rawConfig({ agentcash_command: "npx" })),
    (error) => error.code === "invalid_input" && /absolute/.test(error.message),
  );
  assert.throws(
    () => normalizeAgentCashAdapterConfig(rawConfig({
      operations: [{ ...rawConfig().operations[0], url: "https://goldkey-edge-storefront.noah-ing.workers.dev/v1/guard/paygo/authorize/network" }],
    })),
    (error) => error.code === "invalid_input" && /separate payments/.test(error.message),
  );
  assert.throws(
    () => normalizeAgentCashAdapterConfig(rawConfig({ guard_origin: "https://substitute.invalid" })),
    (error) => error.code === "invalid_input" && /live GoldKey Guard origin/.test(error.message),
  );
  assert.throws(
    () => normalizeAgentCashAdapterConfig(rawConfig({
      operations: [{ ...rawConfig().operations[0], headers: { authorization: "Bearer secret" } }],
    })),
    (error) => error.code === "invalid_input" && /sensitive/.test(error.message),
  );
  assert.throws(
    () => normalizeAgentCashAdapterConfig(rawConfig({
      operations: [{ ...rawConfig().operations[0], url: `${rawConfig().operations[0].url}?api_key=secret` }],
    })),
    (error) => error.code === "invalid_input" && /without a query/.test(error.message),
  );
  assert.throws(
    () => normalizeAgentCashAdapterConfig(rawConfig({
      operations: [{ ...rawConfig().operations[0], headers: { "x-client-secret": "secret" } }],
    })),
    (error) => error.code === "invalid_input" && /only the non-secret accept/.test(error.message),
  );
  assert.throws(
    () => normalizeAgentCashAdapterConfig(rawConfig({
      operations: [{ ...rawConfig().operations[0], headers: { accept: " application/json " } }],
    })),
    (error) => error.code === "invalid_input" && /invalid header/.test(error.message),
  );
  assert.throws(
    () => normalizeAgentCashAdapterConfig(rawConfig({
      operations: [{ ...rawConfig().operations[0], headers: { accept: "Bearer disguised-secret" } }],
    })),
    (error) => error.code === "invalid_input" && /exactly application\/json/.test(error.message),
  );
});

test("combined JSON loader selects agentcash beside runtime and resolves local paths", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-agentcash-config-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filename = path.join(directory, "goldkey.json");
  const section = rawConfig({ agentcash_command: "node_modules/.bin/agentcash", working_directory: "private/agentcash" });
  await writeFile(filename, JSON.stringify({ runtime: { parsed: "by shared runtime" }, agentcash: section }), { mode: 0o600 });
  const loaded = await loadAgentCashAdapterConfigFile(filename);
  assert.equal(loaded.document.runtime.parsed, "by shared runtime");
  assert.equal(loaded.agentCashConfig.agentcash_command, path.join(directory, "node_modules/.bin/agentcash"));
  assert.equal(loaded.agentCashConfig.working_directory, path.join(directory, "private/agentcash"));
});

test("combined JSON loader rejects a group-writable operator config", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX permission test");
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-agentcash-loose-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filename = path.join(directory, "goldkey.json");
  await writeFile(filename, JSON.stringify({ agentcash: rawConfig() }), { mode: 0o666 });
  await chmod(filename, 0o666);
  await assert.rejects(
    () => loadAgentCashAdapterConfigFile(filename),
    (error) => error.code === "local_state_error" && /writable/.test(error.message),
  );
});

test("prepare probes without purchase and only passes AgentCash credential environment", async () => {
  const calls = [];
  const rpcImpl = async (request) => {
    calls.push(request);
    assert.equal(request.method, "tools/list");
    return fetchToolList();
  };
  const adapter = await prepareAgentCashAdapter({
    config: rawConfig(),
    environment: environment(),
    rpcImpl,
    ...publicResolvers(),
    clock: () => NOW,
  });
  assert.equal(calls.length, 1);
  assert.deepEqual(Object.keys(calls[0].environment).sort(), [
    "CI", "FORCE_COLOR", "HOME", "NO_COLOR", "X402_PRIVATE_KEY", "X402_SOLANA_PRIVATE_KEY",
  ]);
  assert.equal(calls[0].environment.GOLDKEY_PAYER_PRIVATE_KEY, undefined);
  assert.equal(calls[0].environment.DATABASE_URL, undefined);
  assert.equal(adapter.preflight.operations_checked, 1);
  assert.equal(adapter.connector.tools[0].effect, "payment");
});

test("prepare rejects a symlink AgentCash command before MCP startup", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-agentcash-command-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const command = path.join(directory, "agentcash");
  await symlink(process.execPath, command);
  let rpcCalls = 0;
  await assert.rejects(
    () => prepareAgentCashAdapter({
      config: rawConfig({ agentcash_command: command, working_directory: directory }),
      environment: environment(),
      rpcImpl: async () => { rpcCalls += 1; return fetchToolList(); },
      ...publicResolvers(),
      clock: () => NOW,
    }),
    (error) => error.code === "agentcash_executable_not_ready" && /non-symlink/.test(error.message),
  );
  assert.equal(rpcCalls, 0);
});

test("wallet-file mode refuses startup before both 0600 AgentCash wallets exist", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-agentcash-wallet-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const config = rawConfig({ credential_mode: "wallet_files", working_directory: directory });
  const env = { HOME: directory, PATH: "/usr/bin:/bin" };
  await assert.rejects(
    () => prepareAgentCashAdapter({ config, environment: env, rpcImpl: async () => fetchToolList(), ...publicResolvers(), clock: () => NOW }),
    (error) => error.code === "agentcash_wallet_not_ready",
  );
  const walletDirectory = path.join(directory, ".agentcash");
  await mkdir(walletDirectory, { mode: 0o700 });
  await writeFile(path.join(walletDirectory, "wallet.json"), "{}", { mode: 0o600 });
  await writeFile(path.join(walletDirectory, "solana-wallet.json"), "{}", { mode: 0o600 });
  const adapter = await prepareAgentCashAdapter({
    config,
    environment: env,
    rpcImpl: async () => fetchToolList(),
    ...publicResolvers(),
    clock: () => NOW,
  });
  assert.deepEqual(adapter.preflight.wallet_files_checked, ["wallet.json", "solana-wallet.json"]);
});

test("injected Guard primitive remains the only path to the AgentCash connector", async () => {
  const rpcCalls = [];
  const adapter = await prepareAgentCashAdapter({
    config: rawConfig(),
    environment: environment(),
    rpcImpl: async (request) => {
      rpcCalls.push(request);
      return request.method === "tools/list" ? fetchToolList() : successfulMcpFetch();
    },
    ...publicResolvers(),
    clock: () => NOW,
  });
  const guardCalls = [];
  const invoke = adapter.createInvoker({
    guardMcpTool: async (request) => {
      guardCalls.push(request);
      return { authorized: true };
    },
  });
  const result = await invoke({
    operation: "people_enrich",
    arguments: { body: { profile: "https://www.linkedin.com/in/example" } },
    idempotencyKey: "agentcash-call-0001",
  });
  assert.deepEqual(result, { authorized: true });
  assert.equal(guardCalls.length, 1);
  assert.equal(guardCalls[0].connectorId, "agentcash-x402");
  assert.equal(guardCalls[0].tool, "people_enrich");
  assert.equal(rpcCalls.filter(({ method }) => method === "tools/call").length, 0, "mock Guard did not forward, so AgentCash must not run");
  await assert.rejects(
    () => invoke({
      operation: "people_enrich",
      arguments: { body: {}, url: "https://attacker.invalid" },
      idempotencyKey: "agentcash-call-0002",
    }),
    (error) => error.code === "invalid_input",
  );
});

test("connector emits exactly one pinned x402 fetch and sanitizes response metadata", async () => {
  const calls = [];
  const adapter = await prepareAgentCashAdapter({
    config: rawConfig(),
    environment: environment(),
    rpcImpl: async (request) => {
      calls.push(request);
      return request.method === "tools/list" ? fetchToolList() : successfulMcpFetch();
    },
    ...publicResolvers(),
    clock: () => NOW,
  });
  const result = await adapter.connector.invokeTool({
    serverId: "agentcash-local",
    tool: "people_enrich",
    arguments: { body: { profile: "https://www.linkedin.com/in/example" } },
    signal: new AbortController().signal,
    deadlineAt: NOW + 10_000,
  });
  const forwarded = calls.filter(({ method }) => method === "tools/call");
  assert.equal(forwarded.length, 1);
  assert.deepEqual(forwarded[0].params, {
    name: "fetch",
    arguments: {
      url: "https://stableenrich.dev/api/pdl/people-enrich",
      method: "POST",
      body: { profile: "https://www.linkedin.com/in/example" },
      headers: { accept: "application/json", "content-type": "application/json" },
      timeout: 8_000,
      paymentProtocol: "x402",
      paymentNetwork: "base",
      maxAmount: 0.25,
      stream: false,
    },
  });
  assert.equal(result.payment.max_amount_usd, "0.25");
  assert.equal(result.payment.settlement.transaction_hash, "0xabc");
  assert.deepEqual(result.response_headers, { "content-type": "application/json", "x-request-id": "req-1" });
});

test("connector never retries an ambiguous AgentCash failure", async () => {
  let toolCalls = 0;
  const adapter = await prepareAgentCashAdapter({
    config: rawConfig(),
    environment: environment(),
    rpcImpl: async (request) => {
      if (request.method === "tools/list") return fetchToolList();
      toolCalls += 1;
      throw Object.assign(new Error("ambiguous"), { code: "agentcash_process_closed" });
    },
    ...publicResolvers(),
    clock: () => NOW,
  });
  await assert.rejects(
    () => adapter.connector.invokeTool({
      serverId: "agentcash-local",
      tool: "people_enrich",
      arguments: { body: { profile: "example" } },
      signal: new AbortController().signal,
      deadlineAt: NOW + 10_000,
    }),
    /ambiguous/,
  );
  assert.equal(toolCalls, 1);
});

test("real GoldKeyEnforcer persists AgentCash failure UNKNOWN and same key never spawns again", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-agentcash-outcomes-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  let toolCalls = 0;
  const adapter = await prepareAgentCashAdapter({
    config: rawConfig(),
    environment: environment(),
    rpcImpl: async (request) => {
      if (request.method === "tools/list") return fetchToolList();
      toolCalls += 1;
      throw Object.assign(new Error("post-send process exit"), { code: "agentcash_process_closed" });
    },
    ...publicResolvers(),
    clock: () => NOW,
  });
  const authorizer = Object.freeze({
    assertReceiptFresh() {},
    async authorize({ call }) {
      return Object.freeze({
        receipt: Object.freeze({
          receipt_id: "agentcash-receipt-0001",
          decision: "ALLOW",
          connector_id: call.connector_id,
          kind: "mcp_tool",
          policy_sha256: "a".repeat(64),
          expires_at: new Date(NOW + 60_000).toISOString(),
        }),
        receipt_sha256: "b".repeat(64),
        evidence: Object.freeze({
          effect: "payment",
          destination: "mcp://agentcash-local/people_enrich",
        }),
        paymentProof: null,
      });
    },
  });
  const outcomeStore = new FileOutcomeStore({ directory, clock: () => NOW });
  const enforcer = new GoldKeyEnforcer({
    installationIdentity: createInstallationIdentity(),
    outcomeStore,
    authorizer,
    commitAuthorization: async () => ({ ok: true, replay: false }),
    connectors: [adapter.connector],
    clock: () => NOW,
  });
  const guardedCall = {
    connectorId: "agentcash-x402",
    tool: "people_enrich",
    arguments: { body: { profile: "example" } },
    idempotencyKey: "agentcash-durable-0001",
  };
  await assert.rejects(() => enforcer.guardMcpTool(guardedCall), AmbiguousOutcomeError);
  assert.equal((await outcomeStore.get(guardedCall.idempotencyKey)).state, "UNKNOWN");
  assert.equal(toolCalls, 1);
  await assert.rejects(() => enforcer.guardMcpTool(guardedCall), AmbiguousOutcomeError);
  assert.equal(toolCalls, 1, "durable UNKNOWN must stop a second AgentCash process");
});

test("drop-in MCP server lists only configured operations and routes every call through Guard", async (t) => {
  const adapter = await prepareAgentCashAdapter({
    config: rawConfig(),
    environment: environment(),
    rpcImpl: async (request) => request.method === "tools/list" ? fetchToolList() : successfulMcpFetch(),
    ...publicResolvers(),
    clock: () => NOW,
  });
  const guarded = [];
  const enforcer = {
    guardMcpTool: async (request) => {
      guarded.push(request);
      return {
        content: [{ type: "text", text: JSON.stringify({ company: "Example" }) }],
        payment: { protocol: "x402", network: "base", price: "$0.03", settlement: null, max_amount_usd: "0.25" },
        response_headers: { "content-type": "application/json" },
      };
    },
  };
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = await serveAgentCashGuardMcp({
    adapter,
    enforcer,
    transport: serverTransport,
    stderr: new Writable({ write(_chunk, _encoding, callback) { callback(); } }),
  });
  t.after(() => server.close());
  const client = new Client({ name: "agentcash-test-client", version: "1.0.0" }, { capabilities: {} });
  await client.connect(clientTransport);
  t.after(() => client.close());
  const listed = await client.listTools();
  assert.deepEqual(listed.tools.map(({ name }) => name), ["people_enrich"]);
  assert.equal(listed.tools[0].inputSchema["x-goldkey-agentcash-binding"].max_amount_usd, "0.25");
  await assert.rejects(() => client.callTool({ name: "people_enrich", arguments: { body: { profile: "example" } } }));
  assert.equal(guarded.length, 0, "missing stable idempotency must fail before Guard");
  const guardedRequest = {
    name: "people_enrich",
    arguments: { body: { profile: "example" } },
    _meta: { "com.goldkey/idempotency-key": "agentcash-purchase-0001" },
  };
  const result = await client.callTool(guardedRequest);
  assert.equal(JSON.parse(result.content[0].text).company, "Example");
  assert.equal(guarded.length, 1);
  assert.equal(guarded[0].connectorId, "agentcash-x402");
  assert.equal(guarded[0].idempotencyKey, "agentcash-purchase-0001");
  await client.callTool(guardedRequest);
  assert.equal(guarded[1].idempotencyKey, guarded[0].idempotencyKey, "same exact purchase stays replay-safe across JSON-RPC request IDs");
  await assert.rejects(() => client.callTool({ name: "fetch", arguments: { url: "https://attacker.invalid" } }));
  assert.equal(guarded.length, 2);
});

test("normal CLI serve mode needs one injected runtime factory and no customer connector code", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-agentcash-serve-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const configFilename = path.join(directory, "goldkey.json");
  await writeFile(configFilename, JSON.stringify({ runtime: { marker: "shared" }, agentcash: rawConfig() }), { mode: 0o600 });
  const inputSchema = normalizeAgentCashAdapterConfig(rawConfig()).operations[0].input_schema;
  const guarded = [];
  const fakeAdapter = Object.freeze({
    config: Object.freeze({ connector_id: "agentcash-x402", max_response_bytes: 256 * 1024 }),
    connector: Object.freeze({ id: "agentcash-x402" }),
    tool_manifest: Object.freeze([Object.freeze({
      name: "people_enrich",
      upstream_url: "https://stableenrich.dev/api/pdl/people-enrich",
      max_amount_usd: "0.25",
      payment_network: "base",
      input_schema: inputSchema,
    })]),
    createInvoker: (enforcer) => async (request) => {
      guarded.push(request);
      return enforcer.guardMcpTool(request);
    },
  });
  let runtimeFactoryCalls = 0;
  const runtimeFactory = async (input) => {
    runtimeFactoryCalls += 1;
    assert.equal(input.configFilename, configFilename);
    assert.equal(input.document.runtime.marker, "shared");
    assert.equal(input.connector.id, "agentcash-x402");
    return {
      enforcer: {
        guardMcpTool: async () => ({
          content: [{ type: "text", text: "guarded" }],
          payment: null,
          response_headers: {},
        }),
      },
    };
  };
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const servePromise = runAgentCashCli({
    argv: [configFilename],
    env: environment(),
    runtimeFactory,
    adapterFactory: async () => fakeAdapter,
    downstreamTransport: serverTransport,
    stderr: new Writable({ write(_chunk, _encoding, callback) { callback(); } }),
  });
  const client = new Client({ name: "agentcash-cli-test", version: "1.0.0" }, { capabilities: {} });
  await client.connect(clientTransport);
  const listed = await client.listTools();
  assert.deepEqual(listed.tools.map(({ name }) => name), ["people_enrich"]);
  const called = await client.callTool({
    name: "people_enrich",
    arguments: { body: { profile: "example" } },
    _meta: { "com.goldkey/idempotency-key": "agentcash-cli-purchase-0001" },
  });
  assert.equal(called.content[0].text, "guarded");
  assert.equal(guarded.length, 1);
  await client.close();
  assert.deepEqual(await servePromise, { mode: "serve" });
  assert.equal(runtimeFactoryCalls, 1);
});

test("inspection is deterministic and performs no DNS, process, Guard, signature, or payment action", () => {
  const report = inspectAgentCashInvocation({
    config: rawConfig(),
    operation: "people_enrich",
    arguments: { body: { profile: "example" } },
    idempotencyKey: "inspect-agentcash-0001",
  });
  assert.equal(report.discovery_only, true);
  assert.equal(report.agentcash_process_started, false);
  assert.equal(report.authorization_or_payment_attempted, false);
  assert.equal(report.signature_created, false);
  assert.equal(report.agentcash_stdio.command, process.execPath);
  assert.deepEqual(report.agentcash_stdio.argv, [process.execPath, "server", "--quiet"]);
  assert.equal(JSON.parse(report.canonical_guarded_call).arguments.body.profile, "example");
  assert.match(report.guarded_call_sha256, /^[0-9a-f]{64}$/);
  const wireCall = JSON.parse(report.agentcash_stdio.stdin_json_lines[2]);
  assert.equal(wireCall.method, "tools/call");
  assert.equal(wireCall.params.arguments.maxAmount, 0.25);
});

class FakeAgentCashChild extends EventEmitter {
  constructor(onMessage) {
    super();
    this.stdout = new PassThrough();
    this.stderr = new PassThrough();
    this.messages = [];
    let buffered = "";
    this.stdin = new Writable({
      write: (chunk, _encoding, callback) => {
        buffered += Buffer.from(chunk).toString("utf8");
        while (buffered.includes("\n")) {
          const index = buffered.indexOf("\n");
          const line = buffered.slice(0, index);
          buffered = buffered.slice(index + 1);
          if (line) {
            const message = JSON.parse(line);
            this.messages.push(message);
            onMessage(message, this);
          }
        }
        callback();
      },
    });
    queueMicrotask(() => this.emit("spawn"));
  }

  reply(message) {
    queueMicrotask(() => this.stdout.write(JSON.stringify(message) + "\n"));
  }

  kill(signal) {
    this.killedWith = signal;
    return true;
  }
}

test("stdio RPC keeps target and body off argv and makes one tools/call request", async () => {
  const spawns = [];
  let child;
  const spawnImpl = (command, args, options) => {
    child = new FakeAgentCashChild((message, process) => {
      if (message.method === "initialize") {
        process.reply({
          jsonrpc: "2.0",
          id: message.id,
          result: {
            protocolVersion: AGENTCASH_MCP_PROTOCOL_VERSION,
            serverInfo: { name: "agentcash", version: "0.17.1" },
            capabilities: {},
          },
        });
      }
      if (message.method === "tools/call") process.reply({ jsonrpc: "2.0", id: message.id, result: successfulMcpFetch() });
    });
    spawns.push({ command, args, options });
    return child;
  };
  const result = await runAgentCashMcpRpc({
    nodeCommand: "/opt/goldkey/bin/node",
    agentCashCommand: "/opt/goldkey/node_modules/agentcash/dist/esm/index.js",
    expectedVersion: "0.17.1",
    workingDirectory: "/opt/goldkey/private/agentcash",
    environment: { HOME: "/operator", PATH: "/usr/bin", CI: "1" },
    method: "tools/call",
    params: {
      name: "fetch",
      arguments: { url: "https://stableenrich.dev/api", body: { private: "body-value" }, maxAmount: 0.25 },
    },
    deadlineAt: NOW + 5_000,
    clock: () => NOW,
    spawnImpl,
  });
  assert.deepEqual(result, successfulMcpFetch());
  assert.equal(spawns.length, 1);
  assert.deepEqual(spawns[0].args, ["/opt/goldkey/node_modules/agentcash/dist/esm/index.js", "server", "--quiet"]);
  assert.equal(JSON.stringify([spawns[0].command, spawns[0].args, spawns[0].options.env]).includes("body-value"), false);
  assert.equal(child.messages.filter(({ method }) => method === "tools/call").length, 1);
  assert.equal(child.messages.find(({ method }) => method === "tools/call").params.arguments.body.private, "body-value");
});

test("pinned official AgentCash 0.17.1 completes a zero-payment MCP tools/list handshake", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-agentcash-official-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const require = createRequire(import.meta.url);
  const packageDirectory = path.dirname(require.resolve("agentcash/package.json"));
  const entrypoint = path.join(packageDirectory, "dist", "esm", "index.js");
  const result = await runAgentCashMcpRpc({
    nodeCommand: process.execPath,
    agentCashCommand: entrypoint,
    expectedVersion: "0.17.1",
    workingDirectory: directory,
    environment: { HOME: directory, CI: "1", NO_COLOR: "1", FORCE_COLOR: "0" },
    method: "tools/list",
    params: {},
    deadlineAt: Date.now() + 10_000,
    maxResponseBytes: 1024 * 1024,
  });
  const fetchTool = result.tools.find(({ name }) => name === "fetch");
  assert.ok(fetchTool, "official MCP server must expose fetch");
  assert.deepEqual(
    ["url", "method", "body", "headers", "timeout", "paymentProtocol", "paymentNetwork", "maxAmount"]
      .filter((field) => !Object.hasOwn(fetchTool.inputSchema.properties, field)),
    [],
  );
});
