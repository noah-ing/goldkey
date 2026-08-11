import assert from "node:assert/strict";
import { Writable } from "node:stream";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { CallToolResultSchema, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { GoldKeyEnforcer } from "../src/enforcer.mjs";
import { createInstallationIdentity } from "../src/identity.mjs";
import { FileOutcomeStore } from "../src/state-store.mjs";
import {
  normalizeMcpStdioConfig,
  normalizeMcpStdioInspectionConfig,
} from "../src/adapters/mcp-stdio-config.mjs";
import {
  inspectMcpStdioUpstream,
  prepareMcpStdioProxy,
} from "../src/adapters/mcp-stdio-launcher.mjs";

const POLICY_HASH = "a".repeat(64);
const RECEIPT_HASH = "b".repeat(64);

function discardStream() {
  return new Writable({ write(_chunk, _encoding, callback) { callback(); } });
}

function rawConfig({ tools = [], logFile, extraEnv = {} } = {}) {
  const env = {
    ALLOWED_MARKER: { value: "operator-value" },
    ...(logFile ? { FIXTURE_LOG_FILE: { value: logFile } } : {}),
    ...extraEnv,
  };
  return {
    schema: "goldkey.mcp-stdio-launcher.v1",
    connector: { id: "guarded-fixture", server_id: "fixture-upstream", tools },
    upstream: {
      command: process.execPath,
      args: [path.resolve("examples/mcp/fixture-upstream.mjs")],
      cwd: process.cwd(),
      env,
      startup_timeout_ms: 5000,
      max_message_bytes: 1024 * 1024,
    },
  };
}

async function inspectedTools(raw) {
  const report = await inspectMcpStdioUpstream({
    config: normalizeMcpStdioInspectionConfig(raw),
    stderr: discardStream(),
  });
  return new Map(report.map((tool) => [tool.name, tool.input_schema_sha256]));
}

async function actualEnforcer(t, proxy, config, { outcomeDirectory } = {}) {
  const directory = outcomeDirectory ?? await mkdtemp(path.join(tmpdir(), "goldkey-mcp-outcomes-"));
  if (!outcomeDirectory) t.after(() => rm(directory, { recursive: true, force: true }));
  const installationIdentity = createInstallationIdentity();
  const authorizations = [];
  let receiptCounter = 0;
  const byName = new Map(config.connector.tools.map((tool) => [tool.name, tool]));
  const authorizer = Object.freeze({
    assertReceiptFresh() {},
    async authorize(input) {
      authorizations.push(input);
      receiptCounter += 1;
      const receiptId = `mcp-receipt-${receiptCounter}`;
      const tool = byName.get(input.call.tool);
      return Object.freeze({
        receipt: Object.freeze({
          receipt_id: receiptId,
          decision: "ALLOW",
          connector_id: config.connector.id,
          kind: "mcp_tool",
          policy_sha256: POLICY_HASH,
          expires_at: new Date(Date.now() + 60_000).toISOString(),
        }),
        receipt_sha256: RECEIPT_HASH,
        evidence: Object.freeze({
          effect: tool.effect,
          destination: `mcp://${config.connector.server_id}/${tool.name}`,
        }),
        paymentProof: null,
      });
    },
  });
  const commits = [];
  const enforcer = new GoldKeyEnforcer({
    installationIdentity,
    outcomeStore: new FileOutcomeStore({ directory }),
    authorizer,
    connectors: [proxy.connector],
    commitAuthorization: async (commit) => {
      commits.push(commit);
      return { ok: true, replay: false };
    },
  });
  return { enforcer, authorizations, commits };
}

async function readLog(filename) {
  try {
    return (await readFile(filename, "utf8")).trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

test("exclusive proxy mirrors only guarded tools and every actual call crosses GoldKeyEnforcer", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-mcp-proxy-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const logFile = path.join(directory, "calls.jsonl");
  const initial = rawConfig({ logFile });
  const hashes = await inspectedTools(initial);
  assert.deepEqual(await readLog(logFile), [], "inspection must never invoke a tool");

  const effects = new Map([
    ["echo", "read"],
    ["inspect_env", "read"],
    ["side_effect", "write"],
    ["callback_probe", "execute"],
  ]);
  const configuredTools = [...effects].map(([name, effect]) => ({
    name,
    effect,
    input_schema_sha256: hashes.get(name),
  }));
  const config = normalizeMcpStdioConfig(rawConfig({ tools: configuredTools, logFile }));
  const proxy = await prepareMcpStdioProxy({ config, stderr: discardStream() });
  t.after(() => proxy.close());
  const runtime = await actualEnforcer(t, proxy, config);

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await proxy.serve({ enforcer: runtime.enforcer, transport: serverTransport });
  const downstream = new Client({ name: "goldkey-test-client", version: "1.0.0" }, { capabilities: {} });
  await downstream.connect(clientTransport);
  t.after(() => downstream.close());

  const listed = await downstream.listTools();
  assert.deepEqual(listed.tools.map(({ name }) => name), [...effects.keys()]);
  assert.equal(listed.tools.some(({ name }) => name === "hidden_unconfigured"), false);

  const echo = await downstream.callTool({
    name: "echo",
    arguments: { text: "guarded" },
    _meta: { "com.goldkey/idempotency-key": "echo-guarded-0001" },
  });
  assert.equal(echo.content[0].text, "guarded");
  assert.equal(runtime.authorizations[0].idempotencyKey, "echo-guarded-0001");
  assert.equal(runtime.commits.length, 1);

  const explicitKey = "operator-retry-key-0001";
  await downstream.callTool({
    name: "side_effect",
    arguments: { value: "once" },
    _meta: { "com.goldkey/idempotency-key": explicitKey },
  });
  assert.equal(runtime.authorizations[1].idempotencyKey, explicitKey);
  assert.equal(runtime.commits.length, 2);

  const environment = await downstream.callTool({
    name: "inspect_env",
    arguments: {},
    _meta: { "com.goldkey/idempotency-key": "inspect-env-0001" },
  });
  const environmentNames = JSON.parse(environment.content[0].text);
  assert.equal(environmentNames.includes("ALLOWED_MARKER"), true);
  assert.equal(environmentNames.includes("PATH"), false);
  assert.equal(environmentNames.includes("HOME"), false);
  assert.equal(environmentNames.includes("AGENT_CONTROLLED_SECRET"), false);

  const callback = await downstream.callTool({
    name: "callback_probe",
    arguments: {},
    _meta: { "com.goldkey/idempotency-key": "callback-probe-0001" },
  });
  assert.match(callback.content[0].text, /callback denied: -32601/);
  assert.equal(runtime.authorizations.length, 4);
  assert.equal(runtime.commits.length, 4);

  const beforeDenied = (await readLog(logFile)).length;
  await assert.rejects(
    () => downstream.callTool({ name: "hidden_unconfigured", arguments: {} }),
    (error) => error.code === ErrorCode.InvalidParams,
  );
  await assert.rejects(
    () => downstream.listResources(),
    (error) => error.code === ErrorCode.MethodNotFound,
  );
  await assert.rejects(
    () => downstream.request({
      method: "tools/call",
      params: { name: "echo", arguments: { text: "task" }, task: { ttl: 1000 } },
    }, CallToolResultSchema),
    (error) => [ErrorCode.MethodNotFound, ErrorCode.InternalError].includes(error.code),
  );
  assert.equal((await readLog(logFile)).length, beforeDenied, "unsupported paths must not reach upstream");
  assert.equal(runtime.authorizations.length, 4, "unsupported paths must not reach the enforcer authorizer");
});

test("a durable explicit idempotency key prevents a repeated side effect after proxy restart", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-mcp-restart-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const outcomes = path.join(directory, "outcomes");
  const logFile = path.join(directory, "calls.jsonl");
  const hashes = await inspectedTools(rawConfig({ logFile }));
  const config = normalizeMcpStdioConfig(rawConfig({
    logFile,
    tools: [{ name: "side_effect", effect: "write", input_schema_sha256: hashes.get("side_effect") }],
  }));
  const key = "durable-restart-side-effect-0001";

  const firstProxy = await prepareMcpStdioProxy({ config, stderr: discardStream() });
  const firstRuntime = await actualEnforcer(t, firstProxy, config, { outcomeDirectory: outcomes });
  const [firstClientTransport, firstServerTransport] = InMemoryTransport.createLinkedPair();
  await firstProxy.serve({ enforcer: firstRuntime.enforcer, transport: firstServerTransport });
  const firstClient = new Client({ name: "restart-first", version: "1.0.0" }, { capabilities: {} });
  await firstClient.connect(firstClientTransport);
  await firstClient.callTool({
    name: "side_effect",
    arguments: { value: "once" },
    _meta: { "com.goldkey/idempotency-key": key },
  });
  await firstClient.close();
  await firstProxy.close();
  assert.equal((await readLog(logFile)).length, 1);

  const secondProxy = await prepareMcpStdioProxy({ config, stderr: discardStream() });
  t.after(() => secondProxy.close());
  const secondRuntime = await actualEnforcer(t, secondProxy, config, { outcomeDirectory: outcomes });
  const [secondClientTransport, secondServerTransport] = InMemoryTransport.createLinkedPair();
  await secondProxy.serve({ enforcer: secondRuntime.enforcer, transport: secondServerTransport });
  const secondClient = new Client({ name: "restart-second", version: "1.0.0" }, { capabilities: {} });
  await secondClient.connect(secondClientTransport);
  t.after(() => secondClient.close());
  await assert.rejects(
    () => secondClient.callTool({
      name: "side_effect",
      arguments: { value: "once" },
      _meta: { "com.goldkey/idempotency-key": key },
    }),
    (error) => error.code === ErrorCode.InvalidParams && error.data?.code === "replay_detected",
  );
  assert.equal(secondRuntime.authorizations.length, 0, "durable outcome state rejects before reauthorization");
  assert.equal((await readLog(logFile)).length, 1, "restart retry must not reach upstream");
});
