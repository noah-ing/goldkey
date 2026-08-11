import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { privateKeyToAccount } from "viem/accounts";
import {
  GUARD_RUNTIME_CONFIG_SCHEMA,
  createConfiguredGuardRuntime,
  loadGuardRuntimeConfig,
  normalizeGuardRuntimeConfig,
} from "../src/adapters/runtime.mjs";
import {
  createBaseWalletRuntime,
  createMcpAdapterRuntime,
} from "../src/adapters/runtime-factory.mjs";

const POLICY = "a".repeat(64);
const TOOL_SCHEMA = "b".repeat(64);
const PAYER_KEY = "0x" + "11".repeat(32);

function rawConfig() {
  return {
    schema: GUARD_RUNTIME_CONFIG_SCHEMA,
    policy_sha256: POLICY,
    installation_key_file: "private/installation.json",
    receipt_keyset_file: "receipt-keys.json",
    state_directory: "private/outcomes",
    payment: {
      payer_private_key_env: "GOLDKEY_TEST_PAYER_KEY",
      budget_database_file: "private/payment-budget.sqlite",
      period_seconds: 86400,
      max_period_atomic: "5000000",
      max_outstanding_atomic: "200000",
      max_outstanding_count: 2,
      timeout_ms: 15000,
    },
  };
}

function keyset() {
  const { publicKey } = generateKeyPairSync("ed25519");
  return {
    schema: "goldkey.guard-receipt-keyset.v1",
    keys: [{ ...publicKey.export({ format: "jwk" }), kid: "test-receipt-key" }],
  };
}

test("runtime config resolves every operator-owned path and rejects loose shapes", () => {
  const normalized = normalizeGuardRuntimeConfig(rawConfig(), { configDirectory: "/operator/goldkey" });
  assert.equal(normalized.installation_key_file, "/operator/goldkey/private/installation.json");
  assert.equal(normalized.receipt_keyset_file, "/operator/goldkey/receipt-keys.json");
  assert.equal(normalized.payment.budget_database_file, "/operator/goldkey/private/payment-budget.sqlite");
  assert.throws(
    () => normalizeGuardRuntimeConfig({ ...rawConfig(), service_origin: "https://attacker.invalid" }),
    (error) => error.code === "invalid_input" && /unsupported/.test(error.message),
  );
  assert.throws(
    () => normalizeGuardRuntimeConfig({ ...rawConfig(), payment: { ...rawConfig().payment, payer_private_key_env: "bad-name" } }),
    (error) => error.code === "invalid_input",
  );
});

test("config loader rejects a group-writable runtime config", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX permission test");
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-runtime-config-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filename = path.join(directory, "goldkey.json");
  await writeFile(filename, JSON.stringify(rawConfig()), { mode: 0o666 });
  await chmod(filename, 0o666);
  await assert.rejects(
    () => loadGuardRuntimeConfig(filename),
    (error) => error.code === "local_state_error" && /writable/.test(error.message),
  );
});

test("config loader accepts the runtime section of one combined launcher document", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-combined-config-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filename = path.join(directory, "goldkey.json");
  await writeFile(filename, JSON.stringify({ runtime: rawConfig(), mcp_stdio: { intentionally: "parsed elsewhere" } }), { mode: 0o600 });
  const loaded = await loadGuardRuntimeConfig(filename);
  assert.equal(loaded.policy_sha256, POLICY);
  assert.equal(loaded.installation_key_file, path.join(directory, "private/installation.json"));
});

test("config loader refuses a symlink even when its target is private", async (t) => {
  if (process.platform === "win32") return t.skip("symlink permission behavior differs on Windows");
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-symlink-config-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const target = path.join(directory, "target.json");
  const filename = path.join(directory, "goldkey.json");
  await writeFile(target, JSON.stringify(rawConfig()), { mode: 0o600 });
  await symlink(target, filename);
  await assert.rejects(
    () => loadGuardRuntimeConfig(filename),
    (error) => error.code === "local_state_error" && /non-symlink/.test(error.message),
  );
});

test("configured runtime keeps payer and installation secrets out of its public result", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-runtime-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const privateDirectory = path.join(directory, "private");
  await mkdir(privateDirectory, { mode: 0o700 });
  const receiptKeysetFile = path.join(directory, "receipt-keys.json");
  await writeFile(receiptKeysetFile, JSON.stringify(keyset()), { mode: 0o600 });
  const config = normalizeGuardRuntimeConfig(rawConfig(), { configDirectory: directory });
  const runtime = await createConfiguredGuardRuntime({
    config,
    callKind: "network",
    connectors: [{
      id: "mcp-production",
      kind: "mcp_tool",
      server_id: "upstream-production",
      tools: [{ name: "send", effect: "write", input_schema_sha256: TOOL_SCHEMA }],
      invokeTool: async () => ({ ok: true }),
    }],
    env: { GOLDKEY_TEST_PAYER_KEY: PAYER_KEY },
    fetchImpl: async () => { throw new Error("network must not run during construction"); },
    serviceOrigin: "https://guard.example",
  });
  assert.equal(runtime.installation.installation_id.startsWith("gki_"), true);
  assert.deepEqual(Object.keys(runtime.installation).sort(), ["installation_id", "public_key_jwk"]);
  assert.equal(runtime.payment.payer, privateKeyToAccount(PAYER_KEY).address);
  assert.equal(runtime.payment.max_per_authorization_atomic, "50000");
  assert.equal(JSON.stringify(runtime).includes(PAYER_KEY.slice(2)), false);
  const installationDocument = JSON.parse(await readFile(config.installation_key_file, "utf8"));
  assert.equal(installationDocument.schema, "goldkey-installation-key.v1");
  assert.equal(typeof installationDocument.private_jwk.d, "string");
});

test("configured runtime fails closed without a payer key or with a substituted origin", async () => {
  await assert.rejects(
    () => createConfiguredGuardRuntime({
      config: normalizeGuardRuntimeConfig(rawConfig(), { configDirectory: "/tmp" }),
      callKind: "network",
      connectors: [],
      env: {},
      fetchImpl: fetch,
    }),
    (error) => error.code === "local_state_error" && /GOLDKEY_TEST_PAYER_KEY/.test(error.message),
  );
  await assert.rejects(
    () => createConfiguredGuardRuntime({
      config: normalizeGuardRuntimeConfig(rawConfig(), { configDirectory: "/tmp" }),
      callKind: "network",
      connectors: [],
      env: { GOLDKEY_TEST_PAYER_KEY: PAYER_KEY },
      fetchImpl: fetch,
      serviceOrigin: "https://guard.example/path",
    }),
    (error) => error.code === "invalid_input" && /HTTPS origin/.test(error.message),
  );
});

test("adapter factories use the combined runtime section and separate payment/execution wallets", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-runtime-factory-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await mkdir(path.join(directory, "private"), { mode: 0o700 });
  await writeFile(path.join(directory, "receipt-keys.json"), JSON.stringify(keyset()), { mode: 0o600 });
  const filename = path.join(directory, "combined.json");
  const document = { runtime: rawConfig(), mcp_stdio: {} };
  await writeFile(filename, JSON.stringify(document), { mode: 0o600 });
  const connector = {
    id: "mcp-production",
    kind: "mcp_tool",
    server_id: "upstream-production",
    tools: [{ name: "send", effect: "write", input_schema_sha256: TOOL_SCHEMA }],
    invokeTool: async () => ({ ok: true }),
  };
  const mcp = await createMcpAdapterRuntime({
    configFilename: filename,
    document,
    connector,
    env: { GOLDKEY_TEST_PAYER_KEY: PAYER_KEY },
    fetchImpl: async () => { throw new Error("network must not run during construction"); },
  });
  assert.equal(typeof mcp.enforcer.guardMcpTool, "function");

  await assert.rejects(
    () => createMcpAdapterRuntime({
      configFilename: filename,
      document,
      connector,
      agentCashConfig: { guard_origin: "https://substituted.example" },
      env: { GOLDKEY_TEST_PAYER_KEY: PAYER_KEY },
      fetchImpl: async () => { throw new Error("network must not run during construction"); },
    }),
    (error) => error.code === "invalid_input" && /guard_origin/.test(error.message),
  );

  const payer = privateKeyToAccount(PAYER_KEY);
  await assert.rejects(
    () => createBaseWalletRuntime({
      walletConfig: { filename },
      evmConnectors: [{
        id: "base-wallet",
        kind: "evm_transaction",
        chain_id: 8453,
        from: payer.address,
        max_estimated_network_fee_atomic: "1000",
        max_wallet_native_exposure_atomic: "2000",
        recheckFeeExposure: async () => ({}),
        signAndBroadcast: async () => ({}),
      }],
      env: { GOLDKEY_TEST_PAYER_KEY: PAYER_KEY },
      fetchImpl: async () => { throw new Error("network must not run during construction"); },
    }),
    (error) => error.code === "local_state_error" && /separate wallets/.test(error.message),
  );
});
