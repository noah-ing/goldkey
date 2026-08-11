import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { runBaseWalletCli, safeBaseWalletCliError } from "../src/adapters/base-wallet-cli.mjs";

const FROM = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A";
const TO = "0x220FE98C77CE79baa00d47C5896BE05C2A7D3db0";

function configDocument() {
  return {
    schema: "goldkey.base-wallet-config.v1",
    rpc_url_env: "BASE_RPC_URL",
    execution_signer: { type: "env", key_env: "EXECUTION_PRIVATE_KEY" },
    connectors: [{
      id: "base-wallet",
      chain_id: 8453,
      from: FROM,
      max_gas_limit: "50000",
      max_fee_per_gas_atomic: "20",
      max_priority_fee_per_gas_atomic: "2",
      max_estimated_network_fee_atomic: "1000000",
      max_wallet_native_exposure_atomic: "2000000",
      operations: [{ kind: "native_transfer", recipients: [TO], max_amount_atomic: "100" }],
    }],
  };
}

function requestDocument(overrides = {}) {
  return {
    schema: "goldkey.base-wallet-request.v1",
    connector_id: "base-wallet",
    idempotency_key: "operator-job-0001",
    nonce: "3",
    gas_limit: "30000",
    max_fee_per_gas_atomic: "20",
    max_priority_fee_per_gas_atomic: "2",
    operation: { kind: "native_transfer", to: TO, amount_atomic: "1" },
    ...overrides,
  };
}

async function fixture(t, request = requestDocument(), { combined = false } = {}) {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-wallet-cli-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const configPath = path.join(directory, "goldkey.json");
  const requestPath = path.join(directory, "request.json");
  const config = combined
    ? { runtime: { schema: "loaded-by-central-runtime" }, base_wallet: configDocument() }
    : configDocument();
  await writeFile(configPath, JSON.stringify(config), { mode: 0o600 });
  await writeFile(requestPath, JSON.stringify(request), { mode: 0o600 });
  return { configPath, requestPath };
}

test("probe never reads environment, loads runtime/signer/RPC, authorizes, pays, signs, or broadcasts", async (t) => {
  const files = await fixture(t);
  let runtimeCalls = 0;
  let bindingCalls = 0;
  const hostileEnv = new Proxy({}, { get: () => { throw new Error("probe read environment"); } });
  const outcome = await runBaseWalletCli({
    argv: ["probe", "--config", files.configPath, "--request", files.requestPath],
    env: hostileEnv,
    runtimeFactory: async () => { runtimeCalls += 1; throw new Error("runtime called"); },
    connectorBindingsFactory: async () => { bindingCalls += 1; throw new Error("signer/RPC called"); },
  });
  assert.equal(outcome.kind, "result");
  assert.equal(outcome.value.mode, "probe");
  assert.equal(outcome.value.payment_attempted, false);
  assert.equal(outcome.value.signer_loaded, false);
  assert.equal(outcome.value.transaction_signed, false);
  assert.equal(outcome.value.transaction_broadcast, false);
  assert.equal(runtimeCalls, 0);
  assert.equal(bindingCalls, 0);
});

test("execute injects connector bindings into the central runtime, then calls its enforcer once", async (t) => {
  const files = await fixture(t, requestDocument(), { combined: true });
  const events = [];
  const connectors = Object.freeze([{ id: "base-wallet", kind: "evm_transaction" }]);
  const publicClient = Object.freeze({ label: "operator-client" });
  const outcome = await runBaseWalletCli({
    argv: ["execute", "--request", files.requestPath, "--config", files.configPath],
    env: {},
    connectorBindingsFactory: async ({ config }) => {
      events.push("bindings");
      assert.equal(config.filename, files.configPath);
      return Object.freeze({ connectors, publicClient });
    },
    runtimeFactory: async ({ walletConfig, evmConnectors, operatorPublicClient }) => {
      events.push("runtime");
      assert.equal(walletConfig.filename, files.configPath);
      assert.equal(evmConnectors, connectors);
      assert.equal(operatorPublicClient, publicClient);
      return {
        enforcer: {
          guardEvmTransaction: async (call) => {
            events.push("enforcer");
            assert.equal(call.connectorId, "base-wallet");
            assert.equal(call.transaction.to, TO);
            assert.equal(call.transaction.data, "0x");
            assert.equal(call.idempotencyKey, "operator-job-0001");
            return { transactionHash: "0x" + "ab".repeat(32) };
          },
        },
      };
    },
  });
  assert.deepEqual(events, ["bindings", "runtime", "enforcer"]);
  assert.equal(outcome.value.transactionHash, "0x" + "ab".repeat(32));
});

test("over-cap execute request cannot load signer/runtime or reach broadcast path", async (t) => {
  const files = await fixture(t, requestDocument({ gas_limit: "50001" }));
  let bindingCalls = 0;
  let runtimeCalls = 0;
  let enforcerCalls = 0;
  await assert.rejects(
    () => runBaseWalletCli({
      argv: ["execute", "--config", files.configPath, "--request", files.requestPath],
      env: {},
      connectorBindingsFactory: async () => { bindingCalls += 1; return {}; },
      runtimeFactory: async () => {
        runtimeCalls += 1;
        return { enforcer: { guardEvmTransaction: async () => { enforcerCalls += 1; } } };
      },
    }),
    (error) => error.code === "invalid_input" && /gas_limit/.test(error.message),
  );
  assert.equal(bindingCalls, 0);
  assert.equal(runtimeCalls, 0);
  assert.equal(enforcerCalls, 0);
});

test("help is standalone and CLI failures expose no stack/cause object", async () => {
  const outcome = await runBaseWalletCli({ argv: ["--help"], env: new Proxy({}, { get: () => { throw new Error("read env"); } }) });
  assert.equal(outcome.kind, "help");
  assert.match(outcome.text, /does not load a signer/);
  const failure = safeBaseWalletCliError(Object.assign(new Error("bounded failure"), { code: "invalid_input", cause: new Error("hidden") }));
  assert.deepEqual(failure, { ok: false, code: "invalid_input", message: "bounded failure" });
  assert.equal(Object.hasOwn(failure, "stack"), false);
  assert.equal(Object.hasOwn(failure, "cause"), false);
});
