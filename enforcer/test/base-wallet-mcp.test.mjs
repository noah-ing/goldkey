import assert from "node:assert/strict";
import test from "node:test";
import { normalizeBaseWalletConfig } from "../src/adapters/base-wallet-config.mjs";
import { createBaseWalletMcpFacade } from "../src/adapters/base-wallet-mcp.mjs";

const FROM = "0x1111111111111111111111111111111111111111";
const RECIPIENT = "0x2222222222222222222222222222222222222222";
const SPENDER = "0x3333333333333333333333333333333333333333";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

function config({ nativeOnly = false } = {}) {
  const operations = [
    { kind: "native_transfer", recipients: [RECIPIENT], max_amount_atomic: "100" },
    ...nativeOnly ? [] : [
      { kind: "erc20_transfer", token: USDC, recipients: [RECIPIENT], max_amount_atomic: "1000000" },
      { kind: "erc20_approve", token: USDC, spenders: [SPENDER], max_amount_atomic: "1000000" },
    ],
  ];
  return normalizeBaseWalletConfig({
    schema: "goldkey.base-wallet-config.v1",
    rpc_url_env: "BASE_RPC_URL",
    execution_signer: { type: "env", key_env: "EXECUTION_KEY" },
    connectors: [{
      id: "base-wallet",
      chain_id: 8453,
      from: FROM,
      max_gas_limit: "100000",
      max_fee_per_gas_atomic: "1000",
      max_priority_fee_per_gas_atomic: "100",
      max_estimated_network_fee_atomic: "1000000",
      max_wallet_native_exposure_atomic: "2000000",
      operations,
    }],
  });
}

function nativeArgs(overrides = {}) {
  return {
    connector_id: "base-wallet",
    idempotency_key: "operator-job-0001",
    nonce: "3",
    gas_limit: "30000",
    max_fee_per_gas_atomic: "20",
    max_priority_fee_per_gas_atomic: "2",
    to: RECIPIENT,
    amount_atomic: "1",
    ...overrides,
  };
}

test("MCP exposes only high-level operation kinds present in operator config", () => {
  const all = createBaseWalletMcpFacade({ config: config(), executableWalletFactory: async () => ({ execute: async () => ({}) }) });
  assert.deepEqual(all.tools.map(({ name }) => name), [
    "goldkey_base_native_transfer",
    "goldkey_base_erc20_transfer",
    "goldkey_base_erc20_approve",
  ]);
  assert.equal(all.tools[0].inputSchema.additionalProperties, false);
  assert.deepEqual(all.tools[0].inputSchema.oneOf[0].properties.to.enum, [RECIPIENT]);

  const native = createBaseWalletMcpFacade({ config: config({ nativeOnly: true }), executableWalletFactory: async () => ({ execute: async () => ({}) }) });
  assert.deepEqual(native.tools.map(({ name }) => name), ["goldkey_base_native_transfer"]);
});

test("MCP probe never initializes executable runtime/signer and reports no side effects", async () => {
  let factoryCalls = 0;
  const facade = createBaseWalletMcpFacade({
    config: config(),
    executableWalletFactory: async () => { factoryCalls += 1; throw new Error("must not initialize"); },
  });
  const result = await facade.callTool("goldkey_base_native_transfer", nativeArgs({ probe: true }));
  assert.equal(factoryCalls, 0);
  assert.equal(result.structuredContent.mode, "probe");
  assert.equal(result.structuredContent.payment_attempted, false);
  assert.equal(result.structuredContent.signer_loaded, false);
  assert.equal(result.structuredContent.transaction_broadcast, false);
});

test("MCP rejects raw calldata and cap bypasses before executable runtime", async () => {
  let factoryCalls = 0;
  const facade = createBaseWalletMcpFacade({
    config: config(),
    executableWalletFactory: async () => { factoryCalls += 1; return { execute: async () => ({}) }; },
  });
  await assert.rejects(
    () => facade.callTool("goldkey_base_native_transfer", nativeArgs({ data: "0xdeadbeef" })),
    (error) => error.code === "invalid_input" && /unsupported/.test(error.message),
  );
  await assert.rejects(
    () => facade.callTool("goldkey_base_native_transfer", nativeArgs({ gas_limit: "100001" })),
    (error) => error.code === "invalid_input" && /gas_limit/.test(error.message),
  );
  assert.equal(factoryCalls, 0);
});

test("MCP execute lazily reuses the same guarded wallet path", async () => {
  let factoryCalls = 0;
  const calls = [];
  const facade = createBaseWalletMcpFacade({
    config: config(),
    executableWalletFactory: async () => {
      factoryCalls += 1;
      return {
        execute: async (request) => {
          calls.push(request);
          return { transactionHash: "0x" + "ab".repeat(32) };
        },
      };
    },
  });
  const first = await facade.callTool("goldkey_base_native_transfer", nativeArgs());
  const second = await facade.callTool("goldkey_base_native_transfer", nativeArgs({ idempotency_key: "operator-job-0002", nonce: "4" }));
  assert.equal(factoryCalls, 1);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].operation.kind, "native_transfer");
  assert.equal(first.structuredContent.transactionHash, "0x" + "ab".repeat(32));
  assert.equal(second.structuredContent.transactionHash, "0x" + "ab".repeat(32));
});
