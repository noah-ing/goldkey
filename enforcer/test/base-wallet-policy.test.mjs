import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { decodeFunctionData, parseAbi } from "viem";
import { createGuardedBaseWallet } from "../src/adapters/base-wallet.mjs";
import {
  BASE_WALLET_CONFIG_SCHEMA,
  loadBaseWalletConfig,
  normalizeBaseWalletConfig,
} from "../src/adapters/base-wallet-config.mjs";
import {
  BASE_WALLET_REQUEST_SCHEMA,
  buildBaseWalletCall,
  probeBaseWalletRequest,
} from "../src/adapters/base-wallet-request.mjs";

const FROM = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A";
const RECIPIENT = "0x220FE98C77CE79baa00d47C5896BE05C2A7D3db0";
const OTHER = "0xd6b7E00FcD46966676F554fE0455BfF739e85b1b";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const ERC20 = parseAbi([
  "function transfer(address to, uint256 amount) returns (bool)",
  "function approve(address spender, uint256 amount) returns (bool)",
]);

function rawConfig() {
  return {
    schema: BASE_WALLET_CONFIG_SCHEMA,
    rpc_url_env: "GOLDKEY_BASE_RPC_URL",
    execution_signer: { type: "env", key_env: "GOLDKEY_EXECUTION_PRIVATE_KEY" },
    connectors: [{
      id: "base-wallet",
      chain_id: 8453,
      from: FROM,
      max_gas_limit: "100000",
      max_fee_per_gas_atomic: "1000",
      max_priority_fee_per_gas_atomic: "100",
      max_estimated_network_fee_atomic: "1000000",
      max_wallet_native_exposure_atomic: "2000000",
      operations: [
        { kind: "native_transfer", recipients: [RECIPIENT], max_amount_atomic: "10000" },
        { kind: "erc20_transfer", token: USDC, recipients: [RECIPIENT], max_amount_atomic: "5000000" },
        { kind: "erc20_approve", token: USDC, spenders: [OTHER], max_amount_atomic: "3000000" },
      ],
    }],
  };
}

function config() {
  return normalizeBaseWalletConfig(rawConfig(), { baseDirectory: "/operator", filename: "/operator/goldkey.json" });
}

function request(operation = { kind: "native_transfer", to: RECIPIENT, amount_atomic: "25" }) {
  return {
    schema: BASE_WALLET_REQUEST_SCHEMA,
    connector_id: "base-wallet",
    idempotency_key: "operator-job-0001",
    nonce: "7",
    gas_limit: "50000",
    max_fee_per_gas_atomic: "900",
    max_priority_fee_per_gas_atomic: "90",
    operation,
  };
}

test("wallet request creates one exact frozen native transaction", () => {
  const call = buildBaseWalletCall({ config: config(), request: request() });
  assert.deepEqual(call.transaction, {
    chain_id: 8453,
    from: FROM,
    to: RECIPIENT,
    value_atomic: "25",
    data: "0x",
    nonce: "7",
    gas_limit: "50000",
    max_fee_per_gas_atomic: "900",
    max_priority_fee_per_gas_atomic: "90",
    type: "eip1559",
    access_list: [],
  });
  assert.equal(Object.isFrozen(call), true);
  assert.equal(Object.isFrozen(call.transaction), true);
  assert.equal(Object.isFrozen(call.transaction.access_list), true);
});

test("ERC-20 transfer and approval calldata are canonical and cannot carry arbitrary data", () => {
  const transfer = buildBaseWalletCall({
    config: config(),
    request: request({ kind: "erc20_transfer", token: USDC, to: RECIPIENT, amount_atomic: "1234" }),
  });
  assert.equal(transfer.transaction.to, USDC);
  assert.equal(transfer.transaction.value_atomic, "0");
  assert.deepEqual(decodeFunctionData({ abi: ERC20, data: transfer.transaction.data }), {
    functionName: "transfer",
    args: [RECIPIENT, 1234n],
  });

  const approval = buildBaseWalletCall({
    config: config(),
    request: request({ kind: "erc20_approve", token: USDC, spender: OTHER, amount_atomic: "999" }),
  });
  assert.deepEqual(decodeFunctionData({ abi: ERC20, data: approval.transaction.data }), {
    functionName: "approve",
    args: [OTHER, 999n],
  });
  assert.throws(
    () => buildBaseWalletCall({ config: config(), request: { ...request(), data: "0xdeadbeef" } }),
    (error) => error.code === "invalid_input" && /unsupported fields/.test(error.message),
  );
  assert.throws(
    () => buildBaseWalletCall({ config: config(), request: request({ ...request().operation, data: "0xdeadbeef" }) }),
    (error) => error.code === "invalid_input" && /unsupported fields/.test(error.message),
  );
});

test("operator allowlists and every local amount/gas/fee cap fail before the enforcer", async () => {
  let enforcerCalls = 0;
  const wallet = createGuardedBaseWallet({
    config: config(),
    enforcer: { guardEvmTransaction: async () => { enforcerCalls += 1; throw new Error("must not run"); } },
  });
  const attacks = [
    { ...request(), transaction: { to: OTHER } },
    request({ kind: "native_transfer", to: OTHER, amount_atomic: "1" }),
    request({ kind: "native_transfer", to: RECIPIENT, amount_atomic: "10001" }),
    request({ kind: "erc20_transfer", token: OTHER, to: RECIPIENT, amount_atomic: "1" }),
    request({ kind: "erc20_transfer", token: USDC, to: OTHER, amount_atomic: "1" }),
    request({ kind: "erc20_transfer", token: USDC, to: RECIPIENT, amount_atomic: "5000001" }),
    request({ kind: "erc20_approve", token: USDC, spender: RECIPIENT, amount_atomic: "1" }),
    request({ kind: "erc20_approve", token: USDC, spender: OTHER, amount_atomic: ((1n << 256n) - 1n).toString() }),
    { ...request(), gas_limit: "100001" },
    { ...request(), max_fee_per_gas_atomic: "1001" },
    { ...request(), max_priority_fee_per_gas_atomic: "101" },
  ];
  for (const attack of attacks) {
    await assert.rejects(() => wallet.execute(attack), (error) => error.code === "invalid_input");
  }
  assert.equal(enforcerCalls, 0);
});

test("adapter hands only the exact frozen transaction to the injected enforcer", async () => {
  const calls = [];
  const wallet = createGuardedBaseWallet({
    config: config(),
    enforcer: {
      guardEvmTransaction: async (call) => {
        calls.push(call);
        assert.equal(Object.isFrozen(call), true);
        assert.equal(Object.isFrozen(call.transaction), true);
        return { transactionHash: "0x" + "ab".repeat(32) };
      },
    },
  });
  const outcome = await wallet.execute(request());
  assert.equal(outcome.transactionHash, "0x" + "ab".repeat(32));
  assert.equal(calls.length, 1);
  assert.deepEqual(Object.keys(calls[0]).sort(), ["connectorId", "idempotencyKey", "transaction"]);
  assert.equal(calls[0].connectorId, "base-wallet");
  assert.equal(calls[0].idempotencyKey, "operator-job-0001");
});

test("probe is explicit that it did not load, authorize, pay, sign, or broadcast", () => {
  const result = probeBaseWalletRequest({ config: config(), request: request() });
  assert.equal(result.mode, "probe");
  assert.equal(result.payment_attempted, false);
  assert.equal(result.signer_loaded, false);
  assert.equal(result.transaction_signed, false);
  assert.equal(result.transaction_broadcast, false);
  assert.equal(result.local_caps.max_wallet_native_exposure_atomic, "2000000");
});

test("config rejects embedded keys, unsafe signer aliases, and incoherent fee exposure", () => {
  assert.throws(
    () => normalizeBaseWalletConfig({ ...rawConfig(), private_key: "0x" + "11".repeat(32) }),
    (error) => error.code === "invalid_input" && /unsupported/.test(error.message),
  );
  assert.throws(
    () => normalizeBaseWalletConfig({ ...rawConfig(), execution_signer: "execution" }),
    (error) => error.code === "invalid_input",
  );
  const connector = rawConfig().connectors[0];
  assert.throws(
    () => normalizeBaseWalletConfig({
      ...rawConfig(),
      connectors: [{ ...connector, max_estimated_network_fee_atomic: "2000001" }],
    }),
    (error) => error.code === "invalid_input" && /exceeds wallet exposure/.test(error.message),
  );
});

test("loader accepts standalone or combined base_wallet documents and rejects mutable/symlink policy files", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-wallet-config-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const standalone = path.join(directory, "standalone.json");
  const combined = path.join(directory, "combined.json");
  await writeFile(standalone, JSON.stringify(rawConfig()), { mode: 0o600 });
  await writeFile(combined, JSON.stringify({ runtime: { schema: "owned-elsewhere" }, base_wallet: rawConfig() }), { mode: 0o600 });
  assert.equal((await loadBaseWalletConfig(standalone)).connectors[0].id, "base-wallet");
  assert.equal((await loadBaseWalletConfig(combined)).connectors[0].id, "base-wallet");
  assert.equal((await loadBaseWalletConfig(combined)).filename, combined);

  if (process.platform !== "win32") {
    const mutable = path.join(directory, "mutable.json");
    await writeFile(mutable, JSON.stringify(rawConfig()), { mode: 0o600 });
    await chmod(mutable, 0o666);
    await assert.rejects(() => loadBaseWalletConfig(mutable), (error) => error.code === "local_state_error" && /permissions/.test(error.message));
    const linked = path.join(directory, "linked.json");
    await symlink(standalone, linked);
    await assert.rejects(() => loadBaseWalletConfig(linked), (error) => error.code === "local_state_error" && /symlink/.test(error.message));
  }
});
