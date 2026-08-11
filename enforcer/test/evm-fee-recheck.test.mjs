import assert from "node:assert/strict";
import test from "node:test";
import {
  BASE_GAS_PRICE_ORACLE,
  EVM_PREBROADCAST_FEE_SCHEMA,
  createBaseFeeExposureRecheck,
} from "../src/evm-fee-recheck.mjs";

const FROM = "0xd6b7E00FcD46966676F554fE0455BfF739e85b1b";
const TO = "0x220FE98C77CE79baa00d47C5896BE05C2A7D3db0";
const BLOCK_HASH = "0x" + "ab".repeat(32);

function transaction() {
  return Object.freeze({
    chain_id: 8453,
    from: FROM,
    to: TO,
    value_atomic: "1",
    data: "0x",
    nonce: "7",
    gas_limit: "30000",
    max_fee_per_gas_atomic: "20",
    max_priority_fee_per_gas_atomic: "2",
    type: "eip1559",
    access_list: Object.freeze([]),
  });
}

test("Base fee adapter pins wallet balance and oracle estimate to a fresh block", async () => {
  const calls = [];
  const client = {
    getBlock: async (value) => {
      calls.push(["block", value]);
      return { number: 123457n, hash: BLOCK_HASH.toUpperCase().replace("0X", "0x") };
    },
    getTransactionCount: async (value) => {
      calls.push(["nonce", value]);
      return 7;
    },
    getBalance: async (value) => {
      calls.push(["balance", value]);
      return 900000n;
    },
    readContract: async (value) => {
      calls.push(["oracle", value]);
      return value.functionName === "getOperatorFee" ? 100n : 1000n;
    },
  };
  const recheck = createBaseFeeExposureRecheck({ client });
  const state = await recheck({ transaction: transaction(), signal: new AbortController().signal });

  assert.equal(state.schema, EVM_PREBROADCAST_FEE_SCHEMA);
  assert.equal(state.block_hash, BLOCK_HASH);
  assert.equal(state.pending_nonce, "7");
  assert.equal(state.native_balance_atomic, "900000");
  assert.equal(state.l1_fee_estimate_atomic, "1000");
  assert.equal(state.operator_fee_estimate_atomic, "100");
  assert.equal(Object.isFrozen(state), true);
  assert.deepEqual(calls[0], ["block", { blockTag: "latest" }]);
  assert.deepEqual(calls[1], ["nonce", { address: FROM, blockTag: "pending" }]);
  assert.deepEqual(calls[2], ["balance", { address: FROM, blockNumber: 123457n }]);
  assert.equal(calls[3][0], "oracle");
  assert.equal(calls[3][1].address, BASE_GAS_PRICE_ORACLE);
  assert.equal(calls[3][1].functionName, "getL1FeeUpperBound");
  assert.equal(calls[3][1].blockNumber, 123457n);
  assert.equal(typeof calls[3][1].args[0], "bigint");
  assert.ok(calls[3][1].args[0] > 0n);
  assert.equal(calls[4][0], "oracle");
  assert.equal(calls[4][1].address, BASE_GAS_PRICE_ORACLE);
  assert.equal(calls[4][1].functionName, "getOperatorFee");
  assert.deepEqual(calls[4][1].args, [30000n]);
  assert.equal(calls[4][1].blockNumber, 123457n);
});

test("Base fee adapter validates its client and honors an aborted enforcement deadline", async () => {
  assert.throws(() => createBaseFeeExposureRecheck({ client: {} }), /getBlock/);
  const client = {
    getBlock: async () => ({ number: 1n, hash: BLOCK_HASH }),
    getTransactionCount: async () => 7,
    getBalance: async () => 1n,
    readContract: async () => 1n,
  };
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    createBaseFeeExposureRecheck({ client })({ transaction: transaction(), signal: controller.signal }),
    (error) => error.code === "deadline_exceeded",
  );
});
