import assert from "node:assert/strict";
import test from "node:test";
import {
  encodeAbiParameters,
  encodeEventTopics,
  encodeFunctionData,
  getAddress,
  parseAbi,
  parseSignature,
} from "viem";
import { sha256 } from "../src/canonical.mjs";
import { createChainService } from "../src/chain.mjs";
import { BASE_GAS_PRICE_ORACLE, hashEvmTransaction } from "../src/evm-guard.mjs";

const CONTRACT = getAddress("0x0000000000000000000000000000000000000001");
const USDC = getAddress("0x0000000000000000000000000000000000000002");
const TREASURY = getAddress("0x0000000000000000000000000000000000000003");
const OWNER = getAddress("0x0000000000000000000000000000000000000004");
const TERMS_HASH = `0x${"ab".repeat(32)}`;
const BASE_USDC = getAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
const EIP3009_ABI = parseAbi([
  "function transferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce,uint8 v,bytes32 r,bytes32 s)",
  "event Transfer(address indexed from,address indexed to,uint256 value)",
]);

function fixture(overrides = {}) {
  const calls = [];
  const values = {
    USDC,
    treasury: TREASURY,
    MINT_PRICE: 50_000_000n,
    MAX_SUPPLY: 10_000n,
    CALLS_PER_TERM: 10_000n,
    SERVICE_TERM_SECONDS: 365n * 86_400n,
    LICENSE_TERMS_HASH: TERMS_HASH,
    totalMinted: 37n,
    decimals: 6,
    accessState: [OWNER, 2n, 1_900_000_000n, 7n, true],
    getL1FeeUpperBound: 1_000n,
    getOperatorFee: 200n,
    ...overrides.values,
  };
  const client = {
    getChainId: async () => overrides.chainId ?? 8453,
    getCode: async ({ address }) => overrides.emptyCodeAddress === address ? "0x" : "0x60006000",
    getBlock: overrides.getBlock ?? (async () => ({ number: 123n, hash: `0x${"12".repeat(32)}` })),
    getTransactionCount: overrides.getTransactionCount ?? (async () => 7),
    call: overrides.call ?? (async () => ({ data: "0x01" })),
    estimateGas: overrides.estimateGas ?? (async () => 21_000n),
    getTransaction: overrides.getTransaction ?? (async () => { throw new Error("missing mock getTransaction"); }),
    getTransactionReceipt: overrides.getTransactionReceipt ?? (async () => { throw new Error("missing mock getTransactionReceipt"); }),
    verifyMessage: overrides.verifyMessage ?? (async () => true),
    readContract: async (request) => {
      const { address, functionName } = request;
      calls.push(request);
      if (!Object.hasOwn(values, functionName)) throw new Error(`missing mock ${functionName}`);
      return values[functionName];
    },
  };
  const config = {
    chainId: 8453,
    rpcUrl: "https://mainnet.base.org",
    contractAddress: CONTRACT,
    usdcAddress: overrides.usdcAddress ?? USDC,
    treasuryAddress: TREASURY,
    callsPerTerm: 10_000,
    termDays: 365,
  };
  return { chain: createChainService(config, client), calls };
}

test("startup validation accepts the exact deployed commercial identity", async () => {
  const { chain } = fixture();
  const identity = await chain.validateDeployment({ expectedTermsHash: TERMS_HASH });
  assert.equal(identity.chainId, 8453);
  assert.equal(identity.mintPriceAtomic, "50000000");
  assert.equal(identity.maxSupply, "10000");
  assert.equal(identity.callsPerTerm, 10_000);
  assert.equal(identity.termsHash, TERMS_HASH);
});

test("startup validation fails closed on identity mismatches", async () => {
  const wrongChain = fixture({ chainId: 84532 }).chain;
  await assert.rejects(() => wrongChain.validateDeployment({ expectedTermsHash: TERMS_HASH }), /chain id is 84532/);

  const wrongTerms = fixture({ values: { LICENSE_TERMS_HASH: `0x${"cd".repeat(32)}` } }).chain;
  await assert.rejects(() => wrongTerms.validateDeployment({ expectedTermsHash: TERMS_HASH }), /terms hash is/);

  const noContract = fixture({ emptyCodeAddress: CONTRACT }).chain;
  await assert.rejects(() => noContract.validateDeployment({ expectedTermsHash: TERMS_HASH }), /no bytecode/);
});

test("passState consumes the one-call accessState ABI and onchain active flag", async () => {
  const { chain, calls } = fixture();
  const pass = await chain.passState("9");
  assert.deepEqual(pass, {
    tokenId: "9",
    owner: OWNER,
    term: "2",
    ownershipEpoch: "7",
    expiresAt: 1_900_000_000_000,
    active: true,
  });
  assert.deepEqual(calls.map(({ functionName }) => functionName), ["accessState"]);
});

test("purchase plan uses one total approval and explicitly ordered mint batches", () => {
  const { chain } = fixture();
  const plan = chain.purchasePlanTransactions(OWNER, 45);
  assert.equal(plan.length, 4);
  assert.equal(plan[0].asset_amount_atomic, (45n * 50_000_000n).toString());
  assert.deepEqual(plan.map(({ sequence }) => sequence), [1, 2, 3, 4]);
  assert.deepEqual(plan.map(({ depends_on }) => depends_on), [[], [1], [2], [3]]);
  assert.deepEqual(plan.slice(1).map(({ batch_index, quantity }) => [batch_index, quantity]), [[1, "20"], [2, "20"], [3, "5"]]);
});

test("Guard simulation pins block, target code, exact transaction, return data, and gas", async () => {
  const transaction = {
    chain_id: 8453,
    from: OWNER,
    to: CONTRACT,
    value_atomic: "0",
    data: "0x",
    nonce: "7",
    gas_limit: "30000",
    max_fee_per_gas_atomic: "20",
    max_priority_fee_per_gas_atomic: "2",
  };
  const observed = {};
  const { chain, calls } = fixture({
    getTransactionCount: async (request) => { observed.nonce = request; return 7; },
    call: async (request) => { observed.call = request; return { data: "0x01" }; },
    estimateGas: async (request) => { observed.estimate = request; return 21_000n; },
  });
  const evidence = await chain.simulateGuardTransaction(transaction);
  assert.deepEqual(evidence, {
    schema: "goldkey.evm-simulation-evidence.v2",
    status: "success",
    chain_id: 8453,
    transaction_sha256: hashEvmTransaction(transaction),
    block_number: "123",
    block_hash: `0x${"12".repeat(32)}`,
    target_code_sha256: sha256("0x60006000"),
    return_data_sha256: sha256("0x01"),
    gas_estimate: "21000",
    pending_nonce: "7",
    l1_fee_estimate_atomic: "1000",
    operator_fee_estimate_atomic: "200",
    gas_price_oracle_address: BASE_GAS_PRICE_ORACLE,
  });
  assert.deepEqual(observed.nonce, { address: OWNER, blockTag: "pending" });
  assert.equal(observed.call.blockNumber, 123n);
  assert.equal(observed.call.nonce, 7);
  assert.equal(observed.call.gas, 30_000n);
  assert.equal(observed.call.maxFeePerGas, 20n);
  assert.equal(observed.call.maxPriorityFeePerGas, 2n);
  assert.equal(observed.estimate.blockNumber, 123n);
  assert.equal(Object.hasOwn(observed.estimate, "gas"), false);
  assert.equal(calls[0].address, BASE_GAS_PRICE_ORACLE);
  assert.equal(calls[0].functionName, "getL1FeeUpperBound");
  assert.equal(calls[0].blockNumber, 123n);
  assert.ok(calls[0].args[0] > 0n);
  assert.equal(calls[1].address, BASE_GAS_PRICE_ORACLE);
  assert.equal(calls[1].functionName, "getOperatorFee");
  assert.equal(calls[1].blockNumber, 123n);
  assert.deepEqual(calls[1].args, [30000n]);
});

test("Guard simulation records a deterministic revert without turning transport failures into policy evidence", async () => {
  const transaction = {
    chain_id: 8453,
    from: OWNER,
    to: CONTRACT,
    value_atomic: "0",
    data: "0x",
    nonce: "7",
    gas_limit: "30000",
    max_fee_per_gas_atomic: "20",
    max_priority_fee_per_gas_atomic: "2",
  };
  const reverted = fixture({
    call: async () => {
      const cause = { name: "ExecutionRevertedError", data: "0xdeadbeef" };
      throw Object.assign(new Error("execution reverted"), { cause });
    },
  }).chain;
  const evidence = await reverted.simulateGuardTransaction(transaction);
  assert.equal(evidence.status, "revert");
  assert.equal(evidence.return_data_sha256, sha256("0xdeadbeef"));
  assert.equal(evidence.target_code_sha256, sha256("0x60006000"));
  assert.equal(evidence.gas_estimate, "21000");

  const unavailable = fixture({ call: async () => { throw new Error("RPC timeout"); } }).chain;
  await assert.rejects(
    () => unavailable.simulateGuardTransaction(transaction),
    (error) => error.status === 503 && error.code === "guard_simulation_unavailable",
  );
});

test("Guard simulation rejects chain drift and creation before any RPC call", async () => {
  let blocks = 0;
  const { chain } = fixture({ getBlock: async () => { blocks += 1; return { number: 1n, hash: `0x${"34".repeat(32)}` }; } });
  await assert.rejects(
    () => chain.simulateGuardTransaction({ chain_id: 84532, from: OWNER, to: CONTRACT, value_atomic: "0", data: "0x", nonce: "7", gas_limit: "30000", max_fee_per_gas_atomic: "20", max_priority_fee_per_gas_atomic: "2" }),
    (error) => error.status === 400 && error.code === "guard_simulation_chain_mismatch",
  );
  await assert.rejects(
    () => chain.simulateGuardTransaction({ chain_id: 8453, from: OWNER, value_atomic: "0", data: "0x", nonce: "7", gas_limit: "30000", max_fee_per_gas_atomic: "20", max_priority_fee_per_gas_atomic: "2" }),
    (error) => error.status === 400 && error.code === "guard_simulation_creation_blocked",
  );
  assert.equal(blocks, 0);
});

test("Guard payment recovery proves the exact Base USDC EIP-3009 calldata and transfer receipt", async () => {
  const transaction = `0x${"aa".repeat(32)}`;
  const blockHash = `0x${"bb".repeat(32)}`;
  const nonce = `0x${"cc".repeat(32)}`;
  const signature = `0x${"11".repeat(32)}${"22".repeat(32)}1b`;
  const authorization = {
    from: OWNER,
    to: TREASURY,
    value: "50000",
    validAfter: "0",
    validBefore: "2000000000",
    nonce,
    signature,
  };
  const parsed = parseSignature(signature);
  const input = encodeFunctionData({
    abi: EIP3009_ABI,
    functionName: "transferWithAuthorization",
    args: [OWNER, TREASURY, 50_000n, 0n, 2_000_000_000n, nonce, parsed.v, parsed.r, parsed.s],
  });
  const transferLog = {
    address: BASE_USDC,
    topics: encodeEventTopics({ abi: EIP3009_ABI, eventName: "Transfer", args: { from: OWNER, to: TREASURY } }),
    data: encodeAbiParameters([{ type: "uint256" }], [50_000n]),
  };
  const baseTransaction = {
    hash: transaction,
    blockNumber: 777n,
    blockHash,
    chainId: 8453,
    to: BASE_USDC,
    input: `${input}802180218021`,
  };
  const baseReceipt = {
    status: "success",
    transactionHash: transaction,
    blockNumber: 777n,
    blockHash,
    logs: [transferLog],
  };
  const { chain } = fixture({
    usdcAddress: BASE_USDC,
    getTransaction: async () => baseTransaction,
    getTransactionReceipt: async () => baseReceipt,
  });
  const verified = await chain.verifyGuardPaymentTransaction({ transaction, authorization });
  assert.deepEqual(verified, {
    chain_id: 8453,
    transaction,
    block_number: "777",
    block_hash: blockHash,
    payer: OWNER,
    recipient: TREASURY,
    amount_atomic: "50000",
  });

  const wrongCalldata = fixture({
    usdcAddress: BASE_USDC,
    getTransaction: async () => ({ ...baseTransaction, input: `0x${"00".repeat(32)}` }),
    getTransactionReceipt: async () => baseReceipt,
  }).chain;
  await assert.rejects(
    () => wrongCalldata.verifyGuardPaymentTransaction({ transaction, authorization }),
    (error) => error.code === "guard_payment_calldata_mismatch",
  );

  const wrongTransfer = fixture({
    usdcAddress: BASE_USDC,
    getTransaction: async () => baseTransaction,
    getTransactionReceipt: async () => ({ ...baseReceipt, logs: [{ ...transferLog, data: encodeAbiParameters([{ type: "uint256" }], [49_999n]) }] }),
  }).chain;
  await assert.rejects(
    () => wrongTransfer.verifyGuardPaymentTransaction({ transaction, authorization }),
    (error) => error.code === "guard_payment_transfer_mismatch",
  );
});
