import assert from "node:assert/strict";
import test from "node:test";
import { getAddress } from "viem";
import { createChainService } from "../src/chain.mjs";

const CONTRACT = getAddress("0x0000000000000000000000000000000000000001");
const USDC = getAddress("0x0000000000000000000000000000000000000002");
const TREASURY = getAddress("0x0000000000000000000000000000000000000003");
const OWNER = getAddress("0x0000000000000000000000000000000000000004");
const TERMS_HASH = `0x${"ab".repeat(32)}`;

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
    ...overrides.values,
  };
  const client = {
    getChainId: async () => overrides.chainId ?? 8453,
    getCode: async ({ address }) => overrides.emptyCodeAddress === address ? "0x" : "0x60006000",
    readContract: async ({ address, functionName }) => {
      calls.push({ address, functionName });
      if (!Object.hasOwn(values, functionName)) throw new Error(`missing mock ${functionName}`);
      return values[functionName];
    },
  };
  const config = {
    chainId: 8453,
    rpcUrl: "https://mainnet.base.org",
    contractAddress: CONTRACT,
    usdcAddress: USDC,
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
