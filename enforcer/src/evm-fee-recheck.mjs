import { getAddress, parseAbi, serializeTransaction } from "viem";
import { canonicalSha256 } from "./canonical.mjs";
import { DeadlineExceededError, InvalidInputError } from "./errors.mjs";

export const BASE_GAS_PRICE_ORACLE = getAddress("0x420000000000000000000000000000000000000F");
export const EVM_PREBROADCAST_FEE_SCHEMA = "goldkey.evm-prebroadcast-fee-state.v1";

const GAS_PRICE_ORACLE_ABI = parseAbi([
  "function getL1FeeUpperBound(uint256 unsignedTxSize) view returns (uint256)",
  "function getOperatorFee(uint256 gasUsed) view returns (uint256)",
]);

function assertClient(client) {
  for (const method of ["getBlock", "getTransactionCount", "getBalance", "readContract"]) {
    if (typeof client?.[method] !== "function") throw new InvalidInputError(`Base fee recheck client requires ${method}()`);
  }
}

function assertNotAborted(signal) {
  if (signal?.aborted) throw new DeadlineExceededError("EVM pre-broadcast fee recheck was aborted");
}

/**
 * Build the mandatory local EVM fee recheck from an operator-owned Base public
 * client. The oracle value is deliberately labelled an estimate: it is pinned
 * to the returned block and cannot guarantee the L1 data fee at later inclusion.
 */
export function createBaseFeeExposureRecheck({ client } = {}) {
  assertClient(client);
  return async function recheckFeeExposure({ transaction, signal } = {}) {
    assertNotAborted(signal);
    const block = await client.getBlock({ blockTag: "latest" });
    if (block?.number === null || block?.number === undefined || typeof block.hash !== "string") {
      throw new InvalidInputError("Base fee recheck latest block is missing a number or hash");
    }
    assertNotAborted(signal);

    const serialized = serializeTransaction({
      chainId: transaction.chain_id,
      type: "eip1559",
      nonce: Number(transaction.nonce),
      gas: BigInt(transaction.gas_limit),
      maxFeePerGas: BigInt(transaction.max_fee_per_gas_atomic),
      maxPriorityFeePerGas: BigInt(transaction.max_priority_fee_per_gas_atomic),
      to: transaction.to,
      value: BigInt(transaction.value_atomic),
      data: transaction.data,
      accessList: [],
    });
    const unsignedTxSize = BigInt((serialized.length - 2) / 2);
    const [pendingNonce, nativeBalance, l1FeeEstimate, operatorFeeEstimate] = await Promise.all([
      client.getTransactionCount({ address: transaction.from, blockTag: "pending" }),
      client.getBalance({ address: transaction.from, blockNumber: block.number }),
      client.readContract({
        address: BASE_GAS_PRICE_ORACLE,
        abi: GAS_PRICE_ORACLE_ABI,
        functionName: "getL1FeeUpperBound",
        args: [unsignedTxSize],
        blockNumber: block.number,
      }),
      client.readContract({
        address: BASE_GAS_PRICE_ORACLE,
        abi: GAS_PRICE_ORACLE_ABI,
        functionName: "getOperatorFee",
        args: [BigInt(transaction.gas_limit)],
        blockNumber: block.number,
      }),
    ]);
    assertNotAborted(signal);
    return Object.freeze({
      schema: EVM_PREBROADCAST_FEE_SCHEMA,
      chain_id: transaction.chain_id,
      from: transaction.from,
      transaction_sha256: canonicalSha256(transaction),
      block_number: BigInt(block.number).toString(),
      block_hash: block.hash.toLowerCase(),
      pending_nonce: BigInt(pendingNonce).toString(),
      native_balance_atomic: BigInt(nativeBalance).toString(),
      l1_fee_estimate_atomic: BigInt(l1FeeEstimate).toString(),
      operator_fee_estimate_atomic: BigInt(operatorFeeEstimate).toString(),
    });
  };
}
