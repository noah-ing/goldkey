import {
  BaseError,
  createPublicClient,
  decodeEventLog,
  defineChain,
  encodeFunctionData,
  ExecutionRevertedError,
  getAddress,
  http,
  isAddressEqual,
  parseAbi,
  parseSignature,
  serializeTransaction,
} from "viem";
import { sha256 } from "./canonical.mjs";
import {
  CALLS_PER_TERM,
  ERC20_ABI,
  GOLDKEY_ABI,
  MAX_SUPPLY,
  MINT_PRICE_ATOMIC,
} from "./contract.mjs";
import {
  BASE_GAS_PRICE_ORACLE,
  EVM_SIMULATION_SCHEMA,
  hashEvmTransaction,
  normalizeEvmTransaction,
} from "./evm-guard.mjs";
import { ServiceError } from "./errors.mjs";

function normalizedHex(value) {
  return typeof value === "string" && /^0x(?:[0-9a-fA-F]{2})*$/.test(value) ? value.toLowerCase() : "0x";
}

function findExecutionRevert(error) {
  if (error instanceof ExecutionRevertedError) return error;
  if (error instanceof BaseError && typeof error.walk === "function") {
    return error.walk((cause) => cause instanceof ExecutionRevertedError) ?? undefined;
  }
  let cause = error?.cause;
  while (cause) {
    if (cause instanceof ExecutionRevertedError || cause?.name === "ExecutionRevertedError") return cause;
    cause = cause.cause;
  }
  return undefined;
}

const GAS_PRICE_ORACLE_ABI = parseAbi([
  "function getL1FeeUpperBound(uint256 unsignedTxSize) view returns (uint256)",
  "function getOperatorFee(uint256 gasUsed) view returns (uint256)",
]);
const EIP3009_SETTLEMENT_ABI = parseAbi([
  "function transferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce,uint8 v,bytes32 r,bytes32 s)",
  "event Transfer(address indexed from,address indexed to,uint256 value)",
]);

export function canonicalTokenId(value) {
  const text = String(value);
  if (!/^(0|[1-9]\d*)$/.test(text)) throw new Error("token_id must be a canonical uint256 decimal string");
  const tokenId = BigInt(text);
  if (tokenId <= 0n || tokenId > (1n << 256n) - 1n) throw new Error("token_id is outside uint256 range");
  return text;
}

export function createChainService(config, clientOverride) {
  const chain = defineChain({
    id: config.chainId,
    name: `EVM ${config.chainId}`,
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [config.rpcUrl] } },
  });
  const client = clientOverride ?? createPublicClient({ chain, transport: http(config.rpcUrl, { timeout: 10_000, retryCount: 2 }) });

  async function passState(tokenIdInput) {
    const tokenId = BigInt(canonicalTokenId(tokenIdInput));
    const [owner, term, expiresAt, ownershipEpoch, active] = await client.readContract({
      address: config.contractAddress,
      abi: GOLDKEY_ABI,
      functionName: "accessState",
      args: [tokenId],
    });
    return {
      tokenId: tokenId.toString(),
      owner: getAddress(owner),
      term: BigInt(term).toString(),
      ownershipEpoch: BigInt(ownershipEpoch).toString(),
      expiresAt: Number(expiresAt) * 1000,
      active: Boolean(active),
    };
  }

  async function validateDeployment({ expectedTermsHash }) {
    if (typeof expectedTermsHash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(expectedTermsHash)) {
      throw new Error("expectedTermsHash must be a bytes32 hex value");
    }

    let state;
    try {
      state = await Promise.all([
        client.getChainId(),
        client.getCode({ address: config.contractAddress }),
        client.getCode({ address: config.usdcAddress }),
        client.readContract({ address: config.contractAddress, abi: GOLDKEY_ABI, functionName: "USDC" }),
        client.readContract({ address: config.contractAddress, abi: GOLDKEY_ABI, functionName: "treasury" }),
        client.readContract({ address: config.contractAddress, abi: GOLDKEY_ABI, functionName: "MINT_PRICE" }),
        client.readContract({ address: config.contractAddress, abi: GOLDKEY_ABI, functionName: "MAX_SUPPLY" }),
        client.readContract({ address: config.contractAddress, abi: GOLDKEY_ABI, functionName: "CALLS_PER_TERM" }),
        client.readContract({ address: config.contractAddress, abi: GOLDKEY_ABI, functionName: "SERVICE_TERM_SECONDS" }),
        client.readContract({ address: config.contractAddress, abi: GOLDKEY_ABI, functionName: "LICENSE_TERMS_HASH" }),
        client.readContract({ address: config.contractAddress, abi: GOLDKEY_ABI, functionName: "totalMinted" }),
        client.readContract({ address: config.usdcAddress, abi: ERC20_ABI, functionName: "decimals" }),
      ]);
    } catch (cause) {
      throw new Error(`Unable to read GoldKey deployment identity: ${cause.message}`, { cause });
    }

    const [
      chainId,
      contractCode,
      paymentTokenCode,
      paymentToken,
      treasury,
      mintPrice,
      maxSupply,
      callsPerTerm,
      serviceTermSeconds,
      termsHash,
      totalMinted,
      paymentTokenDecimals,
    ] = state;
    const mismatches = [];
    if (Number(chainId) !== config.chainId) mismatches.push(`chain id is ${chainId}, expected ${config.chainId}`);
    if (!contractCode || contractCode === "0x") mismatches.push("GoldKey contract has no bytecode");
    if (!paymentTokenCode || paymentTokenCode === "0x") mismatches.push("configured USDC contract has no bytecode");
    if (!isAddressEqual(getAddress(paymentToken), config.usdcAddress)) {
      mismatches.push(`contract USDC is ${paymentToken}, expected ${config.usdcAddress}`);
    }
    if (!isAddressEqual(getAddress(treasury), config.treasuryAddress)) {
      mismatches.push(`contract treasury is ${treasury}, expected ${config.treasuryAddress}`);
    }
    if (BigInt(mintPrice) !== MINT_PRICE_ATOMIC) {
      mismatches.push(`mint price is ${mintPrice}, expected ${MINT_PRICE_ATOMIC}`);
    }
    if (BigInt(maxSupply) !== MAX_SUPPLY) {
      mismatches.push(`max supply is ${maxSupply}, expected ${MAX_SUPPLY}`);
    }
    if (BigInt(callsPerTerm) !== BigInt(CALLS_PER_TERM) || Number(callsPerTerm) !== config.callsPerTerm) {
      mismatches.push(`calls per term is ${callsPerTerm}, expected ${config.callsPerTerm}`);
    }
    const expectedTermSeconds = BigInt(config.termDays) * 86_400n;
    if (BigInt(serviceTermSeconds) !== expectedTermSeconds) {
      mismatches.push(`service term is ${serviceTermSeconds} seconds, expected ${expectedTermSeconds}`);
    }
    if (String(termsHash).toLowerCase() !== expectedTermsHash.toLowerCase()) {
      mismatches.push(`terms hash is ${termsHash}, expected ${expectedTermsHash}`);
    }
    if (Number(paymentTokenDecimals) !== 6) {
      mismatches.push(`payment token has ${paymentTokenDecimals} decimals, expected 6`);
    }
    if (BigInt(totalMinted) > MAX_SUPPLY) {
      mismatches.push(`total minted ${totalMinted} exceeds cap ${MAX_SUPPLY}`);
    }
    if (mismatches.length > 0) {
      throw new Error(`GoldKey deployment identity mismatch: ${mismatches.join("; ")}`);
    }
    return {
      chainId: Number(chainId),
      contractAddress: config.contractAddress,
      usdcAddress: getAddress(paymentToken),
      treasuryAddress: getAddress(treasury),
      mintPriceAtomic: BigInt(mintPrice).toString(),
      maxSupply: BigInt(maxSupply).toString(),
      callsPerTerm: Number(callsPerTerm),
      termsHash,
      totalMinted: BigInt(totalMinted).toString(),
    };
  }

  async function verifyWalletMessage({ wallet, message, signature }) {
    return client.verifyMessage({ address: getAddress(wallet), message, signature });
  }

  async function simulateGuardTransaction(rawTransaction) {
    const transaction = normalizeEvmTransaction(rawTransaction);
    if (transaction.chain_id !== config.chainId) {
      throw new ServiceError(400, "guard_simulation_chain_mismatch", "Guard transaction chain does not match this RPC service");
    }
    if (!transaction.to) {
      throw new ServiceError(400, "guard_simulation_creation_blocked", "Contract creation is not eligible for Guard simulation");
    }

    const request = {
      account: transaction.from,
      to: transaction.to,
      value: BigInt(transaction.value_atomic),
      data: transaction.data,
      nonce: Number(transaction.nonce),
      gas: BigInt(transaction.gas_limit),
      maxFeePerGas: BigInt(transaction.max_fee_per_gas_atomic),
      maxPriorityFeePerGas: BigInt(transaction.max_priority_fee_per_gas_atomic),
    };
    let block;
    let code;
    let pendingNonce;
    let l1FeeEstimate;
    let operatorFeeEstimate;
    try {
      block = await client.getBlock({ blockTag: "latest" });
      if (block.number === null || !block.hash) throw new Error("latest block is missing a number or hash");
      [code, pendingNonce] = await Promise.all([
        client.getCode({ address: transaction.to, blockNumber: block.number }).then(normalizedHex),
        client.getTransactionCount({ address: transaction.from, blockTag: "pending" }),
      ]);
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
      [l1FeeEstimate, operatorFeeEstimate] = await Promise.all([
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
    } catch (cause) {
      throw new ServiceError(503, "guard_simulation_unavailable", "Unable to pin EVM state, pending nonce, target code, and Base L1-data/operator-fee estimates", { cause: cause.message });
    }

    const base = {
      schema: EVM_SIMULATION_SCHEMA,
      chain_id: transaction.chain_id,
      transaction_sha256: hashEvmTransaction(transaction),
      block_number: BigInt(block.number).toString(),
      block_hash: block.hash.toLowerCase(),
      target_code_sha256: sha256(code),
      pending_nonce: BigInt(pendingNonce).toString(),
      // getL1FeeUpperBound is evaluated at this pinned block. Despite the
      // contract method name, this is evidence of a point-in-time estimate,
      // not an absolute cap on the fee at later inclusion.
      l1_fee_estimate_atomic: BigInt(l1FeeEstimate).toString(),
      operator_fee_estimate_atomic: BigInt(operatorFeeEstimate).toString(),
      gas_price_oracle_address: BASE_GAS_PRICE_ORACLE,
    };
    let gasEstimate;
    let gasEstimateFailure;
    try {
      const { gas: _gasLimit, ...estimateRequest } = request;
      gasEstimate = await client.estimateGas({ ...estimateRequest, blockNumber: block.number });
    } catch (cause) {
      gasEstimateFailure = cause;
    }
    try {
      const result = await client.call({ ...request, blockNumber: block.number });
      if (gasEstimate === undefined) {
        throw new ServiceError(503, "guard_simulation_unavailable", "EVM call succeeded but a pinned gas estimate was unavailable", { cause: gasEstimateFailure?.message ?? "unknown estimate failure" });
      }
      return Object.freeze({
        ...base,
        status: "success",
        return_data_sha256: sha256(normalizedHex(result?.data)),
        gas_estimate: BigInt(gasEstimate).toString(),
      });
    } catch (cause) {
      const revert = findExecutionRevert(cause);
      if (!revert) {
        throw new ServiceError(503, "guard_simulation_unavailable", "EVM simulation provider failed before returning a deterministic result", { cause: cause.message });
      }
      return Object.freeze({
        ...base,
        status: "revert",
        return_data_sha256: sha256(normalizedHex(revert.data ?? revert.raw)),
        ...(gasEstimate === undefined ? {} : { gas_estimate: BigInt(gasEstimate).toString() }),
      });
    }
  }

  async function verifyGuardPaymentTransaction({ transaction, authorization }) {
    if (config.chainId !== 8453) {
      throw new ServiceError(500, "guard_payment_network_invalid", "Guard payment recovery is restricted to Base mainnet");
    }
    if (typeof transaction !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(transaction)) {
      throw new ServiceError(400, "invalid_guard_payment_proof", "Payment transaction must be a Base transaction hash");
    }
    if (!authorization || typeof authorization !== "object") {
      throw new ServiceError(400, "invalid_guard_payment_proof", "Payment authorization evidence is missing");
    }
    let chainTransaction;
    let receipt;
    try {
      [chainTransaction, receipt] = await Promise.all([
        client.getTransaction({ hash: transaction }),
        client.getTransactionReceipt({ hash: transaction }),
      ]);
    } catch (cause) {
      throw new ServiceError(503, "guard_payment_proof_unavailable", "Unable to read the Base payment transaction and receipt", { cause: cause.message });
    }
    if (
      receipt.status !== "success"
      || receipt.transactionHash.toLowerCase() !== transaction.toLowerCase()
      || chainTransaction.hash.toLowerCase() !== transaction.toLowerCase()
      || chainTransaction.blockNumber === null
      || chainTransaction.blockHash === null
      || receipt.blockHash.toLowerCase() !== chainTransaction.blockHash.toLowerCase()
    ) {
      throw new ServiceError(409, "guard_payment_transaction_unconfirmed", "Payment transaction is not a successful confirmed Base transaction");
    }
    if (Number(chainTransaction.chainId) !== 8453 || !chainTransaction.to || !isAddressEqual(chainTransaction.to, config.usdcAddress)) {
      throw new ServiceError(409, "guard_payment_transaction_mismatch", "Payment transaction does not call canonical Base USDC on Base mainnet");
    }

    let parsedSignature;
    try {
      parsedSignature = parseSignature(authorization.signature);
    } catch (cause) {
      throw new ServiceError(400, "invalid_guard_payment_proof", "Payment authorization signature is malformed", { cause: cause.message });
    }
    const expectedCalldata = encodeFunctionData({
      abi: EIP3009_SETTLEMENT_ABI,
      functionName: "transferWithAuthorization",
      args: [
        getAddress(authorization.from),
        getAddress(authorization.to),
        BigInt(authorization.value),
        BigInt(authorization.validAfter),
        BigInt(authorization.validBefore),
        authorization.nonce,
        parsedSignature.v ?? parsedSignature.yParity,
        parsedSignature.r,
        parsedSignature.s,
      ],
    }).toLowerCase();
    const calldata = String(chainTransaction.input ?? "").toLowerCase();
    if (!calldata.startsWith(expectedCalldata)) {
      throw new ServiceError(409, "guard_payment_calldata_mismatch", "Payment transaction does not execute the settlement-bound EIP-3009 authorization");
    }

    const transfers = [];
    for (const log of receipt.logs ?? []) {
      if (!isAddressEqual(log.address, config.usdcAddress)) continue;
      try {
        const decoded = decodeEventLog({ abi: EIP3009_SETTLEMENT_ABI, eventName: "Transfer", data: log.data, topics: log.topics });
        transfers.push(decoded.args);
      } catch {
        // Ignore non-Transfer USDC events; the exact matching Transfer below is mandatory.
      }
    }
    const matching = transfers.filter(({ from, to, value }) => (
      isAddressEqual(from, authorization.from)
      && isAddressEqual(to, authorization.to)
      && BigInt(value) === BigInt(authorization.value)
    ));
    if (matching.length !== 1 || transfers.length !== 1) {
      throw new ServiceError(409, "guard_payment_transfer_mismatch", "Payment receipt does not contain exactly the settlement-bound Base USDC transfer");
    }
    return Object.freeze({
      chain_id: 8453,
      transaction: transaction.toLowerCase(),
      block_number: BigInt(receipt.blockNumber).toString(),
      block_hash: receipt.blockHash.toLowerCase(),
      payer: getAddress(authorization.from),
      recipient: getAddress(authorization.to),
      amount_atomic: BigInt(authorization.value).toString(),
    });
  }

  async function supplyState() {
    const [totalMinted, termsHash, blockNumber, mintPrice, paymentToken, salesPaused, termsUri] = await Promise.all([
      client.readContract({ address: config.contractAddress, abi: GOLDKEY_ABI, functionName: "totalMinted" }),
      client.readContract({ address: config.contractAddress, abi: GOLDKEY_ABI, functionName: "LICENSE_TERMS_HASH" }),
      client.getBlockNumber(),
      client.readContract({ address: config.contractAddress, abi: GOLDKEY_ABI, functionName: "MINT_PRICE" }),
      client.readContract({ address: config.contractAddress, abi: GOLDKEY_ABI, functionName: "USDC" }),
      client.readContract({ address: config.contractAddress, abi: GOLDKEY_ABI, functionName: "salesPaused" }),
      client.readContract({ address: config.contractAddress, abi: GOLDKEY_ABI, functionName: "licenseTermsURI" }),
    ]);
    return {
      totalMinted: BigInt(totalMinted).toString(),
      remaining: (MAX_SUPPLY - BigInt(totalMinted)).toString(),
      termsHash,
      blockNumber: BigInt(blockNumber).toString(),
      mintPriceAtomic: BigInt(mintPrice).toString(),
      paymentToken: getAddress(paymentToken),
      paymentTokenDecimals: 6,
      salesPaused: Boolean(salesPaused),
      termsUri,
    };
  }

  function purchaseTransactions(recipient, quantityInput) {
    const quantity = BigInt(quantityInput);
    if (quantity < 1n || quantity > 20n) throw new Error("quantity must be from 1 to 20 per mint transaction");
    const to = getAddress(recipient);
    const amount = MINT_PRICE_ATOMIC * quantity;
    return [
      {
        step: 1,
        purpose: "Approve exact USDC purchase amount",
        to: config.usdcAddress,
        value: "0",
        data: encodeFunctionData({ abi: ERC20_ABI, functionName: "approve", args: [config.contractAddress, amount] }),
        asset_amount_atomic: amount.toString(),
      },
      {
        step: 2,
        purpose: "Mint GoldKey pass",
        to: config.contractAddress,
        value: "0",
        data: encodeFunctionData({ abi: GOLDKEY_ABI, functionName: "mint", args: [to, quantity] }),
      },
    ];
  }

  function purchasePlanTransactions(recipient, totalQuantityInput) {
    let totalQuantity;
    try {
      totalQuantity = BigInt(totalQuantityInput);
    } catch {
      throw new Error("total quantity must be an integer");
    }
    if (totalQuantity < 1n || totalQuantity > MAX_SUPPLY) {
      throw new Error(`total quantity must be from 1 to ${MAX_SUPPLY}`);
    }
    const to = getAddress(recipient);
    const totalAmount = MINT_PRICE_ATOMIC * totalQuantity;
    const transactions = [
      {
        sequence: 1,
        batch_index: null,
        depends_on: [],
        purpose: "Approve the exact total USDC purchase amount",
        to: config.usdcAddress,
        value: "0",
        data: encodeFunctionData({
          abi: ERC20_ABI,
          functionName: "approve",
          args: [config.contractAddress, totalAmount],
        }),
        asset_amount_atomic: totalAmount.toString(),
      },
    ];
    let remaining = totalQuantity;
    let batchIndex = 1;
    while (remaining > 0n) {
      const quantity = remaining > 20n ? 20n : remaining;
      const sequence = transactions.length + 1;
      transactions.push({
        sequence,
        batch_index: batchIndex,
        depends_on: [sequence - 1],
        purpose: `Mint GoldKey batch ${batchIndex}`,
        to: config.contractAddress,
        value: "0",
        data: encodeFunctionData({ abi: GOLDKEY_ABI, functionName: "mint", args: [to, quantity] }),
        quantity: quantity.toString(),
      });
      remaining -= quantity;
      batchIndex += 1;
    }
    return transactions;
  }

  function renewalTransactions(tokenIdInput) {
    const tokenId = BigInt(canonicalTokenId(tokenIdInput));
    return [
      {
        step: 1,
        purpose: "Approve exact 50 USDC renewal amount",
        to: config.usdcAddress,
        value: "0",
        data: encodeFunctionData({ abi: ERC20_ABI, functionName: "approve", args: [config.contractAddress, MINT_PRICE_ATOMIC] }),
        asset_amount_atomic: MINT_PRICE_ATOMIC.toString(),
      },
      {
        step: 2,
        purpose: "Renew GoldKey term",
        to: config.contractAddress,
        value: "0",
        data: encodeFunctionData({ abi: GOLDKEY_ABI, functionName: "renew", args: [tokenId] }),
      },
    ];
  }

  return {
    client,
    passState,
    verifyWalletMessage,
    simulateGuardTransaction,
    verifyGuardPaymentTransaction,
    supplyState,
    validateDeployment,
    purchaseTransactions,
    purchasePlanTransactions,
    renewalTransactions,
  };
}
