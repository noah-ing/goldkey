import {
  createPublicClient,
  defineChain,
  encodeFunctionData,
  getAddress,
  http,
  isAddressEqual,
} from "viem";
import {
  CALLS_PER_TERM,
  ERC20_ABI,
  GOLDKEY_ABI,
  MAX_SUPPLY,
  MINT_PRICE_ATOMIC,
} from "./contract.mjs";

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
    supplyState,
    validateDeployment,
    purchaseTransactions,
    purchasePlanTransactions,
    renewalTransactions,
  };
}
