import {
  decodeFunctionResult,
  encodeFunctionData,
  getAddress,
  isAddressEqual,
} from "viem";
import { EdgeError, assert } from "./errors.mjs";

export const MINT_PRICE_ATOMIC = 50_000_000n;
export const MAX_SUPPLY = 10_000n;
export const CALLS_PER_TERM = 10_000n;
export const SERVICE_TERM_SECONDS = 365n * 86_400n;

export const GOLDKEY_ABI = [
  { type: "function", name: "accessState", stateMutability: "view", inputs: [{ name: "tokenId", type: "uint256" }], outputs: [{ name: "owner", type: "address" }, { name: "term", type: "uint256" }, { name: "expiresAt", type: "uint256" }, { name: "epoch", type: "uint256" }, { name: "active", type: "bool" }] },
  { type: "function", name: "totalMinted", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
  { type: "function", name: "LICENSE_TERMS_HASH", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bytes32" }] },
  { type: "function", name: "MINT_PRICE", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
  { type: "function", name: "USDC", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "address" }] },
  { type: "function", name: "treasury", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "address" }] },
  { type: "function", name: "MAX_SUPPLY", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
  { type: "function", name: "CALLS_PER_TERM", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
  { type: "function", name: "SERVICE_TERM_SECONDS", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
  { type: "function", name: "salesPaused", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "licenseTermsURI", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "string" }] },
  { type: "function", name: "mint", stateMutability: "nonpayable", inputs: [{ name: "recipient", type: "address" }, { name: "quantity", type: "uint256" }], outputs: [{ name: "firstTokenId", type: "uint256" }] },
  { type: "function", name: "renew", stateMutability: "nonpayable", inputs: [{ name: "tokenId", type: "uint256" }], outputs: [{ name: "newTerm", type: "uint256" }, { name: "expiresAt", type: "uint256" }] },
];

export const ERC20_ABI = [
  { type: "function", name: "decimals", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint8" }] },
  { type: "function", name: "approve", stateMutability: "nonpayable", inputs: [{ name: "spender", type: "address" }, { name: "amount", type: "uint256" }], outputs: [{ name: "", type: "bool" }] },
];

function canonicalTokenId(value) {
  const text = String(value);
  assert(/^[1-9]\d*$/.test(text), 400, "invalid_token_id", "tokenId must be a canonical positive integer string");
  const tokenId = BigInt(text);
  assert(tokenId <= (1n << 256n) - 1n, 400, "invalid_token_id", "tokenId is outside uint256 range");
  return text;
}

function ethCall(address, functionName, args = [], abi = GOLDKEY_ABI) {
  return {
    method: "eth_call",
    params: [{ to: address, data: encodeFunctionData({ abi, functionName, args }) }, "latest"],
    decode: (result) => decodeFunctionResult({ abi, functionName, data: result }),
  };
}

function plainCall(method, params = [], decode = (value) => value) {
  return { method, params, decode };
}

export function createChainClient(config, fetchImpl = fetch) {
  async function rpcBatch(calls) {
    const body = calls.map(({ method, params }, index) => ({ jsonrpc: "2.0", id: index + 1, method, params }));
    let response;
    try {
      response = await fetchImpl(config.rpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify(body),
      });
    } catch {
      throw new EdgeError(503, "rpc_unavailable", "Base RPC is unavailable");
    }
    assert(response.ok, 503, "rpc_unavailable", `Base RPC returned HTTP ${response.status}`);
    let payload;
    try {
      payload = await response.json();
    } catch {
      throw new EdgeError(503, "rpc_invalid_response", "Base RPC returned invalid JSON");
    }
    assert(Array.isArray(payload), 503, "rpc_invalid_response", "Base RPC did not return a batch response");
    const byId = new Map(payload.map((item) => [Number(item?.id), item]));
    return calls.map((call, index) => {
      const item = byId.get(index + 1);
      assert(item, 503, "rpc_invalid_response", "Base RPC omitted a batch item");
      assert(!item.error, 503, "rpc_call_failed", "A required onchain read failed", { rpc_code: item.error?.code });
      try {
        return call.decode(item.result);
      } catch {
        throw new EdgeError(503, "rpc_invalid_response", "A required onchain value could not be decoded");
      }
    });
  }

  async function supplyState() {
    const calls = [
      plainCall("eth_chainId", [], (value) => Number(BigInt(value))),
      plainCall("eth_blockNumber", [], (value) => BigInt(value)),
      plainCall("eth_getCode", [config.contractAddress, "latest"]),
      plainCall("eth_getCode", [config.usdcAddress, "latest"]),
      ethCall(config.contractAddress, "totalMinted"),
      ethCall(config.contractAddress, "LICENSE_TERMS_HASH"),
      ethCall(config.contractAddress, "MINT_PRICE"),
      ethCall(config.contractAddress, "USDC"),
      ethCall(config.contractAddress, "treasury"),
      ethCall(config.contractAddress, "MAX_SUPPLY"),
      ethCall(config.contractAddress, "CALLS_PER_TERM"),
      ethCall(config.contractAddress, "SERVICE_TERM_SECONDS"),
      ethCall(config.contractAddress, "salesPaused"),
      ethCall(config.contractAddress, "licenseTermsURI"),
      ethCall(config.usdcAddress, "decimals", [], ERC20_ABI),
    ];
    const [
      chainId,
      blockNumber,
      contractCode,
      usdcCode,
      totalMinted,
      termsHash,
      mintPrice,
      paymentToken,
      treasury,
      maxSupply,
      callsPerTerm,
      serviceTermSeconds,
      salesPaused,
      termsUri,
      decimals,
    ] = await rpcBatch(calls);

    const mismatches = [];
    if (chainId !== config.chainId) mismatches.push(`chain_id=${chainId}`);
    if (!contractCode || contractCode === "0x") mismatches.push("contract_code_missing");
    if (!usdcCode || usdcCode === "0x") mismatches.push("usdc_code_missing");
    if (!isAddressEqual(getAddress(paymentToken), config.usdcAddress)) mismatches.push(`usdc=${paymentToken}`);
    if (!isAddressEqual(getAddress(treasury), config.treasuryAddress)) mismatches.push(`treasury=${treasury}`);
    if (BigInt(mintPrice) !== MINT_PRICE_ATOMIC) mismatches.push(`mint_price=${mintPrice}`);
    if (BigInt(maxSupply) !== MAX_SUPPLY) mismatches.push(`max_supply=${maxSupply}`);
    if (BigInt(callsPerTerm) !== CALLS_PER_TERM) mismatches.push(`calls_per_term=${callsPerTerm}`);
    if (BigInt(serviceTermSeconds) !== SERVICE_TERM_SECONDS) mismatches.push(`term_seconds=${serviceTermSeconds}`);
    if (String(termsHash).toLowerCase() !== config.expectedTermsHash) mismatches.push(`terms_hash=${termsHash}`);
    if (Number(decimals) !== 6) mismatches.push(`usdc_decimals=${decimals}`);
    if (BigInt(totalMinted) > MAX_SUPPLY) mismatches.push(`total_minted=${totalMinted}`);
    assert(mismatches.length === 0, 503, "deployment_identity_mismatch", "GoldKey onchain identity does not match edge configuration", { mismatches });

    return {
      status: "live",
      totalMinted: BigInt(totalMinted).toString(),
      remaining: (MAX_SUPPLY - BigInt(totalMinted)).toString(),
      termsHash: String(termsHash),
      termsUri: String(termsUri),
      blockNumber: blockNumber.toString(),
      mintPriceAtomic: BigInt(mintPrice).toString(),
      paymentToken: getAddress(paymentToken),
      paymentTokenDecimals: Number(decimals),
      salesPaused: Boolean(salesPaused),
    };
  }

  async function passState(tokenIdInput) {
    const tokenId = canonicalTokenId(tokenIdInput);
    const [state] = await rpcBatch([ethCall(config.contractAddress, "accessState", [BigInt(tokenId)])]);
    const [owner, term, expiresAt, ownershipEpoch, active] = state;
    const expirySeconds = BigInt(expiresAt);
    assert(expirySeconds <= 8_640_000_000_000n, 503, "rpc_invalid_response", "Onchain expiration is outside the supported date range");
    return {
      tokenId,
      owner: getAddress(owner),
      term: BigInt(term).toString(),
      ownershipEpoch: BigInt(ownershipEpoch).toString(),
      expiresAt: Number(expirySeconds) * 1000,
      active: Boolean(active),
    };
  }

  function purchasePlanTransactions(recipient, totalQuantityInput) {
    const totalQuantity = BigInt(totalQuantityInput);
    assert(totalQuantity >= 1n && totalQuantity <= MAX_SUPPLY, 400, "invalid_quantity", `total quantity must be from 1 to ${MAX_SUPPLY}`);
    const to = getAddress(recipient);
    const totalAmount = MINT_PRICE_ATOMIC * totalQuantity;
    const transactions = [{
      sequence: 1,
      batch_index: null,
      depends_on: [],
      purpose: "Approve the exact total USDC purchase amount",
      to: config.usdcAddress,
      value: "0",
      data: encodeFunctionData({ abi: ERC20_ABI, functionName: "approve", args: [config.contractAddress, totalAmount] }),
      asset_amount_atomic: totalAmount.toString(),
    }];
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

  return { supplyState, passState, purchasePlanTransactions, renewalTransactions };
}
