import { createDecipheriv, pbkdf2 as pbkdf2Callback, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import {
  createPublicClient,
  getAddress,
  http,
  isAddress,
  keccak256,
  parseTransaction,
  recoverTransactionAddress,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";
import { canonicalSha256 } from "../canonical.mjs";
import { DeadlineExceededError, InvalidInputError, LocalStateError } from "../errors.mjs";
import { createBaseFeeExposureRecheck } from "../evm-fee-recheck.mjs";
import { BASE_MAINNET_CHAIN_ID, readOperatorJsonFile, resolveBaseRpcUrl } from "./base-wallet-config.mjs";
import { assertBaseWalletTransactionAllowed } from "./base-wallet-request.mjs";

const scrypt = promisify(scryptCallback);
const pbkdf2 = promisify(pbkdf2Callback);
const PRIVATE_KEY = /^0x[0-9a-fA-F]{64}$/;
const HEX_BYTES = /^[0-9a-fA-F]+$/;
const HASH = /^0x[0-9a-f]{64}$/;
const MAX_SCRYPT_MEMORY = 512 * 1024 * 1024;

function hexBytes(value, name, { exactBytes, maximumBytes = 1024 * 1024 } = {}) {
  if (typeof value !== "string" || value.length % 2 !== 0 || !HEX_BYTES.test(value)) throw new LocalStateError(`${name} must be even-length hexadecimal`);
  const bytes = Buffer.from(value, "hex");
  if ((exactBytes !== undefined && bytes.byteLength !== exactBytes) || bytes.byteLength > maximumBytes) throw new LocalStateError(`${name} has an invalid byte length`);
  return bytes;
}

function positiveInteger(value, name, maximum) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) throw new LocalStateError(`${name} is outside the supported safety bounds`);
  return value;
}

async function deriveKeystoreKey(crypto, password) {
  const params = crypto.kdfparams;
  if (!params || typeof params !== "object" || Array.isArray(params)) throw new LocalStateError("Keystore kdfparams are missing");
  const dklen = positiveInteger(params.dklen, "Keystore dklen", 64);
  if (dklen !== 32) throw new LocalStateError("Keystore dklen must be 32");
  const salt = hexBytes(params.salt, "Keystore salt", { maximumBytes: 1024 });
  if (crypto.kdf === "scrypt") {
    const N = positiveInteger(params.n, "Keystore scrypt n", 1 << 20);
    const r = positiveInteger(params.r, "Keystore scrypt r", 32);
    const p = positiveInteger(params.p, "Keystore scrypt p", 16);
    if ((N & (N - 1)) !== 0 || N < 1024) throw new LocalStateError("Keystore scrypt n must be a power of two of at least 1024");
    const requiredMemory = 128 * N * r;
    if (!Number.isSafeInteger(requiredMemory) || requiredMemory > MAX_SCRYPT_MEMORY) throw new LocalStateError("Keystore scrypt memory cost exceeds the local safety ceiling");
    return Buffer.from(await scrypt(Buffer.from(password, "utf8"), salt, dklen, {
      N,
      r,
      p,
      maxmem: Math.min(MAX_SCRYPT_MEMORY, Math.max(32 * 1024 * 1024, requiredMemory + 16 * 1024 * 1024)),
    }));
  }
  if (crypto.kdf === "pbkdf2") {
    const iterations = positiveInteger(params.c, "Keystore PBKDF2 iterations", 10_000_000);
    if (iterations < 10_000 || params.prf !== "hmac-sha256") throw new LocalStateError("Keystore PBKDF2 requires at least 10000 HMAC-SHA256 iterations");
    return Buffer.from(await pbkdf2(Buffer.from(password, "utf8"), salt, iterations, dklen, "sha256"));
  }
  throw new LocalStateError("Keystore kdf must be scrypt or pbkdf2-hmac-sha256");
}

async function decryptV3Keystore(document, password) {
  if (!document || typeof document !== "object" || Array.isArray(document) || document.version !== 3) throw new LocalStateError("Keystore must use Web3 Secret Storage version 3");
  const crypto = document.crypto ?? document.Crypto;
  if (!crypto || typeof crypto !== "object" || Array.isArray(crypto)) throw new LocalStateError("Keystore crypto section is missing");
  if (crypto.cipher !== "aes-128-ctr") throw new LocalStateError("Keystore cipher must be aes-128-ctr");
  const ciphertext = hexBytes(crypto.ciphertext, "Keystore ciphertext", { exactBytes: 32 });
  const iv = hexBytes(crypto.cipherparams?.iv, "Keystore IV", { exactBytes: 16 });
  const expectedMac = hexBytes(crypto.mac, "Keystore MAC", { exactBytes: 32 });
  const derivedKey = await deriveKeystoreKey(crypto, password);
  let privateKey;
  try {
    const actualMac = Buffer.from(keccak256(Buffer.concat([derivedKey.subarray(16, 32), ciphertext])).slice(2), "hex");
    if (!timingSafeEqual(actualMac, expectedMac)) throw new LocalStateError("Keystore password or MAC is invalid");
    const decipher = createDecipheriv("aes-128-ctr", derivedKey.subarray(0, 16), iv);
    privateKey = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (privateKey.byteLength !== 32) throw new LocalStateError("Keystore decrypted an invalid private-key length");
    const account = privateKeyToAccount(`0x${privateKey.toString("hex")}`);
    if (document.address !== undefined) {
      const addressValue = String(document.address).startsWith("0x") ? String(document.address) : `0x${document.address}`;
      if (!isAddress(addressValue) || getAddress(addressValue) !== account.address) throw new LocalStateError("Keystore address does not match its decrypted private key");
    }
    return account;
  } finally {
    derivedKey.fill(0);
    privateKey?.fill(0);
  }
}

function signerCacheKey(reference) {
  return reference.type === "env" ? `env:${reference.key_env}` : `keystore:${reference.path}:${reference.password_env}`;
}

export async function loadBaseWalletSigner(reference, { env = process.env, cache = new Map() } = {}) {
  const key = signerCacheKey(reference);
  if (cache.has(key)) return cache.get(key);
  let account;
  if (reference.type === "env") {
    const privateKey = env?.[reference.key_env];
    if (typeof privateKey !== "string" || !PRIVATE_KEY.test(privateKey)) throw new LocalStateError(`Signer environment variable ${reference.key_env} must contain one 32-byte 0x private key`);
    try {
      account = privateKeyToAccount(privateKey);
    } finally {
      if (reference.clear_env_after_load) delete env[reference.key_env];
    }
  } else if (reference.type === "keystore") {
    const password = env?.[reference.password_env];
    if (typeof password !== "string" || password.length < 1 || Buffer.byteLength(password, "utf8") > 1024) throw new LocalStateError(`Missing bounded keystore password in ${reference.password_env}`);
    try {
      const document = await readOperatorJsonFile(reference.path, { name: "execution keystore", maximumBytes: 1024 * 1024, requirePrivate: true });
      account = await decryptV3Keystore(document, password);
    } finally {
      if (reference.clear_env_after_load) delete env[reference.password_env];
    }
  } else {
    throw new InvalidInputError("Unsupported execution signer reference");
  }
  if (!account || !isAddress(account.address) || typeof account.signTransaction !== "function" || typeof account.signTypedData !== "function") {
    throw new LocalStateError("Loaded signer is not a local viem account");
  }
  cache.set(key, account);
  return account;
}

function assertNotAborted(signal, deadlineAt, clock) {
  if (signal?.aborted || (Number.isFinite(deadlineAt) && clock() >= deadlineAt)) throw new DeadlineExceededError("Base wallet signing deadline expired");
}

function sameOptionalAddress(actual, expected) {
  return actual === expected || (isAddress(actual) && isAddress(expected) && getAddress(actual) === getAddress(expected));
}

async function verifyExactSignedTransaction(serializedTransaction, transaction, account) {
  if (typeof serializedTransaction !== "string" || !/^0x[0-9a-fA-F]+$/.test(serializedTransaction) || serializedTransaction.length > 512 * 1024) {
    throw new LocalStateError("Execution signer returned an invalid serialized transaction");
  }
  let parsed;
  let recovered;
  try {
    parsed = parseTransaction(serializedTransaction);
    recovered = await recoverTransactionAddress({ serializedTransaction });
  } catch (cause) {
    throw new LocalStateError("Execution signer returned an undecodable transaction", { cause });
  }
  const accessList = parsed.accessList ?? [];
  if (
    parsed.type !== "eip1559"
    || parsed.chainId !== transaction.chain_id
    || BigInt(parsed.nonce) !== BigInt(transaction.nonce)
    || BigInt(parsed.gas) !== BigInt(transaction.gas_limit)
    || BigInt(parsed.maxFeePerGas) !== BigInt(transaction.max_fee_per_gas_atomic)
    || BigInt(parsed.maxPriorityFeePerGas) !== BigInt(transaction.max_priority_fee_per_gas_atomic)
    || !sameOptionalAddress(parsed.to, transaction.to)
    || BigInt(parsed.value) !== BigInt(transaction.value_atomic)
    || (parsed.data ?? "0x").toLowerCase() !== transaction.data
    || !Array.isArray(accessList)
    || accessList.length !== 0
    || getAddress(recovered) !== getAddress(account.address)
    || getAddress(recovered) !== transaction.from
  ) throw new LocalStateError("Execution signer mutated the authorized transaction; broadcast refused");
  return serializedTransaction.toLowerCase();
}

export function createExactBaseBroadcaster({ account, publicClient, clock = () => Date.now() } = {}) {
  if (!account || !isAddress(account.address) || typeof account.signTransaction !== "function") throw new InvalidInputError("A local execution account with signTransaction is required");
  if (!publicClient || typeof publicClient.sendRawTransaction !== "function") throw new InvalidInputError("A Base public client with sendRawTransaction is required");
  return async function signAndBroadcast({ transaction, signal, deadlineAt }) {
    if (transaction.chain_id !== BASE_MAINNET_CHAIN_ID || transaction.from !== getAddress(account.address)) throw new LocalStateError("Authorized transaction does not match the local Base signer");
    assertNotAborted(signal, deadlineAt, clock);
    const serialized = await account.signTransaction({
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
    const exactSerialized = await verifyExactSignedTransaction(serialized, transaction, account);
    assertNotAborted(signal, deadlineAt, clock);
    const expectedHash = keccak256(exactSerialized).toLowerCase();
    const returnedHash = await publicClient.sendRawTransaction({ serializedTransaction: exactSerialized });
    if (typeof returnedHash !== "string" || !HASH.test(returnedHash.toLowerCase()) || returnedHash.toLowerCase() !== expectedHash) {
      throw new LocalStateError("Base RPC returned a transaction hash inconsistent with the exact signed bytes");
    }
    return Object.freeze({ transactionHash: expectedHash, transactionSha256: canonicalSha256(transaction) });
  };
}

export function createBaseWalletPublicClient({ config, env = process.env } = {}) {
  const rpcUrl = resolveBaseRpcUrl(config, env);
  return createPublicClient({
    chain: base,
    transport: http(rpcUrl, { retryCount: 0, timeout: 10_000 }),
  });
}

export async function createBaseWalletConnectorBindings({ config, env = process.env, publicClient, account, clock } = {}) {
  const client = publicClient ?? createBaseWalletPublicClient({ config, env });
  if (typeof client.getChainId !== "function" || await client.getChainId() !== BASE_MAINNET_CHAIN_ID) throw new LocalStateError("Operator RPC is not Base mainnet chain 8453");
  const signer = account ?? await loadBaseWalletSigner(config.execution_signer, { env });
  for (const connector of config.connectors) {
    if (connector.from !== getAddress(signer.address)) throw new LocalStateError(`Connector ${connector.id} sender does not match the loaded execution signer`);
  }
  const recheckFeeExposure = createBaseFeeExposureRecheck({ client });
  const broadcastExact = createExactBaseBroadcaster({ account: signer, publicClient: client, ...(clock ? { clock } : {}) });
  const connectors = config.connectors.map((connector) => Object.freeze({
    id: connector.id,
    kind: "evm_transaction",
    chain_id: connector.chain_id,
    from: connector.from,
    max_estimated_network_fee_atomic: connector.max_estimated_network_fee_atomic,
    max_wallet_native_exposure_atomic: connector.max_wallet_native_exposure_atomic,
    recheckFeeExposure,
    signAndBroadcast: async (input) => {
      assertBaseWalletTransactionAllowed({ connector, transaction: input?.transaction });
      return broadcastExact(input);
    },
  }));
  return Object.freeze({
    publicClient: client,
    connectors: Object.freeze(connectors),
  });
}
