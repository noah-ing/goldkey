import assert from "node:assert/strict";
import { createCipheriv, pbkdf2Sync, randomBytes } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { keccak256 } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { normalizeBaseWalletConfig } from "../src/adapters/base-wallet-config.mjs";
import {
  createBaseWalletConnectorBindings,
  createExactBaseBroadcaster,
  loadBaseWalletSigner,
} from "../src/adapters/base-wallet-signer.mjs";

const PRIVATE_KEY = "0x" + "11".repeat(32);
const ACCOUNT = privateKeyToAccount(PRIVATE_KEY);
const TO = "0x220FE98C77CE79baa00d47C5896BE05C2A7D3db0";
const OTHER = "0xd6b7E00FcD46966676F554fE0455BfF739e85b1b";

function config(executionSigner = { type: "env", key_env: "EXECUTION_KEY" }) {
  return normalizeBaseWalletConfig({
    schema: "goldkey.base-wallet-config.v1",
    rpc_url_env: "BASE_RPC_URL",
    execution_signer: executionSigner,
    connectors: [{
      id: "base-wallet",
      chain_id: 8453,
      from: ACCOUNT.address,
      max_gas_limit: "50000",
      max_fee_per_gas_atomic: "20",
      max_priority_fee_per_gas_atomic: "2",
      max_estimated_network_fee_atomic: "1000000",
      max_wallet_native_exposure_atomic: "2000000",
      operations: [{ kind: "native_transfer", recipients: [TO], max_amount_atomic: "100" }],
    }],
  }, { baseDirectory: "/operator", filename: "/operator/wallet.json" });
}

function transaction(overrides = {}) {
  return Object.freeze({
    chain_id: 8453,
    from: ACCOUNT.address,
    to: TO,
    value_atomic: "1",
    data: "0x",
    nonce: "3",
    gas_limit: "30000",
    max_fee_per_gas_atomic: "20",
    max_priority_fee_per_gas_atomic: "2",
    type: "eip1559",
    access_list: Object.freeze([]),
    ...overrides,
  });
}

function web3Keystore(privateKey, password) {
  const salt = randomBytes(32);
  const iv = randomBytes(16);
  const iterations = 10_000;
  const derived = pbkdf2Sync(Buffer.from(password, "utf8"), salt, iterations, 32, "sha256");
  const cipher = createCipheriv("aes-128-ctr", derived.subarray(0, 16), iv);
  const plaintext = Buffer.from(privateKey.slice(2), "hex");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const mac = keccak256(Buffer.concat([derived.subarray(16, 32), ciphertext])).slice(2);
  plaintext.fill(0);
  derived.fill(0);
  return {
    version: 3,
    address: ACCOUNT.address.slice(2).toLowerCase(),
    crypto: {
      cipher: "aes-128-ctr",
      ciphertext: ciphertext.toString("hex"),
      cipherparams: { iv: iv.toString("hex") },
      kdf: "pbkdf2",
      kdfparams: { dklen: 32, c: iterations, prf: "hmac-sha256", salt: salt.toString("hex") },
      mac,
    },
  };
}

test("environment signer loads locally, clears the secret, and caches only the account", async () => {
  const env = { EXECUTION_KEY: PRIVATE_KEY };
  const cache = new Map();
  const reference = config().execution_signer;
  const first = await loadBaseWalletSigner(reference, { env, cache });
  assert.equal(first.address, ACCOUNT.address);
  assert.equal(env.EXECUTION_KEY, undefined);
  const second = await loadBaseWalletSigner(reference, { env, cache });
  assert.equal(second, first);
  assert.equal([...cache.values()][0].address, ACCOUNT.address);
});

test("private Web3 v3 keystore decrypts with an environment password and clears it", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-wallet-keystore-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filename = path.join(directory, "execution.json");
  const password = "correct horse battery staple";
  await writeFile(filename, JSON.stringify(web3Keystore(PRIVATE_KEY, password)), { mode: 0o600 });
  const reference = {
    type: "keystore",
    path: filename,
    password_env: "KEYSTORE_PASSWORD",
    clear_env_after_load: true,
  };
  const env = { KEYSTORE_PASSWORD: password };
  const account = await loadBaseWalletSigner(reference, { env });
  assert.equal(account.address, ACCOUNT.address);
  assert.equal(env.KEYSTORE_PASSWORD, undefined);

  await assert.rejects(
    () => loadBaseWalletSigner(reference, { env: { KEYSTORE_PASSWORD: "wrong" } }),
    (error) => error.code === "local_state_error" && /password or MAC/.test(error.message),
  );
});

test("exact broadcaster verifies signed fields and broadcasts exactly the checked bytes", async () => {
  const sent = [];
  const publicClient = {
    sendRawTransaction: async ({ serializedTransaction }) => {
      sent.push(serializedTransaction);
      return keccak256(serializedTransaction);
    },
  };
  const broadcaster = createExactBaseBroadcaster({ account: ACCOUNT, publicClient });
  const result = await broadcaster({ transaction: transaction(), signal: new AbortController().signal, deadlineAt: Date.now() + 10_000 });
  assert.equal(sent.length, 1);
  assert.equal(result.transactionHash, keccak256(sent[0]));
  assert.match(result.transactionSha256, /^[0-9a-f]{64}$/);
});

test("mutating signer output is rejected before any raw transaction broadcast", async () => {
  let broadcasts = 0;
  const mutatingAccount = {
    address: ACCOUNT.address,
    signTransaction: async (value) => ACCOUNT.signTransaction({ ...value, to: OTHER }),
  };
  const broadcaster = createExactBaseBroadcaster({
    account: mutatingAccount,
    publicClient: { sendRawTransaction: async () => { broadcasts += 1; return "0x" + "ab".repeat(32); } },
  });
  await assert.rejects(
    () => broadcaster({ transaction: transaction(), signal: new AbortController().signal, deadlineAt: Date.now() + 10_000 }),
    (error) => error.code === "local_state_error" && /mutated/.test(error.message),
  );
  assert.equal(broadcasts, 0);
});

test("deadline expiry after signing still prevents broadcast", async () => {
  let now = 1;
  let signed = 0;
  let broadcasts = 0;
  const delayedAccount = {
    address: ACCOUNT.address,
    signTransaction: async (value) => {
      signed += 1;
      const serialized = await ACCOUNT.signTransaction(value);
      now = 100;
      return serialized;
    },
  };
  const broadcaster = createExactBaseBroadcaster({
    account: delayedAccount,
    publicClient: { sendRawTransaction: async () => { broadcasts += 1; return "0x" + "ab".repeat(32); } },
    clock: () => now,
  });
  await assert.rejects(
    () => broadcaster({ transaction: transaction(), signal: new AbortController().signal, deadlineAt: 50 }),
    (error) => error.code === "deadline_exceeded",
  );
  assert.equal(signed, 1);
  assert.equal(broadcasts, 0);
});

test("connector binding refuses the wrong chain/sender and exposes callbacks, not the account", async () => {
  let broadcasts = 0;
  await assert.rejects(
    () => createBaseWalletConnectorBindings({
      config: config(),
      account: ACCOUNT,
      publicClient: { getChainId: async () => 84532 },
    }),
    (error) => error.code === "local_state_error" && /8453/.test(error.message),
  );

  const wrongSenderRaw = {
    ...config(),
    connectors: config().connectors.map((entry) => ({ ...entry, from: OTHER })),
  };
  await assert.rejects(
    () => createBaseWalletConnectorBindings({
      config: wrongSenderRaw,
      account: ACCOUNT,
      publicClient: { getChainId: async () => 8453 },
    }),
    (error) => error.code === "local_state_error" && /sender/.test(error.message),
  );

  const publicClient = {
    getChainId: async () => 8453,
    getBlock: async () => ({ number: 10n, hash: "0x" + "ab".repeat(32) }),
    getTransactionCount: async () => 3,
    getBalance: async () => 1500000n,
    readContract: async ({ functionName }) => functionName === "getOperatorFee" ? 4n : 5n,
    sendRawTransaction: async ({ serializedTransaction }) => { broadcasts += 1; return keccak256(serializedTransaction); },
  };
  const bindings = await createBaseWalletConnectorBindings({ config: config(), account: ACCOUNT, publicClient });
  assert.deepEqual(Object.keys(bindings).sort(), ["connectors", "publicClient"]);
  assert.equal(bindings.connectors[0].max_estimated_network_fee_atomic, "1000000");
  assert.equal(bindings.connectors[0].max_wallet_native_exposure_atomic, "2000000");
  assert.equal(typeof bindings.connectors[0].recheckFeeExposure, "function");
  assert.equal(typeof bindings.connectors[0].signAndBroadcast, "function");
  await assert.rejects(
    () => bindings.connectors[0].signAndBroadcast({
      transaction: transaction({ data: "0xdeadbeef", value_atomic: "0" }),
      signal: new AbortController().signal,
      deadlineAt: Date.now() + 10_000,
    }),
    (error) => error.code === "invalid_input" && /ERC-20/.test(error.message),
  );
  await assert.rejects(
    () => bindings.connectors[0].signAndBroadcast({
      transaction: transaction({ value_atomic: "101" }),
      signal: new AbortController().signal,
      deadlineAt: Date.now() + 10_000,
    }),
    (error) => error.code === "invalid_input" && /amount cap/.test(error.message),
  );
  assert.equal(broadcasts, 0);
});
