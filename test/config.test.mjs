import assert from "node:assert/strict";
import test from "node:test";
import { loadConfig } from "../src/config.mjs";

const production = {
  nodeEnv: "production",
  publicOrigin: "https://api.goldkey.example",
  chainId: 8453,
  rpcUrl: "https://mainnet.base.org",
  x402FacilitatorUrl: "https://api.cdp.coinbase.com/platform/v2/x402",
  contractAddress: "0x0000000000000000000000000000000000000001",
  usdcAddress: "0x0000000000000000000000000000000000000002",
  treasuryAddress: "0x0000000000000000000000000000000000000003",
  databaseUrl: "postgresql://goldkey:secret@db.example/goldkey?sslmode=require",
  x402Enabled: false,
};

function withoutEnvironment(names, callback) {
  const previous = Object.fromEntries(names.map((name) => [name, process.env[name]]));
  for (const name of names) delete process.env[name];
  try {
    return callback();
  } finally {
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

test("production accepts an explicit HTTPS mainnet identity", () => {
  const config = loadConfig(production);
  assert.equal(config.chainId, 8453);
  assert.equal(config.rpcUrl, production.rpcUrl);
  assert.equal(config.x402FacilitatorUrl, production.x402FacilitatorUrl);
});

test("production requires explicit chain, RPC, facilitator, and addresses", () => {
  withoutEnvironment(["CHAIN_ID"], () => {
    const input = { ...production };
    delete input.chainId;
    assert.throws(() => loadConfig(input), /CHAIN_ID must be explicitly configured/);
  });
});

test("production rejects Base Sepolia and the testnet-only x402.org facilitator", () => {
  assert.throws(() => loadConfig({ ...production, chainId: 84532 }), /Base Sepolia/);
  assert.throws(
    () => loadConfig({ ...production, x402Enabled: true, x402FacilitatorUrl: "https://x402.org/facilitator" }),
    /testnet-only/,
  );
});

test("production requires HTTPS RPC and facilitator transport", () => {
  assert.throws(() => loadConfig({ ...production, rpcUrl: "http://mainnet.base.org" }), /RPC_URL must use https/);
  assert.throws(
    () => loadConfig({ ...production, x402Enabled: true, x402FacilitatorUrl: "http://facilitator.example" }),
    /X402_FACILITATOR_URL must use https/,
  );
});

test("production permits explicit single-instance SQLite but rejects an implicit database", () => {
  const sqlite = { ...production, databasePath: "/app/data/goldkey.sqlite" };
  delete sqlite.databaseUrl;
  assert.equal(loadConfig(sqlite).databasePath, "/app/data/goldkey.sqlite");

  const missing = { ...production };
  delete missing.databaseUrl;
  assert.throws(() => loadConfig(missing), /DATABASE_URL or DATABASE_PATH/);
});

test("production Postgres requires transport encryption", () => {
  assert.throws(
    () => loadConfig({ ...production, databaseUrl: "postgresql://goldkey:secret@db.example/goldkey" }),
    /must require TLS/,
  );
});

test("Guard is disabled by default and exposes fixed premium prices", () => {
  const config = loadConfig(production);
  assert.equal(config.guardEnabled, false);
  assert.equal(config.guardNetworkPriceUsd, "0.05");
  assert.equal(config.guardEvmPriceUsd, "0.10");
  assert.equal(config.guardAuthorizationTtlMs, 60_000);
});

test("production Guard fails closed without a receipt signing key pair", () => {
  assert.throws(
    () => loadConfig({ ...production, guardEnabled: true, x402Enabled: true }),
    /GUARD_RECEIPT_KEY_ID must be explicitly configured/,
  );
  assert.throws(
    () => loadConfig({ ...production, guardEnabled: true, x402Enabled: true, guardReceiptKeyId: "guard-2026-01" }),
    /GUARD_RECEIPT_PRIVATE_KEY must be explicitly configured/,
  );
  const config = loadConfig({
    ...production,
    guardEnabled: true,
    x402Enabled: true,
    x402AuthHeaders: { authorization: "test-only" },
    guardReceiptKeyId: "guard-2026-01",
    guardReceiptPrivateKey: "test-pkcs8-base64",
    guardAllowedOperatorWallets: ["0x0000000000000000000000000000000000000004"],
  });
  assert.equal(config.guardEnabled, true);
  assert.equal(config.guardReceiptKeyId, "guard-2026-01");
  assert.deepEqual(config.guardAllowedOperatorWallets, ["0x0000000000000000000000000000000000000004"]);
});

test("Guard beta requires a bounded unique operator allowlist", () => {
  assert.throws(
    () => loadConfig({
      ...production,
      guardEnabled: true,
      x402Enabled: true,
      x402AuthHeaders: { authorization: "test-only" },
      guardReceiptKeyId: "guard-2026-01",
      guardReceiptPrivateKey: "test-pkcs8-base64",
    }),
    /GUARD_ALLOWED_OPERATOR_WALLETS/,
  );
  assert.throws(
    () => loadConfig({
      ...production,
      guardEnabled: true,
      x402Enabled: true,
      guardAllowedOperatorWallets: ["0x0000000000000000000000000000000000000004", "0x0000000000000000000000000000000000000004"],
      x402AuthHeaders: { authorization: "test-only" },
      guardReceiptKeyId: "guard-2026-01",
      guardReceiptPrivateKey: "test-pkcs8-base64",
    }),
    /duplicates/,
  );
});

test("Guard signing key settings must be paired and single-line", () => {
  assert.throws(
    () => loadConfig({ ...production, guardReceiptPrivateKey: "test-pkcs8-base64" }),
    /must be set together/,
  );
  assert.throws(
    () => loadConfig({ ...production, guardReceiptKeyId: "bad\nkey", guardReceiptPrivateKey: "test" }),
    /single-line/,
  );
});

test("Guard receipt rotation accepts public verification keys and rejects private JWK material", () => {
  const previous = { kty: "OKP", crv: "Ed25519", x: "A".repeat(43), kid: "guard-old", use: "sig", alg: "EdDSA", key_ops: ["verify"] };
  const config = loadConfig({ ...production, guardReceiptPreviousPublicKeys: [previous] });
  assert.deepEqual(config.guardReceiptPreviousPublicKeys, [previous]);
  assert.throws(
    () => loadConfig({ ...production, guardReceiptPreviousPublicKeys: [{ ...previous, d: "private" }] }),
    /public-only JWKs/,
  );
  assert.throws(
    () => loadConfig({ ...production, guardReceiptPreviousPublicKeys: "not-json" }),
    /must be valid JSON/,
  );
});

test("Guard cannot be enabled without paid x402 authorization", () => {
  assert.throws(
    () => loadConfig({ ...production, guardEnabled: true, x402Enabled: false }),
    /requires X402_ENABLED/,
  );
});
