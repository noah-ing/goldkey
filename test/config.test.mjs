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
