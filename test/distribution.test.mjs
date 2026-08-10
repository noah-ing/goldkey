import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  RELEASE_IDENTITY_SOURCE,
  resolveRuntimeConfig,
  run,
  runCli,
  validateIdentityPayload,
  validateReleaseIdentity,
} from "../distribution/goldkey-agent-utilities/scripts/goldkey-client.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const skillPath = resolve(here, "../distribution/goldkey-agent-utilities/SKILL.md");
const CONTRACT = "0x1111111111111111111111111111111111111111";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const TERMS_HASH = `0x${"ab".repeat(32)}`;
const RELEASE = Object.freeze({
  origin: "https://goldkey.example",
  chainId: 8453,
  contract: CONTRACT,
  usdc: USDC,
  termsHash: TERMS_HASH,
});

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function offer(overrides = {}) {
  return {
    schema: "goldkey.offer.v1",
    price: { chain_id: 8453, token_address: USDC },
    contract: { address: CONTRACT, terms_hash: TERMS_HASH, terms_uri: "https://goldkey.example/terms" },
    alternative: { endpoint: "https://goldkey.example/v1/paygo/execute" },
    discovery: {
      catalog_url: "https://goldkey.example/v1/catalog",
      quote_url: "https://goldkey.example/v1/purchase/quote",
    },
    ...overrides,
  };
}

function commerce(overrides = {}) {
  return {
    schema: "goldkey.commerce-response.v1",
    chain_id: 8453,
    contract: CONTRACT,
    payment_token: USDC,
    terms_hash: TERMS_HASH,
    terms_uri: "https://goldkey.example/terms",
    response_schema_url: "https://goldkey.example/schemas/commerce-response-v1.json",
    unsigned_transactions: [],
    ...overrides,
  };
}

test("distribution skill uses portable paths and documented single-line metadata", async () => {
  const source = await readFile(skillPath, "utf8");
  assert.doesNotMatch(source, /node scripts\//);
  const commands = source.match(/^\s*node .*goldkey-client\.mjs.*$/gm) ?? [];
  assert.ok(commands.length >= 10);
  for (const command of commands) assert.match(command, /^\s*node "\{baseDir\}\/scripts\/goldkey-client\.mjs"/);

  const metadataLines = source.split("\n").filter((line) => line.startsWith("metadata:"));
  assert.equal(metadataLines.length, 1);
  const metadata = JSON.parse(metadataLines[0].slice("metadata: ".length));
  assert.deepEqual(metadata.openclaw.requires.bins, ["node"]);
  assert.equal(metadata.openclaw.envVars.some(({ name }) => name === "GOLDKEY_API_URL"), false);
});

test("unsubstituted release fails closed and a complete mainnet identity passes", async () => {
  assert.throws(() => validateReleaseIdentity(RELEASE_IDENTITY_SOURCE), /not configured/);
  await assert.rejects(run(["self-test"]), /not configured/);
  const checked = validateReleaseIdentity(RELEASE);
  assert.equal(checked.chainId, 8453);
  assert.equal(checked.usdc, USDC.toLowerCase());
  assert.equal((await run(["self-test"], { releaseIdentitySource: RELEASE })).contract, CONTRACT.toLowerCase());
  assert.throws(() => validateReleaseIdentity({ ...RELEASE, chainId: 84532 }), /Base mainnet 8453/);
  assert.throws(() => validateReleaseIdentity({ ...RELEASE, usdc: CONTRACT }), /canonical Base mainnet USDC/);
});

test("development origins require explicit opt-in and can never receive bearer tokens", async () => {
  assert.throws(
    () => resolveRuntimeConfig({ env: { GOLDKEY_DEV_API_URL: "https://staging.example" }, releaseIdentitySource: RELEASE }),
    /unless GOLDKEY_ALLOW_DEV_ORIGIN=1/,
  );
  const runtime = resolveRuntimeConfig({
    env: { GOLDKEY_ALLOW_DEV_ORIGIN: "1", GOLDKEY_DEV_API_URL: "https://staging.example" },
    releaseIdentitySource: RELEASE,
  });
  assert.equal(runtime.canonical, false);

  let fetched = false;
  await assert.rejects(
    run(["quota"], {
      env: {
        GOLDKEY_ALLOW_DEV_ORIGIN: "1",
        GOLDKEY_DEV_API_URL: "https://staging.example",
        GOLDKEY_ACCESS_TOKEN: "gks_secret",
      },
      releaseIdentitySource: RELEASE,
      fetchImpl: async () => {
        fetched = true;
        return jsonResponse({});
      },
    }),
    /Refusing to send GOLDKEY_ACCESS_TOKEN/,
  );
  assert.equal(fetched, false);
});

test("legacy origin override is ignored and live offer identity is pinned", async () => {
  let requestedUrl;
  const result = await run(["offer"], {
    env: { GOLDKEY_API_URL: "https://goldkey-edge-sepolia.example" },
    releaseIdentitySource: RELEASE,
    fetchImpl: async (url) => {
      requestedUrl = url;
      return jsonResponse(offer());
    },
  });
  assert.equal(requestedUrl, "https://goldkey.example/.well-known/goldkey.json");
  assert.equal(result.contract.address, CONTRACT);
  await assert.rejects(
    run(["offer"], {
      env: {},
      releaseIdentitySource: RELEASE,
      fetchImpl: async () => jsonResponse(offer({ contract: { ...offer().contract, address: "0x2222222222222222222222222222222222222222" } })),
    }),
    /identity mismatch: offer contract address/,
  );
});

test("commerce validation rejects identity and transaction-target substitution", () => {
  const identity = validateReleaseIdentity(RELEASE);
  assert.equal(validateIdentityPayload("commerce", commerce(), identity).chain_id, 8453);
  assert.throws(() => validateIdentityPayload("commerce", commerce({ terms_hash: `0x${"cd".repeat(32)}` }), identity), /commerce terms hash/);
  assert.throws(
    () => validateIdentityPayload("commerce", commerce({
      unsigned_transactions: [{ to: "0x3333333333333333333333333333333333333333", value: "0" }],
    }), identity),
    /unsigned transaction target/,
  );
});

test("verify rejects argv signatures and accepts secret-store or stdin input", async () => {
  let fetched = false;
  await assert.rejects(
    run(["verify", "--challenge-id", "challenge", "--signature", "0x1234"], {
      env: {},
      releaseIdentitySource: RELEASE,
      fetchImpl: async () => {
        fetched = true;
        return jsonResponse({ access_token: "gks_secret" });
      },
    }),
    /--signature is disabled/,
  );
  assert.equal(fetched, false);

  let requestBody;
  await run(["verify", "--challenge-id", "challenge"], {
    env: {},
    releaseIdentitySource: RELEASE,
    readStdinImpl: async () => "0x1234\n",
    fetchImpl: async (_url, init) => {
      requestBody = JSON.parse(init.body);
      return jsonResponse({ access_token: "gks_secret" });
    },
  });
  assert.equal(requestBody.signature, "0x1234");
});

test("CLI writes verify and delegated-key credentials mode 0600 and redacts results", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "goldkey-distribution-"));
  t.after(() => rm(directory, { recursive: true, force: true }));

  const verifyPath = join(directory, "session.json");
  const verifyResult = await runCli(["verify", "--challenge-id", "challenge", "--secret-output", verifyPath], {
    env: { GOLDKEY_WALLET_SIGNATURE: "0x1234" },
    releaseIdentitySource: RELEASE,
    fetchImpl: async () => jsonResponse({ access_token: "gks_do_not_print", expires_at: "later" }),
  });
  assert.equal(verifyResult.access_token, "[REDACTED]");
  assert.doesNotMatch(JSON.stringify(verifyResult), /gks_do_not_print/);
  assert.deepEqual(JSON.parse(await readFile(verifyPath, "utf8")), { access_token: "gks_do_not_print" });
  assert.equal((await stat(verifyPath)).mode & 0o777, 0o600);

  const keyPath = join(directory, "child.json");
  const keyResult = await runCli([
    "key-issue",
    "--secret-output",
    keyPath,
    "--body",
    '{"label":"child","max_calls":1,"tools":["security.url_check"]}',
  ], {
    env: { GOLDKEY_ACCESS_TOKEN: "gks_owner" },
    releaseIdentitySource: RELEASE,
    fetchImpl: async (_url, init) => {
      assert.equal(init.headers.authorization, "Bearer gks_owner");
      return jsonResponse({ id: "key-id", access_key: "gk_do_not_print" });
    },
  });
  assert.equal(keyResult.access_key, "[REDACTED]");
  assert.doesNotMatch(JSON.stringify(keyResult), /gk_do_not_print/);
  assert.deepEqual(JSON.parse(await readFile(keyPath, "utf8")), { access_key: "gk_do_not_print" });
});
