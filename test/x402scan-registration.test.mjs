import assert from "node:assert/strict";
import test from "node:test";
import { createSIWxMessage } from "@x402/extensions/sign-in-with-x";
import {
  REGISTRANT,
  REGISTRY_ENDPOINT,
  decodeAndValidateChallenge,
} from "../scripts/register-x402scan.mjs";

const NOW = Date.parse("2026-08-11T05:00:00.000Z");

function encodedChallenge(overrides = {}) {
  const info = {
    domain: "www.x402scan.com",
    uri: REGISTRY_ENDPOINT,
    version: "1",
    chainId: "eip155:8453",
    type: "eip191",
    nonce: "0123456789abcdef0123456789abcdef",
    issuedAt: "2026-08-11T05:00:00.000Z",
    expirationTime: "2026-08-11T05:05:00.000Z",
    statement: "Sign in to verify your wallet identity",
    ...(overrides.info ?? {}),
  };
  const payload = {
    x402Version: 2,
    resource: { url: REGISTRY_ENDPOINT },
    accepts: [],
    extensions: {
      "sign-in-with-x": {
        info,
        supportedChains: [{ chainId: "eip155:8453", type: "eip191" }],
      },
    },
    ...overrides,
  };
  if (overrides.info) payload.extensions["sign-in-with-x"].info = info;
  return Buffer.from(JSON.stringify(payload)).toString("base64");
}

test("x402scan identity challenge is zero-payment, short-lived, and Base-bound", () => {
  const info = decodeAndValidateChallenge(encodedChallenge(), NOW);
  const message = createSIWxMessage(info, REGISTRANT);
  assert.match(message, /^www\.x402scan\.com wants you to sign in with your Ethereum account:/);
  assert.match(message, new RegExp(REGISTRANT, "i"));
  assert.match(message, /URI: https:\/\/www\.x402scan\.com\/api\/x402\/registry\/register-origin/);
  assert.match(message, /Chain ID: 8453/);
  assert.match(message, /Nonce: 0123456789abcdef0123456789abcdef/);
});

test("x402scan registration refuses any challenge that requests payment", () => {
  assert.throws(
    () => decodeAndValidateChallenge(encodedChallenge({ accepts: [{ amount: "1" }] }), NOW),
    /unexpectedly requests payment/,
  );
});

test("x402scan registration refuses an expired or wrong-domain challenge", () => {
  assert.throws(
    () => decodeAndValidateChallenge(encodedChallenge({ info: { domain: "lookalike.example" } }), NOW),
    /domain mismatch/,
  );
  assert.throws(
    () => decodeAndValidateChallenge(encodedChallenge(), NOW + 301_000),
    /issue time is stale|expired/,
  );
});

test("registration helper has no transaction, payment, or private-key path", async () => {
  const source = await import("node:fs/promises").then((fs) => fs.readFile(new URL("../scripts/register-x402scan.mjs", import.meta.url), "utf8"));
  assert.doesNotMatch(source, /wallet\s+send|cast\s+send|--private-key|payment-signature|x-payment/i);
  assert.match(source, /accepts\.length === 0/);
  assert.match(source, /wallet", "sign", "--account"/);
});
