import assert from "node:assert/strict";
import { generateKeyPairSync, verify } from "node:crypto";
import test from "node:test";
import {
  createCdpFacilitatorAuth,
  generateCdpJwt,
  validateCdpApiKeySecret,
} from "../src/cdp-auth.mjs";

function decode(part) {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

function secretFromKeyPair(privateKey, publicKey) {
  const seed = privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32);
  const publicBytes = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  return Buffer.concat([seed, publicBytes]).toString("base64");
}

test("CDP facilitator JWT binds method, host, path, key, and a two-minute lifetime", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const apiKeySecret = secretFromKeyPair(privateKey, publicKey);
  const jwt = generateCdpJwt({
    apiKeyId: "organizations/example/apiKeys/key",
    apiKeySecret,
    method: "POST",
    host: "api.cdp.coinbase.com",
    path: "/platform/v2/x402/verify",
    nowSeconds: 1_700_000_000,
  });
  const [encodedHeader, encodedPayload, encodedSignature] = jwt.split(".");
  const header = decode(encodedHeader);
  const payload = decode(encodedPayload);
  assert.equal(header.alg, "EdDSA");
  assert.equal(header.kid, "organizations/example/apiKeys/key");
  assert.equal(payload.uri, "POST api.cdp.coinbase.com/platform/v2/x402/verify");
  assert.equal(payload.exp - payload.nbf, 120);
  assert.equal(verify(null, Buffer.from(`${encodedHeader}.${encodedPayload}`), publicKey, Buffer.from(encodedSignature, "base64url")), true);
});

test("CDP secret validation requires the documented 64-byte seed and public key", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const valid = secretFromKeyPair(privateKey, publicKey);
  assert.equal(validateCdpApiKeySecret(valid), true);
  assert.throws(
    () => validateCdpApiKeySecret(privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32).toString("base64")),
    /64-byte/,
  );
  const mismatched = Buffer.from(valid, "base64");
  mismatched[63] ^= 1;
  assert.throws(() => validateCdpApiKeySecret(mismatched.toString("base64")), /does not match/);
});

test("facilitator JWT paths normalize every trailing slash", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const createHeaders = createCdpFacilitatorAuth({
    facilitatorUrl: "https://api.cdp.coinbase.com/platform/v2/x402///",
    apiKeyId: "organizations/example/apiKeys/key",
    apiKeySecret: secretFromKeyPair(privateKey, publicKey),
  });
  const headers = await createHeaders();
  const verifyPayload = decode(headers.verify.Authorization.slice("Bearer ".length).split(".")[1]);
  const settlePayload = decode(headers.settle.Authorization.slice("Bearer ".length).split(".")[1]);
  assert.equal(verifyPayload.uri, "POST api.cdp.coinbase.com/platform/v2/x402/verify");
  assert.equal(settlePayload.uri, "POST api.cdp.coinbase.com/platform/v2/x402/settle");
});
