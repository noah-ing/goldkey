import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { verifyMessage } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  GUARD_POLICY_SCHEMA,
  GUARD_INSTALLATION_SCHEMA,
  GUARD_REVOCATION_SCHEMA,
  guardInstallationId,
  guardInstallationKeyProofMessage,
  guardInstallationSigningMessage,
  guardPolicySigningMessage,
  guardRevocationSigningMessage,
  hashGuardPolicy,
  normalizeGuardPolicy,
  verifyGuardInstallation,
  verifyGuardPolicy,
  verifyGuardRevocation,
} from "../src/guard-policy.mjs";

const account = privateKeyToAccount(`0x${"11".repeat(32)}`);
const RECIPIENT = "0x0000000000000000000000000000000000000011";
const SPENDER = "0x0000000000000000000000000000000000000012";
const TOKEN = "0x0000000000000000000000000000000000000013";
const OTHER_TOKEN = "0x0000000000000000000000000000000000000014";
const SCHEMA_HASH = "ab".repeat(32);

function unsignedPolicy(overrides = {}) {
  return {
    schema: GUARD_POLICY_SCHEMA,
    policy_id: "policy.production.1",
    version: 1,
    operator_wallet: account.address,
    audience: "https://guard.goldkey.example",
    issued_at: "2026-08-11T00:00:00.000Z",
    expires_at: "2027-08-11T00:00:00.000Z",
    connectors: [
      {
        id: "mcp.billing",
        kind: "mcp_tool",
        server_id: "billing-server",
        tools: [{
          name: "invoice.create",
          effect: "write",
          input_schema_sha256: SCHEMA_HASH,
          arguments_schema: {
            type: "object",
            properties: {
              recipient: { const: "acct.vendor.17" },
              amount_atomic: { const: "1000" },
            },
            required: ["recipient", "amount_atomic"],
            additionalProperties: false,
          },
        }],
      },
      {
        id: "https.vendor",
        kind: "https",
        origin: "https://api.vendor.example",
        operations: [{
          id: "quote",
          method: "POST",
          path: "/v1/quote",
          effect: "network",
          query_schema: {
            type: "object",
            properties: { region: { enum: ["us"] } },
            required: ["region"],
            additionalProperties: false,
          },
          body_schema: {
            type: "object",
            properties: { sku: { const: "A-17" } },
            required: ["sku"],
            additionalProperties: false,
          },
        }],
      },
      {
        id: "evm.treasury",
        kind: "evm_transaction",
        chain_id: 8453,
        from: account.address,
        allowed_native_recipients: [],
        allowed_erc20_tokens: [TOKEN],
        allowed_erc20_recipients: [RECIPIENT],
        allowed_approval_spenders: [SPENDER],
        max_native_value_atomic: "0",
        max_erc20_transfer_atomic: "1000000",
        max_erc20_approval_atomic: "2000000",
        max_gas_limit: "100000",
        max_fee_per_gas_atomic: "100",
        max_priority_fee_per_gas_atomic: "10",
        max_total_fee_atomic: "5000000",
        fee_period_seconds: 86400,
        max_fee_period_atomic: "10000000",
        spend_period_seconds: 86400,
        max_period_atomic: "2000000",
        require_simulation: true,
      },
    ],
    ...overrides,
  };
}

async function signedPolicy(overrides = {}) {
  const policy = unsignedPolicy(overrides);
  const signature = await account.signMessage({ message: guardPolicySigningMessage(policy) });
  return { ...policy, signature };
}

const verifyWalletMessage = ({ wallet, message, signature }) => verifyMessage({ address: wallet, message, signature });

test("guard policy canonical hash ignores object key order and signature", async () => {
  const policy = unsignedPolicy();
  const reordered = {
    connectors: policy.connectors.map((connector) => ({ ...connector })),
    expires_at: policy.expires_at,
    issued_at: policy.issued_at,
    audience: policy.audience,
    operator_wallet: policy.operator_wallet,
    version: policy.version,
    policy_id: policy.policy_id,
    schema: policy.schema,
  };
  assert.equal(hashGuardPolicy(policy), hashGuardPolicy(reordered));
  const nestedSchemaReordered = structuredClone(policy);
  nestedSchemaReordered.connectors[0].tools[0].arguments_schema = {
    additionalProperties: false,
    required: ["recipient", "amount_atomic"],
    properties: {
      amount_atomic: { const: "1000" },
      recipient: { const: "acct.vendor.17" },
    },
    type: "object",
  };
  assert.equal(hashGuardPolicy(policy), hashGuardPolicy(nestedSchemaReordered));
  const signed = await signedPolicy();
  assert.equal(hashGuardPolicy(signed), hashGuardPolicy(policy));
  const normalized = normalizeGuardPolicy(signed);
  assert.equal(Object.isFrozen(normalized), true);
  assert.equal(Object.isFrozen(normalized.connectors), true);
  assert.equal(normalized.connectors[2].asset_id, TOKEN);
});

test("operator EIP-191 signature binds every immutable policy field", async () => {
  const signed = await signedPolicy();
  const verified = await verifyGuardPolicy(signed, { verifyWalletMessage });
  assert.equal(verified.policy.operator_wallet, account.address);
  assert.equal(verified.policy_sha256, hashGuardPolicy(signed));
  assert.match(verified.signing_message, /^GoldKey Guard Policy v1\n/);

  await assert.rejects(
    () => verifyGuardPolicy({ ...signed, version: 2 }, { verifyWalletMessage }),
    (error) => error.code === "invalid_guard_policy_signature",
  );
});

test("policy connectors are closed, HTTPS-only, and period-authoritative", () => {
  assert.throws(
    () => normalizeGuardPolicy({ ...unsignedPolicy(), caller_mandate: {} }),
    (error) => error.code === "invalid_guard_policy",
  );
  const insecure = unsignedPolicy();
  insecure.connectors[1] = { ...insecure.connectors[1], origin: "http://api.vendor.example" };
  assert.throws(() => normalizeGuardPolicy(insecure), /HTTPS origin/);

  const weakPeriod = unsignedPolicy();
  weakPeriod.connectors[2] = {
    ...weakPeriod.connectors[2],
    spend_period_seconds: 10,
  };
  assert.throws(() => normalizeGuardPolicy(weakPeriod), /60-31536000/);

  const underfundedPeriod = unsignedPolicy();
  underfundedPeriod.connectors[2] = {
    ...underfundedPeriod.connectors[2],
    max_period_atomic: "1",
  };
  assert.throws(() => normalizeGuardPolicy(underfundedPeriod), /at least every per-transaction cap/);

  const mixedAssets = unsignedPolicy();
  mixedAssets.connectors[2] = {
    ...mixedAssets.connectors[2],
    allowed_native_recipients: [RECIPIENT],
    max_native_value_atomic: "1",
  };
  assert.throws(() => normalizeGuardPolicy(mixedAssets), /must not authorize ERC-20/);

  const multipleTokens = unsignedPolicy();
  multipleTokens.connectors[2] = {
    ...multipleTokens.connectors[2],
    allowed_erc20_tokens: [TOKEN, OTHER_TOKEN],
  };
  assert.throws(() => normalizeGuardPolicy(multipleTokens), /exactly one native or ERC-20 asset domain/);

  const invertedFeeCaps = unsignedPolicy();
  invertedFeeCaps.connectors[2] = {
    ...invertedFeeCaps.connectors[2],
    max_fee_per_gas_atomic: "9",
    max_priority_fee_per_gas_atomic: "10",
  };
  assert.throws(() => normalizeGuardPolicy(invertedFeeCaps), /must not exceed max_fee_per_gas_atomic/);

  const noSimulation = unsignedPolicy();
  noSimulation.connectors[2] = { ...noSimulation.connectors[2], require_simulation: false };
  assert.throws(() => normalizeGuardPolicy(noSimulation), /require_simulation must be true/);

  const underfundedFeePeriod = unsignedPolicy();
  underfundedFeePeriod.connectors[2] = { ...underfundedFeePeriod.connectors[2], max_fee_period_atomic: "4999999" };
  assert.throws(() => normalizeGuardPolicy(underfundedFeePeriod), /must be at least max_total_fee_atomic/);

  const inconsistentFeeDomain = unsignedPolicy();
  inconsistentFeeDomain.connectors.push({
    ...inconsistentFeeDomain.connectors[2],
    id: "evm.second",
    max_fee_period_atomic: "12000000",
  });
  assert.throws(() => normalizeGuardPolicy(inconsistentFeeDomain), /same fee period and cap/);

  const unsafeArgumentsSchema = unsignedPolicy();
  unsafeArgumentsSchema.connectors[0].tools[0].arguments_schema = { type: "string", pattern: "(a+)+$" };
  assert.throws(
    () => normalizeGuardPolicy(unsafeArgumentsSchema),
    (error) => error.code === "invalid_guard_policy" && error.details?.schema_error_code === "unsafe_schema_keyword",
  );

  const remoteBodySchema = unsignedPolicy();
  remoteBodySchema.connectors[1].operations[0].body_schema = { $ref: "https://attacker.example/schema.json" };
  assert.throws(
    () => normalizeGuardPolicy(remoteBodySchema),
    (error) => error.code === "invalid_guard_policy" && error.details?.schema_error_code === "remote_schema_ref",
  );
});

test("policy signing is audience-bound and signatures are mandatory", async () => {
  const signed = await signedPolicy();
  const otherAudience = { ...signed, audience: "https://other.example" };
  await assert.rejects(
    () => verifyGuardPolicy(otherAudience, { verifyWalletMessage }),
    (error) => error.code === "invalid_guard_policy_signature",
  );
  await assert.rejects(
    () => verifyGuardPolicy(unsignedPolicy(), { verifyWalletMessage }),
    (error) => error.code === "invalid_guard_policy_signature" || error.code === "invalid_guard_policy",
  );
});

test("operator signature binds one public-only installation key to one policy hash", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const publicOnlyJwk = { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x };
  const installationId = guardInstallationId(publicOnlyJwk);
  const expectedFingerprint = createHash("sha256")
    .update(Buffer.from(JSON.stringify({ crv: "Ed25519", kty: "OKP", x: publicJwk.x }), "utf8"))
    .digest("base64url");
  assert.equal(installationId, `gki_${expectedFingerprint}`);
  const binding = {
    schema: GUARD_INSTALLATION_SCHEMA,
    installation_id: installationId,
    operator_wallet: account.address,
    policy_sha256: hashGuardPolicy(unsignedPolicy()),
    public_key_jwk: publicOnlyJwk,
    issued_at: "2026-08-11T00:00:00.000Z",
    expires_at: "2027-08-11T00:00:00.000Z",
  };
  const signed = {
    ...binding,
    signature: await account.signMessage({ message: guardInstallationSigningMessage(binding) }),
    key_proof: sign(null, Buffer.from(guardInstallationKeyProofMessage(binding), "utf8"), privateKey).toString("base64url"),
  };
  const verified = await verifyGuardInstallation(signed, { verifyWalletMessage });
  assert.equal(verified.installation.installation_id, binding.installation_id);
  assert.equal(verified.installation.policy_sha256, binding.policy_sha256);

  const otherKey = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" });
  await assert.rejects(
    () => verifyGuardInstallation({
      ...signed,
      public_key_jwk: { kty: otherKey.kty, crv: otherKey.crv, x: otherKey.x },
    }, { verifyWalletMessage }),
    (error) => error.code === "invalid_guard_installation" && /does not match/.test(error.message),
  );

  const unrelatedPrivate = generateKeyPairSync("ed25519").privateKey;
  await assert.rejects(
    () => verifyGuardInstallation({
      ...signed,
      key_proof: sign(null, Buffer.from(guardInstallationKeyProofMessage(binding), "utf8"), unrelatedPrivate).toString("base64url"),
    }, { verifyWalletMessage }),
    (error) => error.code === "invalid_guard_installation_key_proof",
  );

  assert.throws(
    () => guardInstallationSigningMessage({ ...binding, installation_id: `gki_${"A".repeat(43)}` }),
    (error) => error.code === "invalid_guard_installation" && /does not match/.test(error.message),
  );

  const privateJwk = privateKey.export({ format: "jwk" });
  assert.throws(
    () => guardInstallationSigningMessage({ ...binding, public_key_jwk: privateJwk }),
    (error) => error.code === "invalid_guard_installation",
  );
});

test("operator-signed revocations bind the target, audience, wallet, and issue time", async () => {
  const body = {
    schema: GUARD_REVOCATION_SCHEMA,
    target_kind: "policy",
    target_id: hashGuardPolicy(unsignedPolicy()),
    operator_wallet: account.address,
    audience: "https://guard.goldkey.example",
    issued_at: "2026-08-11T00:00:00.000Z",
  };
  const signed = { ...body, signature: await account.signMessage({ message: guardRevocationSigningMessage(body) }) };
  const verified = await verifyGuardRevocation(signed, { verifyWalletMessage });
  assert.equal(verified.revocation.target_id, body.target_id);
  assert.match(verified.signing_message, /^GoldKey Guard Revocation v1\n/);

  await assert.rejects(
    () => verifyGuardRevocation({ ...signed, target_id: "cd".repeat(32) }, { verifyWalletMessage }),
    (error) => error.code === "invalid_guard_revocation_signature",
  );
  assert.throws(
    () => guardRevocationSigningMessage({ ...body, target_kind: "installation", target_id: "bad id" }),
    (error) => error.code === "invalid_guard_revocation",
  );
});
