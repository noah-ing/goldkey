import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import {
  GUARD_RECEIPT_EVIDENCE_SCHEMA,
  createGuardReceiptSigner,
  verifyGuardAuthorizationReceipt,
} from "../src/guard-receipt.mjs";

const NOW = Date.parse("2026-08-11T12:00:00.000Z");
const POLICY_HASH = "ab".repeat(32);
const CALL_HASH = "cd".repeat(32);

function keyMaterial() {
  const { privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPkcs8Base64: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
    privateJwk: privateKey.export({ format: "jwk" }),
  };
}

function authorizationInput(overrides = {}) {
  return {
    installation_id: "install.production.1",
    idempotency_key: "invoice.create.0001",
    connector_id: "mcp.billing",
    kind: "mcp_tool",
    policy_id: "policy.production.1",
    policy_version: 4,
    policy_sha256: POLICY_HASH,
    call_sha256: CALL_HASH,
    decision: "ALLOW",
    reason_codes: [],
    evidence: {
      schema: GUARD_RECEIPT_EVIDENCE_SCHEMA,
      decision: "ALLOW",
      reason_codes: [],
      effect: "write",
      destination: "mcp://billing-server/invoice.create",
      details: { tool_schema_sha256: "ef".repeat(32) },
    },
    ttl_ms: 30_000,
    ...overrides,
  };
}

test("Ed25519 authorization receipt binds call, policy, idempotency, connector, and evidence", () => {
  const current = keyMaterial();
  const signer = createGuardReceiptSigner({
    ...current,
    keyId: "receipt-key-2026-08",
    clock: () => NOW,
    idGenerator: () => "receipt.0001",
  });
  const envelope = signer.signAuthorization(authorizationInput());
  const verified = verifyGuardAuthorizationReceipt(envelope, { keyset: signer.keyset, now: NOW + 1 });
  assert.equal(verified.valid, true);
  assert.equal(verified.receipt.idempotency_key, "invoice.create.0001");
  assert.equal(verified.receipt.connector_id, "mcp.billing");
  assert.equal(verified.receipt.kind, "mcp_tool");
  assert.equal(verified.receipt.call_sha256, CALL_HASH);
  assert.equal(verified.evidence.destination, "mcp://billing-server/invoice.create");
  assert.equal(JSON.stringify(envelope).includes(current.privateKeyPkcs8Base64), false);
});

test("receipt verification rejects evidence tampering and expiry", () => {
  const signer = createGuardReceiptSigner({
    ...keyMaterial(),
    keyId: "receipt-key-current",
    clock: () => NOW,
    idGenerator: () => "receipt.0002",
  });
  const envelope = signer.signAuthorization(authorizationInput());
  const tampered = {
    ...envelope,
    evidence: { ...envelope.evidence, destination: "mcp://attacker/steal" },
  };
  assert.throws(
    () => verifyGuardAuthorizationReceipt(tampered, { keyset: signer.keyset, now: NOW + 1 }),
    (error) => error.code === "guard_receipt_evidence_mismatch",
  );
  assert.throws(
    () => verifyGuardAuthorizationReceipt(envelope, { keyset: signer.keyset, now: NOW + 30_000 }),
    (error) => error.code === "guard_receipt_expired",
  );
});

test("receipt evidence hash prevents target bytecode evidence tampering", () => {
  const signer = createGuardReceiptSigner({
    ...keyMaterial(),
    keyId: "receipt-key-evm",
    clock: () => NOW,
    idGenerator: () => "receipt.evm.0001",
  });
  const envelope = signer.signAuthorization(authorizationInput({
    connector_id: "evm.usdc",
    kind: "evm_transaction",
    evidence: {
      schema: GUARD_RECEIPT_EVIDENCE_SCHEMA,
      decision: "ALLOW",
      reason_codes: [],
      effect: "payment",
      destination: "eip155:8453:0x0000000000000000000000000000000000000013",
      details: { simulation: { target_code_sha256: "ef".repeat(32) } },
    },
  }));
  const tampered = {
    ...envelope,
    evidence: {
      ...envelope.evidence,
      details: { simulation: { target_code_sha256: "00".repeat(32) } },
    },
  };
  assert.throws(
    () => verifyGuardAuthorizationReceipt(tampered, { keyset: signer.keyset, now: NOW + 1 }),
    (error) => error.code === "guard_receipt_evidence_mismatch",
  );
});

test("key rotation retains bounded old public verification keys but never old private keys", () => {
  const oldMaterial = keyMaterial();
  let oldClock = NOW;
  const oldSigner = createGuardReceiptSigner({
    ...oldMaterial,
    keyId: "receipt-key-old",
    clock: () => oldClock,
    idGenerator: () => `receipt.old.${oldClock}`,
  });
  const historicalEnvelope = oldSigner.signAuthorization(authorizationInput({ ttl_ms: 60_000 }));
  const retiredAt = NOW + 10_000;

  const currentSigner = createGuardReceiptSigner({
    ...keyMaterial(),
    keyId: "receipt-key-current",
    previousPublicKeys: [{
      ...oldSigner.publicKeyJwk,
      not_before: new Date(NOW - 60_000).toISOString(),
      signing_not_after: new Date(retiredAt).toISOString(),
    }],
    clock: () => retiredAt,
    idGenerator: () => "receipt.current",
  });
  assert.equal(currentSigner.keyset.keys.length, 2);
  assert.equal(verifyGuardAuthorizationReceipt(historicalEnvelope, { keyset: currentSigner.keyset, now: retiredAt + 1 }).valid, true);
  assert.equal(JSON.stringify(currentSigner.keyset).includes("\"d\""), false);

  // A compromised retired private key can still make a valid Ed25519 signature,
  // but it cannot make a receipt whose issue time falls after the rotation cutover.
  oldClock = retiredAt + 1;
  const forgedFreshEnvelope = oldSigner.signAuthorization(authorizationInput({ ttl_ms: 60_000 }));
  assert.throws(
    () => verifyGuardAuthorizationReceipt(forgedFreshEnvelope, { keyset: currentSigner.keyset, now: retiredAt + 2 }),
    (error) => error.code === "guard_receipt_key_retired",
  );

  assert.throws(
    () => createGuardReceiptSigner({
      ...keyMaterial(),
      keyId: "receipt-key-missing-window",
      previousPublicKeys: [oldSigner.publicKeyJwk],
    }),
    (error) => error.code === "invalid_guard_keyset" && /bounded signing interval/.test(error.message),
  );

  assert.throws(
    () => createGuardReceiptSigner({
      ...keyMaterial(),
      keyId: "receipt-key-next",
      previousPublicKeys: [{ ...oldMaterial.privateJwk, kid: "leaked-private" }],
    }),
    (error) => error.code === "invalid_guard_keyset",
  );
  assert.throws(
    () => verifyGuardAuthorizationReceipt(historicalEnvelope, {
      keyset: { ...oldSigner.keyset, keys: [{ ...oldSigner.publicKeyJwk, d: oldMaterial.privateJwk.d }] },
      now: NOW + 1,
    }),
    (error) => error.code === "invalid_guard_keyset",
  );
});

test("revoked retained keys reject receipts issued at or after revocation", () => {
  const oldSigner = createGuardReceiptSigner({
    ...keyMaterial(),
    keyId: "receipt-key-revoked",
    clock: () => NOW,
    idGenerator: () => "receipt.revoked",
  });
  const envelope = oldSigner.signAuthorization(authorizationInput({ ttl_ms: 60_000 }));
  const keyset = {
    schema: oldSigner.keyset.schema,
    keys: [
      createGuardReceiptSigner({ ...keyMaterial(), keyId: "receipt-key-current" }).publicKeyJwk,
      {
        ...oldSigner.publicKeyJwk,
        not_before: new Date(NOW - 60_000).toISOString(),
        signing_not_after: new Date(NOW + 60_000).toISOString(),
        revoked_at: new Date(NOW).toISOString(),
      },
    ],
  };
  assert.throws(
    () => verifyGuardAuthorizationReceipt(envelope, { keyset, now: NOW + 1 }),
    (error) => error.code === "guard_receipt_key_revoked",
  );
});

test("receipt evidence and top-level decision cannot disagree", () => {
  const signer = createGuardReceiptSigner({ ...keyMaterial(), keyId: "receipt-key-current", clock: () => NOW });
  assert.throws(
    () => signer.signAuthorization(authorizationInput({
      decision: "BLOCK",
      reason_codes: ["policy_denied"],
    })),
    /evidence.decision must match/,
  );
});
