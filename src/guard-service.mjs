import { createPublicKey, verify as verifyBytes } from "node:crypto";
import { canonicalize } from "./canonical.mjs";
import { ServiceError, assert } from "./errors.mjs";
import {
  evaluateGuardRequest,
  guardDecisionEvidence,
  guardRequestSigningMessage,
  hashGuardCall,
  validateGuardRequest,
  verifyGuardCommit,
  verifyGuardCompletion,
} from "./guard.mjs";
import {
  verifyGuardInstallation,
  verifyGuardPolicy,
  verifyGuardRevocation,
} from "./guard-policy.mjs";
import { createGuardReceiptSigner } from "./guard-receipt.mjs";
import {
  guardPaymentBinding,
  validateGuardReconciledCommit,
} from "./guard-payment.mjs";

const DECISION_STATUS = Object.freeze({ ALLOW: "authorized", REVIEW: "review", BLOCK: "denied" });
const RECEIPT_KEYSET_PATH = "/.well-known/goldkey-guard-keys.json";

function parseStoredObject(value, field) {
  try {
    const parsed = JSON.parse(value);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
    return parsed;
  } catch (cause) {
    throw new ServiceError(500, "guard_storage_corrupt", `${field} is not valid stored JSON`, { cause: cause.message });
  }
}

function sameCaseInsensitive(left, right) {
  return String(left).toLowerCase() === String(right).toLowerCase();
}

function storedPolicyId(operatorWallet, policyId) {
  return `${String(operatorWallet).toLowerCase()}:${policyId}`;
}

function importInstallationKey(record) {
  const jwk = parseStoredObject(record.public_key_jwk_json, "installation public key");
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string" || Object.hasOwn(jwk, "d")) {
    throw new ServiceError(500, "guard_storage_corrupt", "Installation public key is not a public Ed25519 JWK");
  }
  try {
    return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
  } catch (cause) {
    throw new ServiceError(500, "guard_storage_corrupt", "Installation public key cannot be imported", { cause: cause.message });
  }
}

function verifyInstallationMessage(record, message, signature) {
  try {
    return verifyBytes(null, Buffer.from(message, "utf8"), importInstallationKey(record), Buffer.from(signature, "base64url"));
  } catch (cause) {
    if (cause instanceof ServiceError) throw cause;
    return false;
  }
}

function publicExecution(row) {
  return {
    execution_id: row.id,
    installation_id: row.installation_id,
    policy_sha256: row.policy_hash,
    call_sha256: row.call_hash,
    decision: row.decision,
    status: row.lifecycle_status,
    issued_at: new Date(row.created_at).toISOString(),
    expires_at: new Date(row.expires_at).toISOString(),
    committed_at: row.committed_at === null ? null : new Date(row.committed_at).toISOString(),
    completed_at: row.completed_at === null ? null : new Date(row.completed_at).toISOString(),
    outcome_status: row.outcome_status,
    outcome_sha256: row.outcome_hash,
  };
}

function capDeniedDecision(decision, error) {
  const reasonCodes = [...new Set([...decision.reason_codes, "authoritative_spend_cap_exceeded"])].sort();
  return Object.freeze({
    ...decision,
    decision: "BLOCK",
    reason_codes: Object.freeze(reasonCodes),
    details: Object.freeze({
      ...(decision.details ?? {}),
      authoritative_spend: Object.freeze({
        status: "denied",
        code: "authoritative_spend_cap_exceeded",
        ...(error.details ?? {}),
      }),
    }),
  });
}

export function createGuardService({
  config,
  db,
  chain,
  receiptSigner,
  previousPublicKeys = [],
  simulateEvmTransaction,
  clock = () => Date.now(),
} = {}) {
  assert(config?.guardEnabled === true, 500, "guard_disabled", "Guard service cannot start unless GUARD_ENABLED is true");
  assert(db && chain && typeof chain.verifyWalletMessage === "function", 500, "guard_dependency_missing", "Guard database and chain verifier are required");
  const signer = receiptSigner ?? createGuardReceiptSigner({
    privateKeyPkcs8Base64: config.guardReceiptPrivateKey,
    keyId: config.guardReceiptKeyId,
    previousPublicKeys,
    clock,
  });
  const allowedOperators = new Set(config.guardAllowedOperatorWallets ?? []);
  function assertAllowedOperator(wallet) {
    assert(allowedOperators.has(String(wallet).toLowerCase()), 403, "guard_operator_not_allowed", "Guard beta registration is restricted to approved design partners");
  }

  async function registerPolicy(rawPolicy) {
    assertAllowedOperator(rawPolicy?.operator_wallet);
    const verified = await verifyGuardPolicy(rawPolicy, { verifyWalletMessage: chain.verifyWalletMessage });
    assert(verified.policy.audience === config.publicOrigin, 403, "guard_policy_audience_mismatch", "Policy audience must equal this permanent public origin");
    const now = clock();
    const issuedAt = Date.parse(verified.policy.issued_at);
    const expiresAt = Date.parse(verified.policy.expires_at);
    assert(issuedAt <= now + 60_000, 400, "guard_policy_not_yet_active", "Policy issued_at is too far in the future");
    assert(expiresAt > now, 410, "guard_policy_expired", "Policy is already expired");
    const policyJson = canonicalize(verified.policy);
    const storagePolicyId = storedPolicyId(verified.policy.operator_wallet, verified.policy.policy_id);
    const existing = await db.getGuardPolicyVersionByHash(verified.policy_sha256);
    if (existing) {
      assert(
        existing.policy_id === storagePolicyId
          && String(existing.version) === String(verified.policy.version)
          && sameCaseInsensitive(existing.operator_wallet, verified.policy.operator_wallet),
        409,
        "guard_policy_conflict",
        "Policy hash is already bound to a different identity",
      );
      return {
        replay: true,
        policy_id: verified.policy.policy_id,
        version: Number(existing.version),
        policy_sha256: existing.policy_hash,
        operator_wallet: existing.operator_wallet,
        expires_at: new Date(existing.expires_at).toISOString(),
      };
    }
    const created = await db.createGuardPolicyVersion({
      policyId: storagePolicyId,
      version: String(verified.policy.version),
      policyHash: verified.policy_sha256,
      policyJson,
      operatorWallet: verified.policy.operator_wallet,
      operatorSignature: verified.policy.signature,
      createdAt: issuedAt,
      expiresAt,
    });
    return {
      replay: false,
      policy_id: verified.policy.policy_id,
      version: Number(created.version),
      policy_sha256: created.policy_hash,
      operator_wallet: created.operator_wallet,
      expires_at: new Date(created.expires_at).toISOString(),
    };
  }

  async function registerInstallation(rawInstallation) {
    assertAllowedOperator(rawInstallation?.operator_wallet);
    const verified = await verifyGuardInstallation(rawInstallation, { verifyWalletMessage: chain.verifyWalletMessage });
    const policy = await db.getGuardPolicyVersionByHash(verified.installation.policy_sha256);
    assert(policy, 404, "guard_policy_not_found", "Pinned Guard policy is not registered");
    assert(policy.revoked_at === null && policy.expires_at > clock(), 403, "guard_policy_inactive", "Pinned Guard policy is expired or revoked");
    assert(sameCaseInsensitive(policy.operator_wallet, verified.installation.operator_wallet), 409, "guard_operator_mismatch", "Installation operator must match policy operator");
    const storedPolicy = parseStoredObject(policy.policy_json, "guard policy");
    const latestPolicy = await db.getLatestGuardPolicyVersion(storedPolicyId(policy.operator_wallet, storedPolicy.policy_id));
    assert(latestPolicy?.policy_hash === policy.policy_hash, 409, "guard_policy_superseded", "New installations must pin the latest Guard policy version");
    const bindingJson = canonicalize(verified.installation);
    const existing = await db.getGuardInstallation(verified.installation.installation_id);
    if (existing) {
      assert(existing.policy_hash === verified.installation.policy_sha256 && existing.binding_json === bindingJson, 409, "guard_installation_conflict", "Installation ID is already bound differently");
      return {
        replay: true,
        installation_id: existing.id,
        policy_sha256: existing.policy_hash,
        operator_wallet: existing.operator_wallet,
        expires_at: new Date(existing.expires_at).toISOString(),
      };
    }
    const created = await db.createGuardInstallation({
      installationId: verified.installation.installation_id,
      operatorWallet: verified.installation.operator_wallet,
      policyHash: verified.installation.policy_sha256,
      publicKeyJwkJson: canonicalize(verified.installation.public_key_jwk),
      bindingJson,
      operatorSignature: verified.installation.signature,
      createdAt: Date.parse(verified.installation.issued_at),
      expiresAt: Date.parse(verified.installation.expires_at),
    });
    return {
      replay: false,
      installation_id: created.id,
      policy_sha256: created.policy_hash,
      operator_wallet: created.operator_wallet,
      expires_at: new Date(created.expires_at).toISOString(),
    };
  }

  async function revoke(rawRevocation) {
    const verified = await verifyGuardRevocation(rawRevocation, { verifyWalletMessage: chain.verifyWalletMessage });
    const { revocation } = verified;
    assert(revocation.audience === config.publicOrigin, 403, "guard_revocation_audience_mismatch", "Revocation audience must equal this permanent public origin");
    const now = clock();
    const issuedAt = Date.parse(revocation.issued_at);
    assert(issuedAt <= now + 60_000 && issuedAt >= now - 5 * 60_000, 401, "guard_revocation_expired", "Guard revocation is outside its accepted five-minute window");
    if (revocation.target_kind === "policy") {
      const policy = await db.getGuardPolicyVersionByHash(revocation.target_id);
      assert(policy, 404, "guard_policy_not_found", "Guard policy version does not exist");
      assert(sameCaseInsensitive(policy.operator_wallet, revocation.operator_wallet), 403, "guard_operator_mismatch", "Only the policy operator may revoke this policy");
      const revoked = await db.revokeGuardPolicyVersion(revocation.target_id, now);
      return {
        target_kind: "policy",
        target_id: revoked.policy_hash,
        operator_wallet: revoked.operator_wallet,
        revoked_at: new Date(revoked.revoked_at).toISOString(),
      };
    }
    const installation = await db.getGuardInstallation(revocation.target_id);
    assert(installation, 404, "guard_installation_not_found", "Guard installation does not exist");
    assert(sameCaseInsensitive(installation.operator_wallet, revocation.operator_wallet), 403, "guard_operator_mismatch", "Only the installation operator may revoke this installation");
    const revoked = await db.revokeGuardInstallation(revocation.target_id, now);
    return {
      target_kind: "installation",
      target_id: revoked.id,
      operator_wallet: revoked.operator_wallet,
      revoked_at: new Date(revoked.revoked_at).toISOString(),
    };
  }

  async function activeContext(rawRequest, expectedKinds) {
    const request = validateGuardRequest(rawRequest);
    if (expectedKinds) assert(expectedKinds.includes(request.call.kind), 400, "guard_route_kind_mismatch", "Call kind does not match this Guard authorization route");
    const now = clock();
    const installation = await db.getGuardInstallation(request.installation_id);
    assert(installation, 404, "guard_installation_not_found", "Guard installation is not registered");
    const policyRecord = await db.getGuardPolicyVersionByHash(installation.policy_hash);
    assert(policyRecord, 500, "guard_storage_corrupt", "Installation references a missing policy");
    const signatureValid = verifyInstallationMessage(installation, guardRequestSigningMessage(request), request.signature);
    assert(signatureValid, 401, "invalid_guard_request_signature", "Guard request signature does not match the registered installation");
    const existing = await db.getGuardExecutionByIdempotency(request.installation_id, request.idempotency_key);
    if (existing && existing.call_hash !== hashGuardCall(request.call)) {
      throw new ServiceError(409, "idempotency_conflict", "Idempotency key was already used with a different call hash");
    }
    if (existing && existing.expires_at <= now) {
      throw new ServiceError(409, "guard_idempotency_expired", "Authorization for this idempotency key expired; use a new key for a new decision");
    }
    const settledClaim = existing?.payment_settled_at !== null
      && existing?.payment_settled_at !== undefined
      && existing?.settlement_started_at !== null
      && existing?.settlement_started_at !== undefined;
    const installationRevokedAfterClaim = settledClaim
      && installation.revoked_at !== null
      && installation.revoked_at >= existing.settlement_started_at;
    const policyRevokedAfterClaim = settledClaim
      && policyRecord.revoked_at !== null
      && policyRecord.revoked_at >= existing.settlement_started_at;
    assert(
      (installation.revoked_at === null || installationRevokedAfterClaim) && installation.expires_at > now,
      403,
      "guard_installation_inactive",
      "Guard installation is expired or revoked",
    );
    assert(
      (policyRecord.revoked_at === null || policyRevokedAfterClaim) && policyRecord.expires_at > now,
      403,
      "guard_policy_inactive",
      "Guard policy is expired or revoked",
    );
    return {
      request,
      installation,
      policyRecord,
      policy: parseStoredObject(policyRecord.policy_json, "guard policy"),
      existing,
      now,
      verifyInstallationSignature: ({ message, signature }) => verifyInstallationMessage(installation, message, signature),
    };
  }

  async function preflight(rawRequest, expectedKinds) {
    const context = await activeContext(rawRequest, expectedKinds);
    const paymentSettled = context.existing?.payment_settled_at !== null
      && context.existing?.payment_settled_at !== undefined;
    return {
      installation_id: context.request.installation_id,
      idempotency_key: context.request.idempotency_key,
      kind: context.request.call.kind,
      call_sha256: hashGuardCall(context.request.call),
      replay: Boolean(context.existing),
      payment_settled: paymentSettled,
      replay_authorization: context.existing && paymentSettled
        ? parseStoredObject(context.existing.authorization_receipt_json, "authorization receipt")
        : undefined,
    };
  }

  async function settlementContext(rawRequest, expectedKinds) {
    const request = validateGuardRequest(rawRequest);
    if (expectedKinds) assert(expectedKinds.includes(request.call.kind), 400, "guard_route_kind_mismatch", "Call kind does not match this Guard authorization route");
    const installation = await db.getGuardInstallation(request.installation_id);
    assert(installation, 404, "guard_installation_not_found", "Guard installation is not registered");
    const signatureValid = verifyInstallationMessage(installation, guardRequestSigningMessage(request), request.signature);
    assert(signatureValid, 401, "invalid_guard_request_signature", "Guard request signature does not match the registered installation");
    const callHash = hashGuardCall(request.call);
    const existing = await db.getGuardExecutionByIdempotency(request.installation_id, request.idempotency_key);
    assert(existing, 500, "guard_settlement_missing_authorization", "Settlement has no stored Guard authorization");
    if (existing.call_hash !== callHash) throw new ServiceError(409, "idempotency_conflict", "Settlement request does not match the stored call hash");
    return { request, existing, callHash };
  }

  async function beginPaymentSettlement(rawRequest, expectedKinds, settlementClaimId, paymentContext) {
    assert(typeof settlementClaimId === "string" && settlementClaimId.length >= 1 && settlementClaimId.length <= 128, 500, "invalid_guard_settlement_claim", "Guard settlement claim is missing or invalid");
    const context = await activeContext(rawRequest, expectedKinds);
    assert(context.existing, 500, "guard_settlement_missing_authorization", "Settlement has no stored Guard authorization");
    const payment = guardPaymentBinding(paymentContext?.paymentPayload, {
      config,
      path: paymentContext?.path,
      requirements: paymentContext?.requirements,
    });
    const started = await db.beginGuardExecutionSettlement({
      installationId: context.request.installation_id,
      idempotencyKey: context.request.idempotency_key,
      callHash: hashGuardCall(context.request.call),
      settlementClaimId,
      paymentSha256: payment.payment_sha256,
      paymentIdentitySha256: payment.payment_identity_sha256,
      startedAt: clock(),
    });
    return { replay: started.replay, ...publicExecution(started.execution) };
  }

  async function cancelPaymentSettlement(rawRequest, expectedKinds, settlementClaimId, { error } = {}) {
    assert(typeof settlementClaimId === "string" && settlementClaimId.length >= 1 && settlementClaimId.length <= 128, 500, "invalid_guard_settlement_claim", "Guard settlement claim is missing or invalid");
    const context = await settlementContext(rawRequest, expectedKinds);
    if (error !== undefined) {
      // A thrown facilitator error is not evidence that settlement did not land;
      // timeouts are explicitly indeterminate in x402. Preserve the durable
      // claim and its unique payment identity for on-chain reconciliation.
      return { replay: true, indeterminate: true, ...publicExecution(context.existing) };
    }
    const canceled = await db.cancelGuardExecutionSettlement({
      installationId: context.request.installation_id,
      idempotencyKey: context.request.idempotency_key,
      callHash: context.callHash,
      settlementClaimId,
      canceledAt: clock(),
    });
    return { replay: canceled.replay, ...publicExecution(canceled.execution) };
  }

  async function recordPaymentSettlement(rawRequest, settlementResult, expectedKinds, settlementClaimId, paymentContext) {
    assert(settlementResult?.success === true, 500, "guard_settlement_not_successful", "Only a successful x402 settlement may mark a Guard authorization as paid");
    assert(typeof settlementClaimId === "string" && settlementClaimId.length >= 1 && settlementClaimId.length <= 128, 500, "invalid_guard_settlement_claim", "Guard settlement claim is missing or invalid");
    const context = await settlementContext(rawRequest, expectedKinds);
    const payment = guardPaymentBinding(paymentContext?.paymentPayload, {
      config,
      path: paymentContext?.path,
      requirements: paymentContext?.requirements,
    });
    assert(context.existing.settlement_payment_hash === payment.payment_sha256, 409, "guard_payment_proof_mismatch", "Settled payment payload does not own this Guard settlement claim");
    assert(context.existing.settlement_payment_identity_hash === payment.payment_identity_sha256, 409, "guard_payment_identity_mismatch", "Settled payment authorization identity does not own this Guard settlement claim");
    assert(settlementResult.network === payment.expected.network, 500, "guard_settlement_proof_mismatch", "Facilitator settlement network does not match the claimed Base payment");
    assert(sameCaseInsensitive(settlementResult.payer, payment.authorization.from), 500, "guard_settlement_proof_mismatch", "Facilitator settlement payer does not match the claimed EIP-3009 authorization");
    if (settlementResult.amount !== undefined) {
      assert(String(settlementResult.amount) === payment.expected.amount, 500, "guard_settlement_proof_mismatch", "Facilitator settlement amount does not match the claimed Guard price");
    }
    assert(
      typeof settlementResult.transaction === "string" && /^0x[0-9a-fA-F]{64}$/.test(settlementResult.transaction),
      500,
      "guard_settlement_proof_missing",
      "Successful Guard settlement must include a canonical Base transaction hash",
    );
    const transaction = settlementResult.transaction.toLowerCase();
    const marked = await db.markGuardExecutionPaymentSettled({
      installationId: context.request.installation_id,
      idempotencyKey: context.request.idempotency_key,
      callHash: context.callHash,
      settlementClaimId,
      paymentSha256: payment.payment_sha256,
      paymentIdentitySha256: payment.payment_identity_sha256,
      settledAt: clock(),
      transaction,
    });
    return { replay: marked.replay, ...publicExecution(marked.execution) };
  }

  function reservationsFor(decision, context) {
    if (decision.decision !== "ALLOW") return {};
    const reservations = [];
    const asset = decision.details?.reservation;
    if (asset && BigInt(asset.amount_atomic) > 0n) {
      const periodMs = asset.spend_period_seconds * 1000;
      const periodStart = Math.floor(context.now / periodMs) * periodMs;
      reservations.push({
        reservationKey: `guard:asset:${decision.policy_sha256}:${context.request.call.connector_id}:${periodStart}`,
        reservationAmountAtomic: asset.amount_atomic,
        spendCapAtomic: asset.max_period_atomic,
      });
    }
    const fee = decision.details?.fee_reservation;
    if (fee && BigInt(fee.amount_atomic) > 0n) {
      const periodMs = fee.spend_period_seconds * 1000;
      const periodStart = Math.floor(context.now / periodMs) * periodMs;
      reservations.push({
        reservationKey: `guard:fee:${decision.policy_sha256}:${fee.fee_domain}:${periodStart}`,
        reservationAmountAtomic: fee.amount_atomic,
        spendCapAtomic: fee.max_period_atomic,
      });
    }
    const nonce = decision.details?.nonce_reservation;
    if (nonce) {
      reservations.push({
        reservationKey: `guard:nonce:${nonce.lock_key}`,
        reservationAmountAtomic: nonce.amount_atomic,
        spendCapAtomic: nonce.max_period_atomic,
      });
    }
    return reservations.length === 0 ? {} : { reservations };
  }

  function signedEnvelope(decision, context) {
    const evidence = guardDecisionEvidence(decision);
    const ttlMs = Math.min(
      config.guardAuthorizationTtlMs,
      context.installation.expires_at - context.now,
      context.policyRecord.expires_at - context.now,
    );
    assert(ttlMs >= 1, 409, "guard_authorization_expired", "Installation or policy expired before authorization could be issued");
    return signer.signAuthorization({
      installation_id: context.request.installation_id,
      idempotency_key: context.request.idempotency_key,
      connector_id: context.request.call.connector_id,
      kind: context.request.call.kind,
      policy_id: decision.policy_id,
      policy_version: decision.policy_version,
      policy_sha256: decision.policy_sha256,
      call_sha256: decision.call_sha256,
      decision: decision.decision,
      reason_codes: decision.reason_codes,
      evidence,
      ttl_ms: ttlMs,
    });
  }

  async function persistAuthorization(decision, context, { allowCapFallback = true } = {}) {
    const envelope = signedEnvelope(decision, context);
    const createdAt = Date.parse(envelope.receipt.issued_at);
    const expiresAt = Date.parse(envelope.receipt.expires_at);
    try {
      const stored = await db.reserveGuardExecution({
        executionId: envelope.receipt.receipt_id,
        installationId: context.request.installation_id,
        idempotencyKey: context.request.idempotency_key,
        callHash: decision.call_sha256,
        policyHash: decision.policy_sha256,
        decision: decision.decision,
        status: DECISION_STATUS[decision.decision],
        authorizationReceiptJson: canonicalize(envelope),
        createdAt,
        expiresAt,
        ...reservationsFor(decision, context),
      });
      if (stored.replay) return parseStoredObject(stored.execution.authorization_receipt_json, "authorization receipt");
      return envelope;
    } catch (error) {
      if (allowCapFallback && error instanceof ServiceError && error.code === "guard_spend_cap_exceeded" && decision.decision === "ALLOW") {
        return persistAuthorization(capDeniedDecision(decision, error), context, { allowCapFallback: false });
      }
      throw error;
    }
  }

  async function authorize(rawRequest, expectedKinds) {
    const context = await activeContext(rawRequest, expectedKinds);
    const evaluation = {
      request: context.request,
      policy: context.policy,
      audience: config.publicOrigin,
      verifyWalletMessage: chain.verifyWalletMessage,
      verifyInstallationSignature: context.verifyInstallationSignature,
      now: context.now,
    };
    let decision = await evaluateGuardRequest(evaluation);

    // Decode and reject forbidden transactions before spending RPC work. Only a
    // transaction that is otherwise policy-compliant may reach live simulation.
    if (
      context.request.call.kind === "evm_transaction"
      && decision.decision === "REVIEW"
      && decision.reason_codes.length === 1
      && decision.reason_codes[0] === "evm_simulation_required"
    ) {
      const simulator = simulateEvmTransaction ?? chain.simulateGuardTransaction;
      assert(typeof simulator === "function", 503, "guard_simulation_unavailable", "EVM simulation provider is unavailable");
      const simulation = await simulator(context.request.call.transaction);
      decision = await evaluateGuardRequest({ ...evaluation, simulation });
    }
    return persistAuthorization(decision, context);
  }

  async function verifiedCommitContext(rawCommit) {
    const installation = await db.getGuardInstallation(rawCommit?.installation_id);
    assert(installation, 404, "guard_installation_not_found", "Guard installation is not registered");
    const verified = await verifyGuardCommit(rawCommit, {
      verifyInstallationSignature: ({ message, signature }) => verifyInstallationMessage(installation, message, signature),
      now: clock(),
    });
    const execution = await db.getGuardExecution(verified.execution_id);
    assert(execution && execution.installation_id === verified.installation_id, 404, "guard_execution_not_found", "Guard execution does not belong to this installation");
    assert(execution.id === verified.receipt_id, 409, "guard_lifecycle_mismatch", "Commit receipt_id does not match execution");
    const authorization = parseStoredObject(execution.authorization_receipt_json, "authorization receipt");
    assert(authorization.receipt_sha256 === verified.receipt_sha256 && execution.call_hash === verified.call_sha256, 409, "guard_lifecycle_mismatch", "Commit does not bind the stored authorization receipt and call");
    return { verified, execution, authorization };
  }

  async function commit(rawCommit) {
    const { execution } = await verifiedCommitContext(rawCommit);
    const committed = await db.commitGuardExecution({ executionId: execution.id, committedAt: clock() });
    return { replay: committed.replay, ...publicExecution(committed.execution) };
  }

  async function reconcileCommit(rawReconciliation) {
    const reconciliation = validateGuardReconciledCommit(rawReconciliation);
    const { execution, authorization } = await verifiedCommitContext(reconciliation.commit);
    assert(execution.settlement_started_at !== null, 409, "guard_settlement_not_started", "Guard payment reconciliation requires an active settlement claim");
    const kind = authorization.receipt?.kind;
    assert(new Set(["mcp_tool", "https", "evm_transaction"]).has(kind), 500, "guard_storage_corrupt", "Authorization receipt contains an invalid Guard call kind");
    const path = kind === "evm_transaction"
      ? "/v1/guard/paygo/authorize/evm"
      : "/v1/guard/paygo/authorize/network";
    const payment = guardPaymentBinding(reconciliation.payment_proof.payment_payload, { config, path });
    assert(execution.settlement_payment_hash === payment.payment_sha256, 409, "guard_payment_proof_mismatch", "Payment payload was not bound to this Guard settlement claim");
    assert(execution.settlement_payment_identity_hash === payment.payment_identity_sha256, 409, "guard_payment_identity_mismatch", "Payment authorization identity was not bound to this Guard settlement claim");
    if (execution.payment_settled_at !== null) {
      assert(execution.payment_transaction === reconciliation.payment_proof.transaction, 409, "guard_payment_transaction_mismatch", "Guard execution is already bound to a different payment transaction");
      const committed = await db.commitGuardExecution({ executionId: execution.id, committedAt: clock() });
      return { replay: committed.replay, payment_reconciled: false, ...publicExecution(committed.execution) };
    }
    assert(typeof chain.verifyGuardPaymentTransaction === "function", 503, "guard_payment_proof_unavailable", "Base payment proof verifier is unavailable");
    await chain.verifyGuardPaymentTransaction({
      transaction: reconciliation.payment_proof.transaction,
      authorization: payment.authorization,
    });
    const now = clock();
    const committed = await db.commitGuardExecution({
      executionId: execution.id,
      committedAt: now,
      paymentReconciliation: {
        paymentSha256: payment.payment_sha256,
        paymentIdentitySha256: payment.payment_identity_sha256,
        transaction: reconciliation.payment_proof.transaction,
        settledAt: now,
      },
    });
    return { replay: committed.replay, payment_reconciled: true, ...publicExecution(committed.execution) };
  }

  async function complete(rawCompletion) {
    const installation = await db.getGuardInstallation(rawCompletion?.installation_id);
    assert(installation, 404, "guard_installation_not_found", "Guard installation is not registered");
    const verified = await verifyGuardCompletion(rawCompletion, {
      verifyInstallationSignature: ({ message, signature }) => verifyInstallationMessage(installation, message, signature),
      now: clock(),
    });
    const execution = await db.getGuardExecution(verified.execution_id);
    assert(execution && execution.installation_id === verified.installation_id, 404, "guard_execution_not_found", "Guard execution does not belong to this installation");
    assert(execution.id === verified.receipt_id, 409, "guard_lifecycle_mismatch", "Completion receipt_id does not match execution");
    const authorization = parseStoredObject(execution.authorization_receipt_json, "authorization receipt");
    assert(authorization.receipt_sha256 === verified.receipt_sha256 && execution.call_hash === verified.call_sha256, 409, "guard_lifecycle_mismatch", "Completion does not bind the stored authorization receipt and call");
    const completed = await db.completeGuardExecution({
      executionId: execution.id,
      completionReceiptJson: canonicalize(verified),
      outcomeStatus: verified.outcome_status,
      outcomeHash: verified.outcome_sha256,
      completedAt: clock(),
    });
    return { replay: completed.replay, ...publicExecution(completed.execution) };
  }

  return Object.freeze({
    keyset: signer.keyset,
    keysetPath: RECEIPT_KEYSET_PATH,
    registerPolicy,
    registerInstallation,
    revoke,
    preflight,
    beginPaymentSettlement,
    cancelPaymentSettlement,
    recordPaymentSettlement,
    authorize,
    commit,
    reconcileCommit,
    complete,
  });
}
