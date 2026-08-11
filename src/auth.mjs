import { randomBytes, randomUUID } from "node:crypto";
import { getAddress, isAddress } from "viem";
import { canonicalTokenId } from "./chain.mjs";
import { ServiceError, assert } from "./errors.mjs";

function bearer(req) {
  const header = req.get("authorization") ?? "";
  const match = /^Bearer ([^\s]+)$/.exec(header);
  return match?.[1];
}

function rpcFailure(error) {
  if (error instanceof ServiceError) return error;
  return new ServiceError(503, "chain_unavailable", "Unable to verify GoldKey ownership onchain", { cause: error.message });
}

export function createAuthService({ config, db, chain }) {
  async function checkedPass(tokenId, expectedOwner) {
    try {
      const pass = await chain.passState(tokenId);
      if (expectedOwner && pass.owner.toLowerCase() !== expectedOwner.toLowerCase()) {
        throw new ServiceError(403, "not_current_owner", "Wallet is not the current owner of this GoldKey");
      }
      if (!pass.active) throw new ServiceError(402, "goldkey_term_expired", "GoldKey service term has expired");
      return pass;
    } catch (error) {
      throw rpcFailure(error);
    }
  }

  async function challenge({ wallet, token_id: tokenIdInput } = {}) {
    assert(isAddress(wallet), 400, "invalid_wallet", "wallet must be an EVM address");
    let tokenId;
    try {
      tokenId = canonicalTokenId(tokenIdInput);
    } catch (error) {
      throw new ServiceError(400, "invalid_token_id", error.message);
    }
    const owner = getAddress(wallet);
    const pass = await checkedPass(tokenId, owner);
    const id = randomUUID();
    const nonce = randomBytes(16).toString("hex");
    const issuedAt = Date.now();
    const expiresAt = issuedAt + config.challengeTtlMs;
    const domain = new URL(config.publicOrigin).host;
    const message = `${domain} wants you to sign in with your Ethereum account:\n${owner}\n\nAuthenticate to GoldKey API using token #${tokenId} ownership epoch ${pass.ownershipEpoch}\n\nURI: ${config.publicOrigin}\nVersion: 1\nChain ID: ${config.chainId}\nNonce: ${nonce}\nIssued At: ${new Date(issuedAt).toISOString()}\nExpiration Time: ${new Date(expiresAt).toISOString()}\nRequest ID: ${id}\nResources:\n- eip155:${config.chainId}/erc721:${config.contractAddress}/${tokenId}?ownership_epoch=${pass.ownershipEpoch}`;
    await db.insertChallenge({ id, wallet: owner, tokenId, ownershipEpoch: pass.ownershipEpoch, message, issuedAt, expiresAt });
    return { challenge_id: id, message, expires_at: new Date(expiresAt).toISOString() };
  }

  async function verify({ challenge_id: challengeId, signature } = {}) {
    assert(typeof challengeId === "string", 400, "invalid_challenge", "challenge_id is required");
    assert(typeof signature === "string" && signature.length <= 8194 && /^0x[0-9a-fA-F]+$/.test(signature), 400, "invalid_signature", "signature must be a hex string of at most 4096 bytes");
    const record = await db.getChallenge(challengeId);
    assert(record, 404, "challenge_not_found", "Challenge was not found");
    assert(record.used_at === null, 409, "challenge_used", "Challenge was already used");
    assert(record.expires_at > Date.now(), 410, "challenge_expired", "Challenge has expired");
    let valid;
    try {
      valid = await chain.verifyWalletMessage({ wallet: record.wallet, message: record.message, signature });
    } catch (error) {
      throw rpcFailure(error);
    }
    assert(valid, 401, "invalid_signature", "Signature does not match the challenged wallet");
    const pass = await checkedPass(record.token_id, record.wallet);
    assert(pass.ownershipEpoch === record.ownership_epoch, 409, "ownership_epoch_changed", "GoldKey transferred after this challenge was issued");
    const rawToken = `gks_${randomBytes(32).toString("base64url")}`;
    const createdAt = Date.now();
    const expiresAt = createdAt + config.sessionTtlMs;
    await db.consumeChallengeAndCreateSession(challengeId, rawToken, {
      wallet: record.wallet,
      tokenId: record.token_id,
      ownershipEpoch: record.ownership_epoch,
      createdAt,
      expiresAt,
    });
    return {
      access_token: rawToken,
      token_type: "Bearer",
      expires_at: new Date(expiresAt).toISOString(),
      goldkey: pass,
    };
  }

  async function authorize(req) {
    const rawToken = bearer(req);
    if (config.devAuthBypass && rawToken && rawToken === config.devAuthToken) {
      return {
        kind: "dev",
        wallet: "0x000000000000000000000000000000000000dEaD",
        tokenId: req.get("x-goldkey-token-id") ?? "1",
        principalId: "dev:0",
        pass: { term: "1", ownershipEpoch: "0", expiresAt: Date.now() + 365 * 86400_000, active: true, owner: "0x000000000000000000000000000000000000dEaD" },
      };
    }
    if (!rawToken) throw new ServiceError(401, "authentication_required", "Provide a GoldKey session or delegated key as a Bearer token");

    if (rawToken.startsWith("gks_")) {
      const session = await db.getSession(rawToken);
      if (!session) throw new ServiceError(401, "invalid_session", "Session is invalid or expired");
      const pass = await checkedPass(session.token_id, session.wallet);
      if (pass.ownershipEpoch !== session.ownership_epoch) throw new ServiceError(401, "stale_session", "Session predates a GoldKey transfer");
      return { kind: "owner", wallet: session.wallet, tokenId: session.token_id, principalId: `owner:${session.wallet.toLowerCase()}:${pass.ownershipEpoch}`, pass };
    }
    if (rawToken.startsWith("gk_")) {
      const key = await db.authenticateAccessKey(rawToken);
      if (!key) throw new ServiceError(401, "invalid_access_key", "Delegated key is invalid, expired, or revoked");
      const pass = await checkedPass(key.token_id, key.issuer_wallet);
      if (pass.term !== key.term_number) throw new ServiceError(401, "stale_access_key", "Delegated key belongs to a previous GoldKey term");
      if (pass.ownershipEpoch !== key.ownership_epoch) throw new ServiceError(401, "stale_access_key", "Delegated key predates a GoldKey transfer");
      return { kind: "delegate", wallet: key.issuer_wallet, tokenId: key.token_id, principalId: `delegate:${key.id}:${pass.ownershipEpoch}`, pass, accessKey: key };
    }
    throw new ServiceError(401, "unknown_credential", "Bearer token is not a GoldKey credential");
  }

  return { challenge, verify, authorize, checkedPass };
}
