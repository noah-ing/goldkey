#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import {
  createSIWxPayload,
  encodeSIWxHeader,
  verifySIWxSignature,
} from "@x402/extensions/sign-in-with-x";

export const REGISTRY_ENDPOINT = "https://www.x402scan.com/api/x402/registry/register-origin";
export const STOREFRONT_ORIGIN = "https://goldkey-edge-storefront.noah-ing.workers.dev";
export const REGISTRANT = "0xd6b7E00FcD46966676F554fE0455BfF739e85b1b";
export const CAST_BIN = process.env.CAST_BIN || "/Users/noah-ing/.foundry/bin/cast";
export const KEYSTORE_ACCOUNT = process.env.GOLDKEY_DEPLOYER_ACCOUNT || "goldkey-deployer";

function check(condition, message, details) {
  if (!condition) {
    const suffix = details === undefined ? "" : `: ${JSON.stringify(details)}`;
    throw new Error(`${message}${suffix}`);
  }
}

function parseJson(text, label) {
  try {
    return text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`${label} returned non-JSON`);
  }
}

export function decodeAndValidateChallenge(encoded, now = Date.now()) {
  check(typeof encoded === "string" && encoded.length > 0, "registry omitted PAYMENT-REQUIRED");
  let challenge;
  try {
    challenge = JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
  } catch {
    throw new Error("registry returned an invalid PAYMENT-REQUIRED challenge");
  }

  check(challenge?.x402Version === 2, "unexpected x402 challenge version", challenge?.x402Version);
  check(Array.isArray(challenge.accepts) && challenge.accepts.length === 0, "registry challenge unexpectedly requests payment", challenge.accepts);
  check(challenge.resource?.url === REGISTRY_ENDPOINT, "registry resource mismatch", challenge.resource?.url);

  const extension = challenge.extensions?.["sign-in-with-x"];
  const info = extension?.info;
  check(info && typeof info === "object", "registry omitted sign-in-with-x info");
  check(info.domain === "www.x402scan.com", "SIWX domain mismatch", info.domain);
  check(info.uri === REGISTRY_ENDPOINT, "SIWX URI mismatch", info.uri);
  check(info.version === "1", "SIWX version mismatch", info.version);
  check(info.chainId === "eip155:8453", "SIWX chain mismatch", info.chainId);
  check(info.type === "eip191", "SIWX signature type mismatch", info.type);
  check(info.statement === "Sign in to verify your wallet identity", "SIWX statement mismatch", info.statement);
  check(/^[A-Za-z0-9]{8,64}$/.test(info.nonce ?? ""), "SIWX nonce is malformed");
  check(info.resources === undefined && info.requestId === undefined && info.notBefore === undefined, "SIWX challenge contains unexpected authorization scope");
  check(Array.isArray(extension.supportedChains) && extension.supportedChains.length === 1, "SIWX challenge must declare exactly one supported chain");
  const selectedChain = extension.supportedChains[0];
  check(selectedChain?.chainId === info.chainId && selectedChain?.type === info.type, "SIWX supported-chain declaration mismatch");
  check(selectedChain.signatureScheme === undefined || selectedChain.signatureScheme === "eip191", "SIWX signature scheme mismatch", selectedChain.signatureScheme);

  const issuedAt = Date.parse(info.issuedAt);
  const expiresAt = Date.parse(info.expirationTime);
  check(Number.isFinite(issuedAt) && issuedAt >= now - 60_000 && issuedAt <= now + 30_000, "SIWX challenge issue time is stale or in the future", info.issuedAt);
  check(Number.isFinite(expiresAt) && expiresAt > now + 10_000, "SIWX challenge has expired or is too close to expiry", info.expirationTime);
  check(expiresAt - issuedAt > 0 && expiresAt - issuedAt <= 600_000, "SIWX challenge lifetime is unexpectedly long", { issuedAt: info.issuedAt, expirationTime: info.expirationTime });

  return Object.freeze({
    ...info,
    chainId: selectedChain.chainId,
    type: selectedChain.type,
    signatureScheme: selectedChain.signatureScheme,
  });
}

export function signWithEncryptedKeystore(message, expiresAt) {
  check(typeof message === "string" && message.length > 0, "SIWX message is missing");
  check(process.stdin.isTTY, "run this registration from an interactive Terminal");
  const timeout = Date.parse(expiresAt) - Date.now() - 10_000;
  check(timeout > 0, "SIWX challenge expired before signing");
  const signerEnv = { ...process.env };
  for (const name of ["ETH_PASSWORD", "ETH_PRIVATE_KEY", "PRIVATE_KEY", "MNEMONIC"]) {
    delete signerEnv[name];
  }
  const result = spawnSync(CAST_BIN, ["wallet", "sign", "--account", KEYSTORE_ACCOUNT, message], {
    encoding: "utf8",
    env: signerEnv,
    maxBuffer: 64 * 1024,
    stdio: ["inherit", "pipe", "inherit"],
    timeout,
  });
  check(result.error === undefined, "could not start cast wallet sign", result.error?.message);
  check(result.status === 0, "cast wallet sign failed", { status: result.status, signal: result.signal });
  const signature = result.stdout.trim();
  check(/^0x[0-9a-fA-F]{130}$/.test(signature), "cast returned an invalid EIP-191 signature");
  return signature;
}

async function postRegistration(siwxHeader) {
  const response = await fetch(REGISTRY_ENDPOINT, {
    method: "POST",
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(120_000),
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      ...(siwxHeader ? { "sign-in-with-x": siwxHeader } : {}),
    },
    body: JSON.stringify({ origin: STOREFRONT_ORIGIN }),
  });
  const text = await response.text();
  return {
    status: response.status,
    ok: response.ok,
    paymentRequired: response.headers.get("payment-required"),
    body: parseJson(text, "x402scan registry"),
  };
}

function failureCount(value) {
  if (Array.isArray(value)) return value.length;
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : 0;
}

export async function main() {
  const first = await postRegistration();
  check(first.status === 402, "registry did not return an identity challenge", { status: first.status, body: first.body });
  const info = decodeAndValidateChallenge(first.paymentRequired);

  process.stdout.write([
    "X402SCAN IDENTITY REGISTRATION",
    `Origin: ${STOREFRONT_ORIGIN}`,
    `Wallet proving identity: ${REGISTRANT}`,
    `Signing domain: ${info.domain}`,
    `Challenge expires: ${info.expirationTime}`,
    "Payment requested: none",
    "Onchain transaction: none",
    "",
  ].join("\n"));

  const payload = await createSIWxPayload(info, {
    address: REGISTRANT,
    async signMessage({ message }) {
      process.stdout.write(`Exact identity message to sign (no payment or transaction):\n\n${message}\n\nEnter the encrypted keystore password.\n`);
      return signWithEncryptedKeystore(message, info.expirationTime);
    },
  });
  const verification = await verifySIWxSignature(payload);
  check(verification.isValid, "local SIWX signature verification failed", verification);
  check(verification.payer.toLowerCase() === REGISTRANT.toLowerCase(), "local signature recovered the wrong wallet", verification.payer);
  check(Date.now() < Date.parse(info.expirationTime) - 5_000, "SIWX challenge expired before submission");

  const header = encodeSIWxHeader(payload);
  const result = await postRegistration(header);
  check(result.ok, "authenticated registry request failed", { status: result.status, body: result.body });
  check(result.body && typeof result.body === "object", "registry returned an empty result");
  check(failureCount(result.body.failed) === 0, "x402scan rejected one or more resources", result.body.failedDetails ?? result.body);
  check(Number(result.body.total) >= 1, "x402scan did not discover any registerable resources", result.body);

  process.stdout.write(`${JSON.stringify({
    ok: true,
    origin: STOREFRONT_ORIGIN,
    wallet: REGISTRANT,
    registered: result.body.registered,
    failed: result.body.failed,
    deprecated: result.body.deprecated,
    total: result.body.total,
    source: result.body.source,
    payment_or_transaction_signed: false,
    signature_printed_or_persisted: false,
  }, null, 2)}\n`);
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  main().catch((error) => {
    process.stderr.write(`X402SCAN REGISTRATION FAILED: ${error.message}\n`);
    process.exitCode = 1;
  });
}
