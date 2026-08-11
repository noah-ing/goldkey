import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import { chmod, mkdir, open, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { canonicalBytes, canonicalize, fromBase64url, sha256Bytes, toBase64url } from "./canonical.mjs";
import { InvalidInputError, LocalStateError, ReceiptVerificationError } from "./errors.mjs";

function normalizePublicJwk(jwk, name = "Ed25519 public JWK") {
  if (!jwk || typeof jwk !== "object" || Array.isArray(jwk)) throw new InvalidInputError(`${name} must be an object`);
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    throw new InvalidInputError(`${name} must have kty=OKP, crv=Ed25519, and x`);
  }
  if (Object.hasOwn(jwk, "d")) throw new InvalidInputError(`${name} must not contain private key material`);
  fromBase64url(jwk.x, { exactBytes: 32 });
  return Object.freeze({ crv: "Ed25519", kty: "OKP", x: jwk.x });
}

function publicFingerprint(publicJwk, prefix) {
  return `${prefix}_${toBase64url(sha256Bytes(canonicalBytes(publicJwk)))}`;
}

export function receiptKeyId(publicJwk) {
  return publicFingerprint(normalizePublicJwk(publicJwk), "gkr");
}

function identityFromPrivateKey(privateKey) {
  const publicKey = createPublicKey(privateKey);
  const publicJwk = normalizePublicJwk(publicKey.export({ format: "jwk" }));
  const installationId = publicFingerprint(publicJwk, "gki");
  return Object.freeze({
    installationId,
    publicJwk,
    signMessage(message) {
      if (typeof message !== "string") throw new InvalidInputError("Installation signing message must be a string");
      return toBase64url(sign(null, Buffer.from(message, "utf8"), privateKey));
    },
    signCanonical(value) {
      return toBase64url(sign(null, canonicalBytes(value), privateKey));
    },
  });
}

export function createInstallationIdentity() {
  const { privateKey } = generateKeyPairSync("ed25519");
  return identityFromPrivateKey(privateKey);
}

export function installationIdentityFromPrivateJwk(privateJwk) {
  if (!privateJwk || privateJwk.kty !== "OKP" || privateJwk.crv !== "Ed25519" || typeof privateJwk.d !== "string") {
    throw new InvalidInputError("Installation private JWK must be an Ed25519 OKP key containing d");
  }
  try {
    return identityFromPrivateKey(createPrivateKey({ key: privateJwk, format: "jwk" }));
  } catch (cause) {
    throw new InvalidInputError("Installation private JWK is invalid", { cause: cause.message });
  }
}

async function assertPrivatePermissions(filename) {
  if (process.platform === "win32") return;
  const metadata = await stat(filename);
  if ((metadata.mode & 0o077) !== 0) {
    throw new LocalStateError(`Installation key ${filename} must not be accessible by group or other users`);
  }
}

async function assertPrivateDirectoryPermissions(directory) {
  if (process.platform === "win32") return;
  const metadata = await stat(directory);
  if ((metadata.mode & 0o077) !== 0) {
    throw new LocalStateError(`Installation key directory ${directory} must not be accessible by group or other users`);
  }
}

export async function loadOrCreateInstallationIdentity(filename) {
  if (typeof filename !== "string" || filename.length === 0) throw new InvalidInputError("Installation key filename is required");
  const directory = path.dirname(path.resolve(filename));
  const resolved = path.resolve(filename);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await assertPrivateDirectoryPermissions(directory);

  async function load() {
    let document;
    try {
      await assertPrivatePermissions(resolved);
      document = JSON.parse(await readFile(resolved, "utf8"));
    } catch (cause) {
      if (cause instanceof LocalStateError) throw cause;
      throw new LocalStateError(`Unable to read installation key ${resolved}`, { cause });
    }
    if (document?.schema !== "goldkey-installation-key.v1") {
      throw new LocalStateError(`Installation key ${resolved} has an unsupported schema`);
    }
    return installationIdentityFromPrivateJwk(document.private_jwk);
  }

  try {
    return await load();
  } catch (error) {
    if (!(error instanceof LocalStateError) || error.cause?.code !== "ENOENT") throw error;
  }

  const { privateKey } = generateKeyPairSync("ed25519");
  const privateJwk = privateKey.export({ format: "jwk" });
  const document = { schema: "goldkey-installation-key.v1", private_jwk: privateJwk };
  let handle;
  try {
    handle = await open(resolved, "wx", 0o600);
    await handle.writeFile(`${canonicalize(document)}\n`, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await chmod(resolved, 0o600);
    return identityFromPrivateKey(privateKey);
  } catch (cause) {
    await handle?.close().catch(() => {});
    if (cause?.code === "EEXIST") return load();
    throw new LocalStateError(`Unable to persist installation key ${resolved}`, { cause });
  }
}

export function verifyEd25519Canonical({ publicJwk, value, signature, keyName = "GoldKey receipt key" }) {
  const normalized = normalizePublicJwk(publicJwk, keyName);
  let signatureBytes;
  try {
    signatureBytes = fromBase64url(signature, { exactBytes: 64 });
  } catch (cause) {
    throw new ReceiptVerificationError("Receipt signature is not a canonical 64-byte Ed25519 signature", { cause: cause.message });
  }
  let valid = false;
  try {
    const key = createPublicKey({ key: normalized, format: "jwk" });
    valid = verify(null, canonicalBytes(value), key, signatureBytes);
  } catch (cause) {
    throw new ReceiptVerificationError("GoldKey receipt public key is invalid", { cause: cause.message });
  }
  if (!valid) throw new ReceiptVerificationError("GoldKey receipt signature verification failed");
  return true;
}

export { normalizePublicJwk };
