import {
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign,
  timingSafeEqual,
} from "node:crypto";

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function decodeCdpSecret(secret) {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new Error("CDP_API_KEY_SECRET must be a base64 Ed25519 secret");
  }
  const encoded = secret.trim();
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) || encoded.length % 4 === 1) {
    throw new Error("CDP_API_KEY_SECRET must be canonical base64");
  }
  const decoded = Buffer.from(encoded, "base64");
  const canonicalInput = encoded.replace(/=+$/, "");
  const canonicalDecoded = decoded.toString("base64").replace(/=+$/, "");
  if (canonicalInput !== canonicalDecoded || decoded.length !== 64) {
    throw new Error("CDP_API_KEY_SECRET must decode to the documented 64-byte Ed25519 secret");
  }
  return decoded;
}

function privateKeyFromDecoded(decoded) {
  const seed = decoded.subarray(0, 32);
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({ key: Buffer.concat([pkcs8Prefix, seed]), format: "der", type: "pkcs8" });
}

export function validateCdpApiKeySecret(secret) {
  const decoded = decodeCdpSecret(secret);
  const privateKey = privateKeyFromDecoded(decoded);
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const derivedPublicKey = Buffer.from(publicDer).subarray(-32);
  if (!timingSafeEqual(derivedPublicKey, decoded.subarray(32))) {
    throw new Error("CDP_API_KEY_SECRET contains a public key that does not match its Ed25519 seed");
  }
  return true;
}

function ed25519PrivateKey(secret) {
  const decoded = decodeCdpSecret(secret);
  const privateKey = privateKeyFromDecoded(decoded);
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  if (!timingSafeEqual(Buffer.from(publicDer).subarray(-32), decoded.subarray(32))) {
    throw new Error("CDP_API_KEY_SECRET contains a public key that does not match its Ed25519 seed");
  }
  return privateKey;
}

export function generateCdpJwt({ apiKeyId, apiKeySecret, method, host, path, nowSeconds = Math.floor(Date.now() / 1000) }) {
  if (!apiKeyId || !apiKeySecret) throw new Error("Both CDP_API_KEY_ID and CDP_API_KEY_SECRET are required");
  const header = {
    alg: "EdDSA",
    typ: "JWT",
    kid: apiKeyId,
    nonce: randomBytes(16).toString("hex"),
  };
  const payload = {
    sub: apiKeyId,
    iss: "cdp",
    aud: ["cdp_service"],
    nbf: nowSeconds,
    exp: nowSeconds + 120,
    uri: `${method.toUpperCase()} ${host}${path}`,
  };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
  const signature = sign(null, Buffer.from(signingInput), ed25519PrivateKey(apiKeySecret));
  return `${signingInput}.${signature.toString("base64url")}`;
}

export function createCdpFacilitatorAuth({ facilitatorUrl, apiKeyId, apiKeySecret }) {
  const url = new URL(facilitatorUrl);
  const basePath = url.pathname.replace(/\/+$/, "");
  const bearer = (method, suffix) => ({
    Authorization: `Bearer ${generateCdpJwt({ apiKeyId, apiKeySecret, method, host: url.host, path: `${basePath}/${suffix}` })}`,
  });
  return async () => ({
    verify: bearer("POST", "verify"),
    settle: bearer("POST", "settle"),
    supported: bearer("GET", "supported"),
  });
}
