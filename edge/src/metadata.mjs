import { assert } from "./errors.mjs";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

function tokenImage(tokenId) {
  const escaped = String(tokenId).replace(/[^0-9]/g, "");
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="1200" viewBox="0 0 1200 1200"><rect width="1200" height="1200" fill="#111827"/><circle cx="600" cy="510" r="310" fill="#f4c542"/><circle cx="600" cy="510" r="235" fill="#111827"/><text x="600" y="535" text-anchor="middle" font-family="monospace" font-size="96" font-weight="700" fill="#f4c542">GOLDKEY</text><text x="600" y="690" text-anchor="middle" font-family="monospace" font-size="64" fill="#fff">#${escaped}</text><text x="600" y="1030" text-anchor="middle" font-family="monospace" font-size="34" fill="#d1d5db">10,000 CALLS / 365 DAYS</text></svg>`;
  return `data:image/svg+xml;base64,${btoa(svg)}`;
}

export async function buildMetadata(tokenId, config, chain) {
  assert(/^[1-9]\d*$/.test(String(tokenId)), 400, "invalid_token_id", "tokenId must be a canonical positive integer string");
  const pass = await chain.passState(tokenId);
  assert(pass.term !== "0" && pass.owner.toLowerCase() !== ZERO_ADDRESS, 404, "goldkey_not_found", "GoldKey token does not exist");
  return {
    name: `GoldKey #${pass.tokenId}`,
    description: "Transferable GoldKey API access credential. It is a utility license, not an investment.",
    image: tokenImage(pass.tokenId),
    external_url: `${config.publicOrigin}/.well-known/goldkey.json`,
    attributes: [
      { trait_type: "Term", value: pass.term },
      { trait_type: "Ownership epoch", value: pass.ownershipEpoch },
      { trait_type: "Calls per term", value: 10_000 },
      { trait_type: "Expires", value: new Date(pass.expiresAt).toISOString() },
    ],
  };
}
