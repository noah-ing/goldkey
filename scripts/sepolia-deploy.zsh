#!/bin/zsh

set -e
set -u
setopt PIPE_FAIL

SCRIPT_DIR="${0:A:h}"
ROOT_DIR="${SCRIPT_DIR:h}"
CAST_BIN="/Users/noah-ing/.foundry/bin/cast"
FORGE_BIN="/Users/noah-ing/.foundry/bin/forge"
ACCOUNT="goldkey-deployer"
DEPLOYER="0xd6b7E00FcD46966676F554fE0455BfF739e85b1b"
USDC="0x036CbD53842c5426634e7929541eC2318f3dCF7e"
METADATA_BASE_URI="https://goldkey-edge-sepolia.noah-ing.workers.dev/metadata/"
TERMS_URI="https://goldkey-edge-sepolia.noah-ing.workers.dev/terms"
TERMS_HASH="0xd1fb20b0e28b63e18b660a2710f1b69b356bc87829a01cf5d75e572ae7de3750"
EXPECTED_CONTRACT="0x220FE98C77CE79baa00d47C5896BE05C2A7D3db0"

fail() {
  print -u2 -- "DEPLOYMENT STOPPED: $1"
  exit 1
}

cd "$ROOT_DIR"

[[ -x "$CAST_BIN" ]] || fail "Foundry cast is missing."
[[ -x "$FORGE_BIN" ]] || fail "Foundry forge is missing."
[[ -f "/Users/noah-ing/.foundry/keystores/$ACCOUNT" ]] || fail "Deployment keystore is missing."

if [[ -z "${GOLDKEY_RPC_URL:-}" || "$GOLDKEY_RPC_URL" == *"base-mainnet"* ]]; then
  read -rs "GOLDKEY_RPC_URL?Paste the Base Sepolia HTTPS RPC URL (hidden): "
  print
fi

[[ "$GOLDKEY_RPC_URL" == https://base-sepolia.g.alchemy.com/v2/* ]] || \
  fail "RPC URL must begin with https://base-sepolia.g.alchemy.com/v2/."

export ETH_RPC_URL="$GOLDKEY_RPC_URL"

chain_id="$($CAST_BIN chain-id)"
[[ "$chain_id" == "84532" ]] || fail "RPC is not Base Sepolia (84532)."

pending_nonce="$($CAST_BIN nonce "$DEPLOYER" --block pending)"
print -- "Pending deployer nonce: $pending_nonce"
[[ "$pending_nonce" == "0" ]] || \
  fail "Deployer nonce is not zero. A transaction may already exist; refusing a duplicate deployment."

[[ "$($CAST_BIN code "$DEPLOYER")" == "0x" ]] || fail "Deployer address unexpectedly contains code."
[[ "$(node scripts/terms-hash.mjs)" == "$TERMS_HASH" ]] || fail "Terms hash changed."

print -- "Network: Base Sepolia (84532)"
print -- "Deployer/owner/treasury: $DEPLOYER"
print -- "USDC: $USDC"
print -- "Metadata: $METADATA_BASE_URI"
print -- "Terms: $TERMS_URI"
print -- "Expected contract: $EXPECTED_CONTRACT"
print -- "This will broadcast exactly one testnet contract-creation transaction."

read "confirmation?Type DEPLOY to continue: "
[[ "$confirmation" == "DEPLOY" ]] || fail "Confirmation not received."

log_path="$ROOT_DIR/sepolia-deploy-$(date -u +%Y%m%dT%H%M%SZ).log"

cd "$ROOT_DIR/contracts"

{
  "$FORGE_BIN" create src/GoldKey.sol:GoldKey \
    --chain 84532 \
    --account "$ACCOUNT" \
    --broadcast \
    --constructor-args \
      "$DEPLOYER" \
      "$USDC" \
      "$DEPLOYER" \
      "$METADATA_BASE_URI" \
      "$TERMS_URI" \
      "$TERMS_HASH"
} 2>&1 | tee "$log_path"

if grep -qE 'Dry run enabled|To broadcast this transaction' "$log_path"; then
  fail "Forge simulated instead of broadcasting. No deployment was recorded."
fi

post_nonce="$($CAST_BIN nonce "$DEPLOYER" --block pending)"
[[ "$post_nonce" == "1" ]] || \
  fail "Expected deployer nonce 1 after broadcast; got $post_nonce. Inspect $log_path."

deployed_code="0x"
for attempt in {1..10}; do
  deployed_code="$($CAST_BIN code "$EXPECTED_CONTRACT")"
  [[ "$deployed_code" != "0x" ]] && break
  sleep 2
done
[[ "$deployed_code" != "0x" ]] || \
  fail "RPC did not expose the confirmed deployment within 20 seconds. Inspect $log_path before taking any action."

[[ "$($CAST_BIN call "$EXPECTED_CONTRACT" 'owner()(address)')" == "$DEPLOYER" ]] || \
  fail "Deployed owner does not match the expected deployer."
[[ "$($CAST_BIN call "$EXPECTED_CONTRACT" 'treasury()(address)')" == "$DEPLOYER" ]] || \
  fail "Deployed treasury does not match the expected deployer."
[[ "$($CAST_BIN call "$EXPECTED_CONTRACT" 'USDC()(address)')" == "$USDC" ]] || \
  fail "Deployed USDC address is incorrect."
[[ "$($CAST_BIN call "$EXPECTED_CONTRACT" 'LICENSE_TERMS_HASH()(bytes32)')" == "$TERMS_HASH" ]] || \
  fail "Deployed terms hash is incorrect."

print -- "DEPLOYMENT CONFIRMED"
print -- "Contract: $EXPECTED_CONTRACT"
print -- "Explorer: https://sepolia.basescan.org/address/$EXPECTED_CONTRACT"
print -- "Deployment log: $log_path"
