#!/bin/zsh

set -e
set -u
setopt PIPE_FAIL

SCRIPT_DIR="${0:A:h}"
ROOT_DIR="${SCRIPT_DIR:h}"
CAST_BIN="/Users/noah-ing/.foundry/bin/cast"
KEYSTORE="/Users/noah-ing/.foundry/keystores/goldkey-deployer"
ACCOUNT="goldkey-deployer"
EXPECTED_DEPLOYER="0xd6b7e00fcd46966676f554fe0455bff739e85b1b"
USDC="0x036CbD53842c5426634e7929541eC2318f3dCF7e"
WORKER_ORIGIN="https://goldkey-edge-sepolia.noah-ing.workers.dev"
EXPECTED_TERMS_HASH="0xd1fb20b0e28b63e18b660a2710f1b69b356bc87829a01cf5d75e572ae7de3750"

fail() {
  print -u2 -- "PREFLIGHT FAILED: $1"
  exit 1
}

cd "$ROOT_DIR"

[[ -x "$CAST_BIN" ]] || fail "Foundry cast is missing."
[[ -f "$KEYSTORE" ]] || fail "goldkey-deployer keystore is missing."
chmod 600 "$KEYSTORE"

if [[ -z "${GOLDKEY_RPC_URL:-}" || "$GOLDKEY_RPC_URL" == *"base-mainnet"* ]]; then
  read -rs "GOLDKEY_RPC_URL?Paste the Base Sepolia HTTPS RPC URL (hidden): "
  print
fi

[[ "$GOLDKEY_RPC_URL" == https://base-sepolia.g.alchemy.com/v2/* ]] || \
  fail "RPC URL must begin with https://base-sepolia.g.alchemy.com/v2/."

chain_id="$($CAST_BIN chain-id --rpc-url "$GOLDKEY_RPC_URL")"
print -- "RPC chain ID: $chain_id"
[[ "$chain_id" == "84532" ]] || fail "RPC is not Base Sepolia (84532)."

deployer="$($CAST_BIN wallet address --account "$ACCOUNT")"
print -- "Deployer: $deployer"
[[ "${(L)deployer}" == "$EXPECTED_DEPLOYER" ]] || fail "Unexpected deployer address."

usdc_code="$($CAST_BIN code "$USDC" --rpc-url "$GOLDKEY_RPC_URL")"
[[ "$usdc_code" != "0x" ]] || fail "Canonical Base Sepolia USDC has no code."

usdc_decimals="$($CAST_BIN call "$USDC" 'decimals()(uint8)' --rpc-url "$GOLDKEY_RPC_URL")"
[[ "$usdc_decimals" == "6" ]] || fail "USDC decimals are not 6."

terms_hash="$(node scripts/terms-hash.mjs)"
[[ "$terms_hash" == "$EXPECTED_TERMS_HASH" ]] || fail "Local terms hash changed."

local_terms_sha="$(shasum -a 256 TERMS.md | awk '{print $1}')"
live_terms_sha="$(curl -fsSL "$WORKER_ORIGIN/terms" | shasum -a 256 | awk '{print $1}')"
[[ "$local_terms_sha" == "$live_terms_sha" ]] || fail "Live Worker terms differ from the release."

eth_wei="$($CAST_BIN balance "$deployer" --rpc-url "$GOLDKEY_RPC_URL")"
eth_display="$($CAST_BIN balance "$deployer" --ether --rpc-url "$GOLDKEY_RPC_URL")"
(( eth_wei > 0 )) || fail "Deployment wallet has no Base Sepolia ETH."

usdc_result="$($CAST_BIN call "$USDC" 'balanceOf(address)(uint256)' "$deployer" --rpc-url "$GOLDKEY_RPC_URL")"
usdc_atomic="${usdc_result%% *}"

print -- "Terms SHA-256: $local_terms_sha"
print -- "Terms Keccak: $terms_hash"
print -- "ETH: $eth_display"
print -- "USDC atomic: $usdc_atomic"

if (( usdc_atomic < 50000000 )); then
  print -- "Note: 50 test USDC is still required for the acceptance mint; deployment itself can proceed."
fi

print -- "PREFLIGHT PASSED"
