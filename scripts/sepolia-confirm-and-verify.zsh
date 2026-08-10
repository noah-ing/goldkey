#!/bin/zsh

set -e
set -u
setopt PIPE_FAIL

SCRIPT_DIR="${0:A:h}"
ROOT_DIR="${SCRIPT_DIR:h}"
CAST_BIN="/Users/noah-ing/.foundry/bin/cast"
FORGE_BIN="/Users/noah-ing/.foundry/bin/forge"
RPC_URL="https://sepolia.base.org"
CONTRACT="0x220FE98C77CE79baa00d47C5896BE05C2A7D3db0"
DEPLOYER="0xd6b7E00FcD46966676F554fE0455BfF739e85b1b"
USDC="0x036CbD53842c5426634e7929541eC2318f3dCF7e"
METADATA_BASE_URI="https://goldkey-edge-sepolia.noah-ing.workers.dev/metadata/"
TERMS_URI="https://goldkey-edge-sepolia.noah-ing.workers.dev/terms"
TERMS_HASH="0xd1fb20b0e28b63e18b660a2710f1b69b356bc87829a01cf5d75e572ae7de3750"
TRANSACTION_HASH="0x8e301c6e89df276c69bf24c506b0e253033c53b61def7d4436302fab19a5f156"

fail() {
  print -u2 -- "CONFIRMATION STOPPED: $1"
  exit 1
}

read_call() {
  "$CAST_BIN" call "$CONTRACT" "$1" --rpc-url "$RPC_URL"
}

[[ -x "$CAST_BIN" ]] || fail "Foundry cast is missing."
[[ -x "$FORGE_BIN" ]] || fail "Foundry forge is missing."
[[ "$($CAST_BIN chain-id --rpc-url "$RPC_URL")" == "84532" ]] || \
  fail "Public RPC is not Base Sepolia."

code="0x"
for attempt in {1..10}; do
  code="$($CAST_BIN code "$CONTRACT" --rpc-url "$RPC_URL")"
  [[ "$code" != "0x" ]] && break
  sleep 2
done
[[ "$code" != "0x" ]] || fail "Public Base Sepolia RPC returned no contract bytecode."

owner="$(read_call 'owner()(address)')"
treasury="$(read_call 'treasury()(address)')"
payment_token="$(read_call 'USDC()(address)')"
terms_hash="$(read_call 'LICENSE_TERMS_HASH()(bytes32)')"
mint_price="$(read_call 'MINT_PRICE()(uint256)')"
max_supply="$(read_call 'MAX_SUPPLY()(uint256)')"
calls_per_term="$(read_call 'CALLS_PER_TERM()(uint256)')"
term_seconds="$(read_call 'SERVICE_TERM_SECONDS()(uint256)')"
total_minted="$(read_call 'totalMinted()(uint256)')"
terms_uri="$(read_call 'licenseTermsURI()(string)')"

[[ "${owner:l}" == "${DEPLOYER:l}" ]] || fail "Owner mismatch: $owner"
[[ "${treasury:l}" == "${DEPLOYER:l}" ]] || fail "Treasury mismatch: $treasury"
[[ "${payment_token:l}" == "${USDC:l}" ]] || fail "USDC mismatch: $payment_token"
[[ "${terms_hash:l}" == "${TERMS_HASH:l}" ]] || fail "Terms hash mismatch: $terms_hash"
[[ "${mint_price%% *}" == "50000000" ]] || fail "Mint price mismatch: $mint_price"
[[ "${max_supply%% *}" == "10000" ]] || fail "Maximum supply mismatch: $max_supply"
[[ "${calls_per_term%% *}" == "10000" ]] || fail "Calls-per-term mismatch: $calls_per_term"
[[ "${term_seconds%% *}" == "31536000" ]] || fail "Service term mismatch: $term_seconds"
[[ "${total_minted%% *}" == "0" ]] || fail "Unexpected minted supply: $total_minted"
terms_uri="${terms_uri#\"}"
terms_uri="${terms_uri%\"}"
[[ "$terms_uri" == "$TERMS_URI" ]] || fail "Terms URI mismatch: $terms_uri"

print -- "ON-CHAIN CONTRACT CONFIRMED"
print -- "Contract: $CONTRACT"
print -- "Transaction: $TRANSACTION_HASH"
print -- "Runtime bytecode: ${#code} hexadecimal characters"
print -- "Owner/treasury: $DEPLOYER"
print -- "Price/supply/quota/term: 50 USDC / 10,000 / 10,000 / 365 days"

constructor_args="$($CAST_BIN abi-encode \
  'constructor(address,address,address,string,string,bytes32)' \
  "$DEPLOYER" \
  "$USDC" \
  "$DEPLOYER" \
  "$METADATA_BASE_URI" \
  "$TERMS_URI" \
  "$TERMS_HASH")"

cd "$ROOT_DIR/contracts"

print -- "Submitting public source verification to Blockscout..."
"$FORGE_BIN" verify-contract \
  "$CONTRACT" \
  src/GoldKey.sol:GoldKey \
  --chain 84532 \
  --rpc-url "$RPC_URL" \
  --verifier blockscout \
  --verifier-url https://base-sepolia.blockscout.com/api/ \
  --compiler-version v0.8.24+commit.e11b9ed9 \
  --num-of-optimizations 10000 \
  --evm-version cancun \
  --watch \
  --constructor-args "$constructor_args"

print -- "SOURCE VERIFICATION COMPLETE"
print -- "Explorer: https://base-sepolia.blockscout.com/address/$CONTRACT?tab=contract"
