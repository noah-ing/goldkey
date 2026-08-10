#!/bin/zsh

set -e
set -u
setopt PIPE_FAIL

SCRIPT_DIR="${0:A:h}"
ROOT_DIR="${SCRIPT_DIR:h}"
CAST_BIN="/Users/noah-ing/.foundry/bin/cast"
FORGE_BIN="/Users/noah-ing/.foundry/bin/forge"
CHAIN_ID="8453"
CONTRACT="0x220FE98C77CE79baa00d47C5896BE05C2A7D3db0"
DEPLOYER="0xd6b7E00FcD46966676F554fE0455BfF739e85b1b"
USDC="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
METADATA_BASE_URI="https://goldkey-edge-storefront.noah-ing.workers.dev/metadata/"
TERMS_URI="https://goldkey-edge-storefront.noah-ing.workers.dev/terms"
TERMS_HASH="0xd1fb20b0e28b63e18b660a2710f1b69b356bc87829a01cf5d75e572ae7de3750"
TRANSACTION_HASH="0x94b0dd9f5bbb93216aea85e1384c5592372e3dcf1ab5da04e51c5f48c6e022c6"
INIT_CODE_HASH="0x1ac4675966261ebcbc30b6be393f97142756a15c48c303f82e9af27149ea1d0c"
EXPECTED_RUNTIME_BYTES="10329"
ARTIFACT="${ROOT_DIR}/contracts/out/GoldKey.sol/GoldKey.json"
RPC_URL=""

fail() {
  print -u2 -- "MAINNET CONFIRMATION STOPPED: $1"
  exit 1
}

decimal_result() {
  local value="${1%% *}"
  [[ "$value" == <-> ]] || fail "Expected a decimal result; received: ${1[1,80]}"
  print -r -- "$value"
}

rpc_cast() {
  ETH_RPC_URL="$RPC_URL" "$CAST_BIN" "$@"
}

read_call() {
  rpc_cast call "$CONTRACT" "$1"
}

cleanup() {
  unset RPC_URL
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

[[ "$#" == "0" ]] || fail "This command takes no arguments."
[[ -x "$CAST_BIN" ]] || fail "Foundry cast is missing."
[[ -x "$FORGE_BIN" ]] || fail "Foundry forge is missing."

# This verification command must never inherit signer material.
unset ETH_PRIVATE_KEY PRIVATE_KEY ETH_KEYSTORE ETH_KEYSTORE_ACCOUNT ETH_PASSWORD \
  ETH_PASSWORD_FILE MNEMONIC MNEMONIC_PATH ETH_MNEMONIC ETH_MNEMONIC_PATH ETH_FROM \
  ETH_RPC_URL 2>/dev/null || true

cd "$ROOT_DIR"
[[ "$(node scripts/terms-hash.mjs)" == "$TERMS_HASH" ]] || fail "Frozen terms changed."
"$FORGE_BIN" build --root "$ROOT_DIR/contracts" --offline --force >/dev/null || \
  fail "The frozen GoldKey source did not compile offline."
[[ -f "$ARTIFACT" ]] || fail "Compiled GoldKey artifact is missing."
input_lines=("${(@f)$(node scripts/mainnet-preflight-data.mjs input "$ARTIFACT")}")
[[ "${#input_lines}" == "5" && "${input_lines[2]}" == "$INIT_CODE_HASH" ]] || \
  fail "Local source no longer builds the deployed creation input."

read -rs "RPC_URL?Paste the Alchemy Base mainnet HTTPS RPC URL (hidden): "
print
[[ "$RPC_URL" =~ '^https://base-mainnet\.g\.alchemy\.com/v2/[A-Za-z0-9_-]+$' ]] || \
  fail "RPC must be an Alchemy Base mainnet /v2 HTTPS URL."

[[ "$(rpc_cast chain-id)" == "$CHAIN_ID" ]] || fail "RPC is not Base mainnet (8453)."

receipt_status="$(rpc_cast receipt "$TRANSACTION_HASH" status)"
receipt_status_value="${receipt_status%% *}"
[[ "$receipt_status_value" == "1" || "$receipt_status_value" == "0x1" ]] || \
  fail "Creation receipt is not successful: $receipt_status"
receipt_contract="$(rpc_cast receipt "$TRANSACTION_HASH" contractAddress)"
[[ "${receipt_contract:l}" == "${CONTRACT:l}" ]] || \
  fail "Receipt contract address mismatch: $receipt_contract"

tx_from="$(rpc_cast tx "$TRANSACTION_HASH" from)"
tx_to="$(rpc_cast tx "$TRANSACTION_HASH" to)"
tx_value="$(rpc_cast tx "$TRANSACTION_HASH" value)"
tx_nonce="$(rpc_cast tx "$TRANSACTION_HASH" nonce)"
tx_input="$(rpc_cast tx "$TRANSACTION_HASH" input)"

[[ "${tx_from:l}" == "${DEPLOYER:l}" ]] || fail "Creation sender mismatch: $tx_from"
[[ "$tx_to" == "null" || "$tx_to" == "" ]] || fail "Creation transaction unexpectedly has a recipient: $tx_to"
[[ "$(decimal_result "$tx_value")" == "0" ]] || fail "Creation transaction sent ETH."
[[ "$(decimal_result "$tx_nonce")" == "0" ]] || fail "Creation nonce is not zero."
tx_input_bytes=$(( (${#tx_input} - 2) / 2 ))
[[ "$tx_input_bytes" == "12387" ]] || fail "Creation input length mismatch: $tx_input_bytes bytes"
[[ "$($CAST_BIN keccak "$tx_input")" == "$INIT_CODE_HASH" ]] || fail "Creation input hash mismatch."

code="$(rpc_cast code "$CONTRACT")"
[[ "$code" != "0x" ]] || fail "No runtime bytecode exists at the GoldKey address."
runtime_bytes=$(( (${#code} - 2) / 2 ))
[[ "$runtime_bytes" == "$EXPECTED_RUNTIME_BYTES" ]] || \
  fail "Runtime bytecode length mismatch: $runtime_bytes bytes"
latest_nonce="$(rpc_cast nonce "$DEPLOYER" --block latest)"
pending_nonce="$(rpc_cast nonce "$DEPLOYER" --block pending)"
[[ "$latest_nonce" == "1" && "$pending_nonce" == "1" ]] || \
  fail "Deployer nonce is not settled at one: latest=$latest_nonce pending=$pending_nonce"

owner="$(read_call 'owner()(address)')"
treasury="$(read_call 'treasury()(address)')"
payment_token="$(read_call 'USDC()(address)')"
terms_hash="$(read_call 'LICENSE_TERMS_HASH()(bytes32)')"
mint_price="$(read_call 'MINT_PRICE()(uint256)')"
max_supply="$(read_call 'MAX_SUPPLY()(uint256)')"
max_mint_quantity="$(read_call 'MAX_MINT_QUANTITY()(uint256)')"
calls_per_term="$(read_call 'CALLS_PER_TERM()(uint256)')"
term_seconds="$(read_call 'SERVICE_TERM_SECONDS()(uint256)')"
total_minted="$(read_call 'totalMinted()(uint256)')"
sales_paused="$(read_call 'salesPaused()(bool)')"
terms_uri="$(read_call 'licenseTermsURI()(string)')"
usdc_decimals="$(rpc_cast call "$USDC" 'decimals()(uint8)')"
contract_usdc_balance="$(rpc_cast call "$USDC" 'balanceOf(address)(uint256)' "$CONTRACT")"
[[ "$(rpc_cast code "$USDC")" != "0x" ]] || fail "Canonical Base USDC has no bytecode."

[[ "${owner:l}" == "${DEPLOYER:l}" ]] || fail "Owner mismatch: $owner"
[[ "${treasury:l}" == "${DEPLOYER:l}" ]] || fail "Treasury mismatch: $treasury"
[[ "${payment_token:l}" == "${USDC:l}" ]] || fail "USDC mismatch: $payment_token"
[[ "${terms_hash:l}" == "${TERMS_HASH:l}" ]] || fail "Terms hash mismatch: $terms_hash"
[[ "$(decimal_result "$mint_price")" == "50000000" ]] || fail "Mint price mismatch: $mint_price"
[[ "$(decimal_result "$max_supply")" == "10000" ]] || fail "Maximum supply mismatch: $max_supply"
[[ "$(decimal_result "$max_mint_quantity")" == "20" ]] || fail "Maximum mint quantity mismatch: $max_mint_quantity"
[[ "$(decimal_result "$calls_per_term")" == "10000" ]] || fail "Calls-per-term mismatch: $calls_per_term"
[[ "$(decimal_result "$term_seconds")" == "31536000" ]] || fail "Service term mismatch: $term_seconds"
[[ "$(decimal_result "$total_minted")" == "0" ]] || fail "Unexpected mainnet minted supply: $total_minted"
[[ "$sales_paused" == "false" ]] || fail "Mainnet sales are paused."
[[ "$(decimal_result "$usdc_decimals")" == "6" ]] || fail "Canonical USDC decimals mismatch."
[[ "$(decimal_result "$contract_usdc_balance")" == "0" ]] || \
  fail "Fresh GoldKey contract unexpectedly holds USDC."
terms_uri="${terms_uri#\"}"
terms_uri="${terms_uri%\"}"
[[ "$terms_uri" == "$TERMS_URI" ]] || fail "Terms URI mismatch: $terms_uri"

print -- "MAINNET CONTRACT CONFIRMED"
print -- "Contract: $CONTRACT"
print -- "Transaction: $TRANSACTION_HASH"
print -- "Creation input: 12,387 bytes / $INIT_CODE_HASH"
print -- "Runtime bytecode: $runtime_bytes bytes"
print -- "Owner/treasury: $DEPLOYER"
print -- "Price/supply/quota/term: 50 USDC / 10,000 / 10,000 / 365 days"
print -- "Total minted: 0"
print -- "Deployer nonce: 1 (settled)"
print

constructor_args="$($CAST_BIN abi-encode \
  'constructor(address,address,address,string,string,bytes32)' \
  "$DEPLOYER" \
  "$USDC" \
  "$DEPLOYER" \
  "$METADATA_BASE_URI" \
  "$TERMS_URI" \
  "$TERMS_HASH")"

cd "$ROOT_DIR/contracts"

print -- "Submitting public source verification to Base Blockscout..."
if ! "$FORGE_BIN" verify-contract \
  "$CONTRACT" \
  src/GoldKey.sol:GoldKey \
  --chain "$CHAIN_ID" \
  --rpc-url "$RPC_URL" \
  --verifier blockscout \
  --verifier-url https://base.blockscout.com/api/ \
  --compiler-version v0.8.24+commit.e11b9ed9 \
  --num-of-optimizations 10000 \
  --evm-version cancun \
  --constructor-args "$constructor_args" \
  --watch \
  --retries 8 \
  --delay 15; then
  print -u2 -- "ONCHAIN CONFIRMED; SOURCE VERIFICATION PENDING."
  print -u2 -- "Rerun this confirmation script later; never rerun the deployment command."
  exit 3
fi

print -- "MAINNET SOURCE VERIFICATION COMPLETE"
print -- "Explorer: https://base.blockscout.com/address/$CONTRACT?tab=contract"
