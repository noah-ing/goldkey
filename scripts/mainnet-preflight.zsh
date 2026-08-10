#!/bin/zsh

set -e
set -u
setopt PIPE_FAIL

SCRIPT_DIR="${0:A:h}"
ROOT_DIR="${SCRIPT_DIR:h}"
CAST_BIN="/Users/noah-ing/.foundry/bin/cast"
FORGE_BIN="/Users/noah-ing/.foundry/bin/forge"
CHAIN_ID="8453"
DEPLOYER="0xd6b7E00FcD46966676F554fE0455BfF739e85b1b"
USDC="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
WORKER_ORIGIN="https://goldkey-edge-storefront.noah-ing.workers.dev"
METADATA_BASE_URI="${WORKER_ORIGIN}/metadata/"
TERMS_URI="${WORKER_ORIGIN}/terms"
TERMS_HASH="0xd1fb20b0e28b63e18b660a2710f1b69b356bc87829a01cf5d75e572ae7de3750"
GAS_PRICE_ORACLE="0x420000000000000000000000000000000000000F"
ARTIFACT="${ROOT_DIR}/contracts/out/GoldKey.sol/GoldKey.json"
RPC_URL=""
LIVE_TERMS=""

fail() {
  print -u2 -- "MAINNET PREFLIGHT STOPPED: $1"
  exit 1
}

decimal_result() {
  local value="${1%% *}"
  [[ "$value" == <-> ]] || fail "Expected a decimal RPC result; received: ${1[1,80]}"
  print -r -- "$value"
}

rpc_cast() {
  ETH_RPC_URL="$RPC_URL" "$CAST_BIN" "$@"
}

cleanup() {
  unset RPC_URL
  if [[ -n "$LIVE_TERMS" && -f "$LIVE_TERMS" ]]; then
    rm -f -- "$LIVE_TERMS"
  fi
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

[[ "$#" == "0" ]] || fail "This command takes no arguments or signer material."
[[ -x "$CAST_BIN" ]] || fail "Foundry cast is missing."
[[ -x "$FORGE_BIN" ]] || fail "Foundry forge is missing."
command -v node >/dev/null || fail "Node.js is missing."
command -v curl >/dev/null || fail "curl is missing."
command -v cmp >/dev/null || fail "cmp is missing."

# Explicitly prevent inherited signer settings from reaching any subprocess.
unset ETH_PRIVATE_KEY PRIVATE_KEY ETH_KEYSTORE ETH_KEYSTORE_ACCOUNT ETH_PASSWORD \
  ETH_PASSWORD_FILE MNEMONIC MNEMONIC_PATH ETH_MNEMONIC ETH_MNEMONIC_PATH ETH_FROM \
  ETH_RPC_URL 2>/dev/null || true

cd "$ROOT_DIR"

local_terms_hash="$(node scripts/terms-hash.mjs)"
[[ "$local_terms_hash" == "$TERMS_HASH" ]] || fail "Local TERMS.md no longer has the frozen hash."

LIVE_TERMS="$(mktemp -t goldkey-mainnet-terms.XXXXXX)"
curl --fail --silent --show-error --location --max-time 30 \
  --proto '=https' --tlsv1.2 "$TERMS_URI" --output "$LIVE_TERMS" || \
  fail "Could not download the permanent storefront terms."
cmp -s "$ROOT_DIR/TERMS.md" "$LIVE_TERMS" || \
  fail "Live storefront terms are not byte-identical to local TERMS.md."

"$FORGE_BIN" build --root "$ROOT_DIR/contracts" --offline --force >/dev/null || \
  fail "The frozen GoldKey contract did not compile offline."
[[ -f "$ARTIFACT" ]] || fail "Compiled GoldKey artifact is missing."

input_lines=("${(@f)$(node scripts/mainnet-preflight-data.mjs input "$ARTIFACT")}")
[[ "${#input_lines}" == "5" ]] || fail "Could not build the exact deployment input."
init_code="${input_lines[1]}"
init_code_hash="${input_lines[2]}"
creation_bytecode_hash="${input_lines[3]}"
init_code_bytes="${input_lines[4]}"
creation_bytecode_bytes="${input_lines[5]}"

print -- "STATIC RELEASE VERIFIED"
print -- "Origin: $WORKER_ORIGIN"
print -- "Terms: exact byte match"
print -- "Terms Keccak: $TERMS_HASH"
print -- "Creation bytecode: ${creation_bytecode_bytes} bytes / $creation_bytecode_hash"
print -- "Exact init code: ${init_code_bytes} bytes / $init_code_hash"
print

read -rs "RPC_URL?Paste the Alchemy Base mainnet HTTPS RPC URL (hidden): "
print
[[ "$RPC_URL" =~ '^https://base-mainnet\.g\.alchemy\.com/v2/[A-Za-z0-9_-]+$' ]] || \
  fail "RPC must be an Alchemy Base mainnet /v2 HTTPS URL."

chain_id="$(rpc_cast chain-id)"
[[ "$chain_id" == "$CHAIN_ID" ]] || fail "RPC chain ID is $chain_id, not Base mainnet 8453."

usdc_code="$(rpc_cast code "$USDC")"
[[ "$usdc_code" != "0x" ]] || fail "Canonical Base USDC has no bytecode."
usdc_decimals="$(rpc_cast call "$USDC" 'decimals()(uint8)')"
[[ "$(decimal_result "$usdc_decimals")" == "6" ]] || fail "Canonical Base USDC decimals are not 6."
oracle_code="$(rpc_cast code "$GAS_PRICE_ORACLE")"
[[ "$oracle_code" != "0x" ]] || fail "Base GasPriceOracle has no bytecode."

deployer_code="$(rpc_cast code "$DEPLOYER")"
[[ "$deployer_code" == "0x" ]] || fail "The dedicated deployer is no longer an EOA."
latest_nonce="$(rpc_cast nonce "$DEPLOYER" --block latest)"
pending_nonce="$(rpc_cast nonce "$DEPLOYER" --block pending)"
[[ "$latest_nonce" == "$pending_nonce" ]] || \
  fail "The deployer has a pending transaction; its contract address is not stable."
predicted_line="$($CAST_BIN compute-address "$DEPLOYER" --nonce "$pending_nonce")"
predicted_contract="${predicted_line##* }"
[[ "$predicted_contract" =~ '^0x[0-9a-fA-F]{40}$' ]] || fail "Could not derive the contract address."
[[ "$(rpc_cast code "$predicted_contract")" == "0x" ]] || \
  fail "The next deployment address already contains bytecode."

gas_raw="$(rpc_cast estimate --from "$DEPLOYER" --create "$init_code")" || \
  fail "Base rejected the read-only creation simulation."
gas_estimate="$(decimal_result "$gas_raw")"
gas_price_raw="$(rpc_cast gas-price)"
gas_price="$(decimal_result "$gas_price_raw")"

sizing_lines=("${(@f)$(node scripts/mainnet-preflight-data.mjs sizing "$gas_estimate" "$gas_price")}")
[[ "${#sizing_lines}" == "2" ]] || fail "Could not calculate transaction sizing."
gas_limit="${sizing_lines[1]}"
fee_cap="${sizing_lines[2]}"

unsigned_tx="$($CAST_BIN mktx --raw-unsigned --chain "$CHAIN_ID" \
  --nonce "$pending_nonce" --gas-limit "$gas_limit" --gas-price "$fee_cap" \
  --priority-gas-price "$gas_price" --create "$init_code")"
[[ "$unsigned_tx" =~ '^0x[0-9a-fA-F]+$' ]] || fail "Could not serialize the unsigned deployment."
unsigned_tx_bytes=$(( (${#unsigned_tx} - 2) / 2 ))

l1_estimate_raw="$(rpc_cast call "$GAS_PRICE_ORACLE" 'getL1Fee(bytes)(uint256)' \
  "$unsigned_tx")"
l1_estimate="$(decimal_result "$l1_estimate_raw")"
l1_upper_raw="$(rpc_cast call "$GAS_PRICE_ORACLE" 'getL1FeeUpperBound(uint256)(uint256)' \
  "$unsigned_tx_bytes")"
l1_upper="$(decimal_result "$l1_upper_raw")"
balance_raw="$(rpc_cast balance "$DEPLOYER")"
balance="$(decimal_result "$balance_raw")"

budget_lines=("${(@f)$(node scripts/mainnet-preflight-data.mjs budget \
  "$gas_estimate" "$gas_price" "$l1_estimate" "$l1_upper" "$balance")}")
[[ "${#budget_lines}" == "9" ]] || fail "Could not calculate the funding budget."
current_execution="${budget_lines[3]}"
current_total="${budget_lines[4]}"
l1_budget="${budget_lines[5]}"
pre_margin_budget="${budget_lines[6]}"
required="${budget_lines[7]}"
shortfall="${budget_lines[8]}"
result="${budget_lines[9]}"

print -- "READ-ONLY BASE MAINNET SIMULATION"
print -- "Chain: $CHAIN_ID"
print -- "Deployer / owner / treasury: $DEPLOYER"
print -- "Canonical USDC: $USDC"
print -- "Metadata base: $METADATA_BASE_URI"
print -- "Terms URI: $TERMS_URI"
print -- "Deployer nonce: $pending_nonce"
print -- "Predicted contract: $predicted_contract"
print -- "Estimated execution gas: $gas_estimate"
print -- "Budget gas limit (20% buffer): $gas_limit"
print -- "Current gas price: $gas_price wei"
print -- "Budget fee cap (2x current): $fee_cap wei"
print -- "Unsigned transaction: $unsigned_tx_bytes bytes"
print -- "Current execution estimate: $current_execution wei"
print -- "Current L1 data-fee estimate: $l1_estimate wei"
print -- "L1 data-fee budget: $l1_budget wei"
print -- "Current total estimate: $current_total wei ($($CAST_BIN from-wei "$current_total") ETH)"
print -- "Pre-margin budget: $pre_margin_budget wei"
print -- "Required with final 25% margin: $required wei ($($CAST_BIN from-wei "$required") ETH)"
print -- "Current deployer balance: $balance wei ($($CAST_BIN from-wei "$balance") ETH)"

if [[ "$result" == "FUNDED" ]]; then
  print -- "RESULT: FUNDED"
  print -- "This command compiled and simulated only; it had no signer and sent no transaction."
  exit 0
fi

print -- "RESULT: SHORT by $shortfall wei ($($CAST_BIN from-wei "$shortfall") ETH)"
print -- "Do not deploy. Re-run this command after the one-time faucet claim is confirmed."
exit 2
