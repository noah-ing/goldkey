#!/bin/zsh

set -euo pipefail

CAST_BIN="/Users/noah-ing/.foundry/bin/cast"
RPC_URL="${GOLDKEY_RPC_URL:-https://sepolia.base.org}"
ACCOUNT="${GOLDKEY_DEPLOYER_ACCOUNT:-goldkey-deployer}"
BUYER="0xd6b7E00FcD46966676F554fE0455BfF739e85b1b"
CONTRACT="0x220FE98C77CE79baa00d47C5896BE05C2A7D3db0"
USDC="0x036CbD53842c5426634e7929541eC2318f3dCF7e"
PRICE_ATOMIC=50000000
ZERO_ADDRESS="0x0000000000000000000000000000000000000000"

fail() {
  print -u2 -- "ACCEPTANCE MINT STOPPED: $*"
  exit 1
}

first_field() {
  print -r -- "${1%% *}"
}

read_contract() {
  "$CAST_BIN" call "$CONTRACT" "$@" --rpc-url "$RPC_URL"
}

read_usdc() {
  "$CAST_BIN" call "$USDC" "$@" --rpc-url "$RPC_URL"
}

current_allowance() {
  local result
  result="$(read_usdc 'allowance(address,address)(uint256)' "$BUYER" "$CONTRACT" 2>/dev/null || print 0)"
  first_field "$result"
}

wait_for_allowance() {
  local attempts="$1"
  local delay_seconds="$2"
  local observed=0
  local attempt
  for (( attempt = 1; attempt <= attempts; attempt += 1 )); do
    observed="$(current_allowance)"
    if (( observed >= PRICE_ATOMIC )); then
      allowance="$observed"
      return 0
    fi
    (( attempt < attempts )) && sleep "$delay_seconds"
  done
  allowance="$observed"
  return 1
}

if [[ "${1:-}" != "--broadcast" || $# -ne 1 ]]; then
  print -- "Usage: $0 --broadcast"
  print -- "Nothing was sent. The --broadcast flag is required for the Sepolia approval and mint."
  exit 2
fi

[[ -x "$CAST_BIN" ]] || fail "cast was not found at $CAST_BIN"
[[ "$($CAST_BIN chain-id --rpc-url "$RPC_URL")" == "84532" ]] || fail "RPC is not Base Sepolia (chain 84532)"
[[ "$($CAST_BIN code "$CONTRACT" --rpc-url "$RPC_URL")" != "0x" ]] || fail "GoldKey contract code is missing"
[[ "$($CAST_BIN code "$USDC" --rpc-url "$RPC_URL")" != "0x" ]] || fail "canonical test USDC code is missing"

[[ "$(first_field "$(read_contract 'MINT_PRICE()(uint256)')")" == "$PRICE_ATOMIC" ]] || fail "mint price mismatch"
[[ "$(first_field "$(read_contract 'MAX_SUPPLY()(uint256)')")" == "10000" ]] || fail "max supply mismatch"
[[ "$(first_field "$(read_contract 'CALLS_PER_TERM()(uint256)')")" == "10000" ]] || fail "calls-per-term mismatch"
[[ "$(first_field "$(read_contract 'SERVICE_TERM_SECONDS()(uint256)')")" == "31536000" ]] || fail "term length mismatch"
[[ "$(first_field "$(read_contract 'salesPaused()(bool)')")" == "false" ]] || fail "primary sales are paused"
[[ "${$(first_field "$(read_contract 'USDC()(address)')"):l}" == "${USDC:l}" ]] || fail "payment-token mismatch"
[[ "${$(first_field "$(read_contract 'treasury()(address)')"):l}" == "${BUYER:l}" ]] || fail "treasury mismatch"

total_before="$(first_field "$(read_contract 'totalMinted()(uint256)')")"
if (( total_before > 0 )); then
  token_one_state="$(read_contract 'accessState(uint256)(address,uint256,uint256,uint256,bool)' 2>/dev/null || true)"
  token_one_lines=("${(@f)token_one_state}")
  token_one_owner="${token_one_lines[1]:-$ZERO_ADDRESS}"
  token_one_owner="$(first_field "$token_one_owner")"
  token_one_active="$(first_field "${token_one_lines[5]:-false}")"
  if [[ "${token_one_owner:l}" == "${BUYER:l}" && "$token_one_active" == "true" ]]; then
    print -- "TOKEN #1 ALREADY MINTED — no transaction sent"
    print -- "Owner: $token_one_owner"
    print -- "Total minted: $total_before"
    exit 0
  fi
  fail "totalMinted is $total_before and token #1 is not the expected active buyer pass"
fi

token_one_state="$(read_contract 'accessState(uint256)(address,uint256,uint256,uint256,bool)' 1)"
token_one_lines=("${(@f)token_one_state}")
token_one_owner="$(first_field "${token_one_lines[1]:-$ZERO_ADDRESS}")"
token_one_active="$(first_field "${token_one_lines[5]:-false}")"
[[ "${token_one_owner:l}" == "${ZERO_ADDRESS:l}" && "$token_one_active" == "false" ]] || fail "token #1 already has state"

buyer_usdc_before="$(first_field "$(read_usdc 'balanceOf(address)(uint256)' "$BUYER")")"
(( buyer_usdc_before >= PRICE_ATOMIC )) || fail "buyer needs $PRICE_ATOMIC test-USDC units; found $buyer_usdc_before"
contract_usdc_before="$(first_field "$(read_usdc 'balanceOf(address)(uint256)' "$CONTRACT")")"
allowance="$(current_allowance)"

print -- "PRECHECK PASSED"
print -- "Buyer test USDC: $buyer_usdc_before"
print -- "Current allowance: $allowance"
print -- "You may be prompted for the encrypted keystore password for each transaction."

if (( allowance < PRICE_ATOMIC )); then
  print -- "Waiting briefly for any recently mined approval to become visible..."
  if wait_for_allowance 10 3; then
    print -- "Existing approval is now visible; no approval transaction needed."
  else
    print -- "Approving exactly $PRICE_ATOMIC test-USDC units..."
    "$CAST_BIN" send "$USDC" 'approve(address,uint256)' "$CONTRACT" "$PRICE_ATOMIC" \
      --account "$ACCOUNT" \
      --rpc-url "$RPC_URL"
    print -- "Waiting for the approval state to propagate across the RPC..."
    wait_for_allowance 30 3 || fail "approval transaction was sent but allowance is not visible yet; wait and rerun safely"
  fi
else
  print -- "Approval already sufficient; skipping approval transaction."
fi

[[ "$(first_field "$(read_contract 'totalMinted()(uint256)')")" == "$total_before" ]] || fail "supply changed before mint; inspect chain state before retrying"
simulated_first_id="$($CAST_BIN call "$CONTRACT" 'mint(address,uint256)(uint256)' "$BUYER" 1 --from "$BUYER" --rpc-url "$RPC_URL")"
simulated_first_id="$(first_field "$simulated_first_id")"
[[ "$simulated_first_id" == "1" ]] || fail "mint simulation returned unexpected first token ID $simulated_first_id"

print -- "Mint simulation passed. Minting exactly one GoldKey..."
"$CAST_BIN" send "$CONTRACT" 'mint(address,uint256)' "$BUYER" 1 \
  --account "$ACCOUNT" \
  --rpc-url "$RPC_URL"

total_after="$(first_field "$(read_contract 'totalMinted()(uint256)')")"
[[ "$total_after" == "1" ]] || fail "unexpected totalMinted after transaction: $total_after"
owner_after="$(first_field "$(read_contract 'ownerOf(uint256)(address)' 1)")"
[[ "${owner_after:l}" == "${BUYER:l}" ]] || fail "token #1 owner mismatch: $owner_after"

state_after="$(read_contract 'accessState(uint256)(address,uint256,uint256,uint256,bool)' 1)"
state_lines=("${(@f)state_after}")
state_owner="$(first_field "${state_lines[1]}")"
state_term="$(first_field "${state_lines[2]}")"
state_expiry="$(first_field "${state_lines[3]}")"
state_epoch="$(first_field "${state_lines[4]}")"
state_active="$(first_field "${state_lines[5]}")"
[[ "${state_owner:l}" == "${BUYER:l}" ]] || fail "accessState owner mismatch"
[[ "$state_term" == "1" ]] || fail "accessState term mismatch: $state_term"
[[ "$state_epoch" == "0" ]] || fail "accessState ownership epoch mismatch: $state_epoch"
[[ "$state_active" == "true" ]] || fail "token #1 is not active"

buyer_usdc_after="$(first_field "$(read_usdc 'balanceOf(address)(uint256)' "$BUYER")")"
contract_usdc_after="$(first_field "$(read_usdc 'balanceOf(address)(uint256)' "$CONTRACT")")"
(( buyer_usdc_before - buyer_usdc_after == PRICE_ATOMIC )) || fail "buyer USDC debit was not exactly $PRICE_ATOMIC"
(( contract_usdc_after - contract_usdc_before == PRICE_ATOMIC )) || fail "contract USDC credit was not exactly $PRICE_ATOMIC"

curl -fsS --max-time 30 "https://goldkey-edge-sepolia.noah-ing.workers.dev/metadata/1" >/dev/null \
  || fail "token metadata endpoint did not resolve"

print -- "SEPOLIA ACCEPTANCE MINT PASSED"
print -- "Token ID: 1"
print -- "Owner: $owner_after"
print -- "Term: $state_term"
print -- "Ownership epoch: $state_epoch"
print -- "Expires at (Unix seconds): $state_expiry"
print -- "Total minted: $total_after"
print -- "Buyer test USDC remaining: $buyer_usdc_after"
print -- "Contract test USDC received: $contract_usdc_after"
