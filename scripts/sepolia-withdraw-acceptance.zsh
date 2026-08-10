#!/bin/zsh

set -euo pipefail

CAST_BIN="/Users/noah-ing/.foundry/bin/cast"
RPC_URL="${GOLDKEY_RPC_URL:-https://sepolia.base.org}"
ACCOUNT="${GOLDKEY_DEPLOYER_ACCOUNT:-goldkey-deployer}"
TREASURY="0xd6b7E00FcD46966676F554fE0455BfF739e85b1b"
CONTRACT="0x220FE98C77CE79baa00d47C5896BE05C2A7D3db0"
USDC="0x036CbD53842c5426634e7929541eC2318f3dCF7e"
EXPECTED_PROCEEDS=50000000

fail() {
  print -u2 -- "WITHDRAWAL ACCEPTANCE STOPPED: $*"
  exit 1
}

first_field() {
  print -r -- "${1%% *}"
}

balance_of() {
  local owner="$1"
  local result
  result="$($CAST_BIN call "$USDC" 'balanceOf(address)(uint256)' "$owner" --rpc-url "$RPC_URL")"
  first_field "$result"
}

if [[ "${1:-}" != "--broadcast" || $# -ne 1 ]]; then
  print -- "Usage: $0 --broadcast"
  print -- "Nothing was sent. The --broadcast flag is required for the Sepolia withdrawal."
  exit 2
fi

[[ -x "$CAST_BIN" ]] || fail "cast was not found at $CAST_BIN"
[[ "$($CAST_BIN chain-id --rpc-url "$RPC_URL")" == "84532" ]] || fail "RPC is not Base Sepolia (chain 84532)"
[[ "$($CAST_BIN code "$CONTRACT" --rpc-url "$RPC_URL")" != "0x" ]] || fail "GoldKey contract code is missing"
onchain_treasury="$($CAST_BIN call "$CONTRACT" 'treasury()(address)' --rpc-url "$RPC_URL")"
[[ "${onchain_treasury:l}" == "${TREASURY:l}" ]] || fail "treasury mismatch: $onchain_treasury"

contract_before="$(balance_of "$CONTRACT")"
treasury_before="$(balance_of "$TREASURY")"
if (( contract_before == 0 && treasury_before >= EXPECTED_PROCEEDS )); then
  print -- "PROCEEDS ALREADY WITHDRAWN — no transaction sent"
  print -- "Contract test USDC: $contract_before"
  print -- "Treasury test USDC: $treasury_before"
  exit 0
fi
[[ "$contract_before" == "$EXPECTED_PROCEEDS" ]] || fail "expected $EXPECTED_PROCEEDS contract test-USDC units; found $contract_before"

simulated="$($CAST_BIN call "$CONTRACT" 'withdrawProceeds()(uint256)' --from "$TREASURY" --rpc-url "$RPC_URL")"
simulated="$(first_field "$simulated")"
[[ "$simulated" == "$contract_before" ]] || fail "withdrawal simulation returned $simulated instead of $contract_before"

print -- "PRECHECK PASSED"
print -- "Withdrawing $contract_before test-USDC units to the immutable onchain treasury..."
"$CAST_BIN" send "$CONTRACT" 'withdrawProceeds()' \
  --account "$ACCOUNT" \
  --rpc-url "$RPC_URL"

contract_after="$contract_before"
treasury_after="$treasury_before"
for (( attempt = 1; attempt <= 30; attempt += 1 )); do
  contract_after="$(balance_of "$CONTRACT" 2>/dev/null || print "$contract_before")"
  treasury_after="$(balance_of "$TREASURY" 2>/dev/null || print "$treasury_before")"
  if (( contract_after == 0 && treasury_after - treasury_before == contract_before )); then
    break
  fi
  (( attempt < 30 )) && sleep 3
done

[[ "$contract_after" == "0" ]] || fail "contract balance has not updated yet; wait and rerun safely"
(( treasury_after - treasury_before == contract_before )) || fail "treasury did not receive the exact proceeds"

print -- "SEPOLIA WITHDRAWAL ACCEPTANCE PASSED"
print -- "Destination: $TREASURY"
print -- "Amount received: $contract_before"
print -- "Contract test USDC remaining: $contract_after"
print -- "Treasury test USDC balance: $treasury_after"
