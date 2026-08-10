# Offline sponsored CREATE2 deployment

This helper builds the exact GoldKey creation code, deterministic address, and factory call
needed by an EIP-7702/CDP sponsored user operation. It is deliberately incapable of signing or
sending a transaction.

The fixed Base `Create2Deployer` is:

```text
0x13b0D85CcB8bf860b6b79AF3029fCA081AE9beF2
```

The only factory function used is:

```solidity
deploy(uint256 value, bytes32 salt, bytes code)
```

GoldKey uses `value = 0`. Its constructor receives explicit owner and treasury addresses, so the
factory never receives either role.

## Networkless Sepolia dry run

Build the contract artifact and run the deterministic sample:

```sh
npm run test:contract
npm run deployment:create2:dry-run
```

The sample uses unmistakable placeholder owner and treasury addresses, `.invalid` metadata URLs,
Circle's Base Sepolia USDC, the current `TERMS.md` hash, and a fixed sample salt. It makes no RPC,
CDP, wallet, or paymaster request. To save the full JSON without overwriting an existing file:

```sh
node scripts/build-create2-deployment.mjs --sample-sepolia \
  --out /tmp/goldkey-create2-sepolia-sample.json
```

## Real offline manifest inputs

Set only public deployment values. Do not set a private key, RPC URL, wallet secret, or paymaster
URL for this command.

| Variable | Required | Meaning |
|---|---:|---|
| `GOLDKEY_NETWORK` | yes | `base-sepolia` or `base` |
| `GOLDKEY_OWNER` | yes | Initial owner, normally the already-deployed or predicted owner Safe |
| `GOLDKEY_TREASURY` | yes | Initial proceeds treasury Safe |
| `GOLDKEY_METADATA_BASE_URI` | yes | HTTPS token metadata base ending in `/` |
| `GOLDKEY_TERMS_URI` | yes | HTTPS license terms URL |
| `GOLDKEY_TERMS_HASH` | yes | Nonzero bytes32 hash printed by `node scripts/terms-hash.mjs` |
| `GOLDKEY_CREATE2_SALT` | yes | Explicit nonzero bytes32 salt; changing it changes the address |
| `GOLDKEY_USDC` | no | If set, must equal canonical Circle USDC for the selected network |
| `GOLDKEY_ARTIFACT` | no | Foundry artifact path; defaults to `contracts/out/GoldKey.sol/GoldKey.json` |

Example for Base Sepolia:

```sh
export GOLDKEY_NETWORK="base-sepolia"
export GOLDKEY_OWNER="<predicted or deployed Sepolia owner Safe>"
export GOLDKEY_TREASURY="<predicted or deployed Sepolia treasury Safe>"
export GOLDKEY_METADATA_BASE_URI="https://testnet-api.<your-domain>/metadata/"
export GOLDKEY_TERMS_URI="https://testnet-api.<your-domain>/terms"
export GOLDKEY_TERMS_HASH="$(node scripts/terms-hash.mjs)"
export GOLDKEY_CREATE2_SALT="$(cast keccak 'goldkey-v1-base-sepolia')"

node scripts/build-create2-deployment.mjs \
  --out /tmp/goldkey-create2-sepolia.json
```

Use a deployment-specific salt label and record it with the manifest. The output file contains no
secret, but it is a launch record and should be retained with the verified constructor arguments.
The command refuses to overwrite an existing output file.

## Output and CDP handoff

The JSON contains:

- the compiled creation-bytecode hash and compiler settings;
- ABI-encoded constructor arguments for source verification;
- complete GoldKey `initCode` and its hash;
- the CREATE2 salt and predicted GoldKey address;
- the exact Base factory selector and calldata;
- `cdpUserOperation.calls`, using CDP's decimal-string value format;
- `walletSendCalls.calls`, using EIP-5792's hex value format;
- the factory address/function to add to the CDP Paymaster policy.

The manifest intentionally omits `from`, signatures, the Paymaster URL, and CDP credentials. A
runtime controlled by the delegated account must add those. If the owner Safe deployment and
GoldKey deployment are meant to be atomic, prepend Safe Protocol Kit's deployment call to the
manifest's call and keep the GoldKey constructor pointed at the predicted Safe address.

Before requesting sponsorship:

1. Re-run the real builder twice and confirm identical manifest hashes.
2. On Base Sepolia, confirm the fixed factory has code and the predicted address has none.
3. Simulate the complete user operation, including any Safe deployment call.
4. Allowlist only the fixed factory and `deploy(uint256,bytes32,bytes)` plus any required Safe
   factory call.
5. Limit the policy to one UserOperation and a small global/per-operation USD ceiling.
6. Submit through the CDP Bundler/Paymaster, not `forge create`.
7. Confirm the deployed runtime code, `owner()`, `treasury()`, `USDC()`, terms hash, and predicted
   address before disabling the deployment policy.

The factory method accepts arbitrary creation code. Never expose an active unrestricted Paymaster
URL, and disable the one-shot deployment policy immediately after use.

## Verification

Factory deployment does not prevent Foundry verification. Use the manifest's
`constructor.encodedArguments`, deployed address, exact compiler configuration, and the appropriate
Blockscout verifier. `forge create` is not used because it produces a conventional EOA contract
creation transaction that CDP Paymaster cannot sponsor.
