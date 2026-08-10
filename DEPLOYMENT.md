# GoldKey deployment runbook

This runbook deliberately separates testnet validation from real-money deployment.

## 0. Launch inputs

Do not paste private keys or CDP secrets into chat, source control, shell history, or a deployment log. Before deployment, prepare:

- permanent Cloudflare `workers.dev` URLs for testnet and mainnet; a paid custom
  domain is optional and must not be required by immutable contract metadata;
- a dedicated deployer EOA stored in a Foundry encrypted keystore;
- owner and treasury addresses; for the zero-cash bootstrap these may be the
  dedicated deployer, with migration to separate Safes funded from first revenue;
- dedicated Base Sepolia and Base mainnet RPC URLs;
- a CDP project with an Ed25519 Secret API Key for the production x402 facilitator;
- a Git repository accessible to the hosting provider.

Verified network values as of 2026-08-10:

| Network | Chain ID | Circle USDC | Blockscout |
|---|---:|---|---|
| Base Sepolia | `84532` | `0x036CbD53842c5426634e7929541eC2318f3dCF7e` | `https://base-sepolia.blockscout.com` |
| Base mainnet | `8453` | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` | `https://base.blockscout.com` |

Reconfirm the USDC addresses against Circle before each deployment. Base's public RPC endpoints are rate-limited and are not intended for production traffic.

## 1. Verify the build

From this directory:

```sh
npm install
npm run check
node scripts/terms-hash.mjs
```

The first connected install after the PostgreSQL dependency was added refreshes
the lockfile. Commit it and switch automated builds back to `npm ci` afterward.

All discovered Node and Solidity tests must pass. The terms hash changes whenever `TERMS.md` changes.

For an offline, zero-ETH-upfront deployment payload, use the deterministic builder documented in
`CREATE2_DEPLOYMENT.md`. It produces the fixed Base factory call for an EIP-7702/CDP sponsored
UserOperation without reading a signer or contacting a network. The `forge create` commands below
remain the conventional funded-EOA alternative.

The Solidity suite includes a local-time renewal test. It first confirms that an owner renewal reverts while the term is active, uses the Foundry `vm.warp` cheatcode to advance to the exact expiry, and then confirms that the owner can purchase the next term. It also confirms that a third party cannot force a renewal. Run that focused test when changing term logic:

```sh
cd contracts
forge test --offline --match-test 'testRenewal|testThirdPartyCannotForceRenew' -vv
```

## 2. Deploy on Base Sepolia

Import the deployer locally. This keeps the key encrypted and out of command history:

```sh
cast wallet import goldkey-deployer --interactive
```

Set non-secret deployment values in the current shell. The metadata base URI must end in `/`:

```sh
export GOLDKEY_RPC_URL="<dedicated Base Sepolia RPC URL>"
export GOLDKEY_DEPLOYER_ACCOUNT="goldkey-deployer"
export GOLDKEY_OWNER="<Base Sepolia owner Safe>"
export GOLDKEY_TREASURY="<Base Sepolia treasury Safe>"
export GOLDKEY_USDC="0x036CbD53842c5426634e7929541eC2318f3dCF7e"
export GOLDKEY_METADATA_BASE_URI="https://<testnet-worker>.<account>.workers.dev/metadata/"
export GOLDKEY_TERMS_URI="https://<testnet-worker>.<account>.workers.dev/terms"
```

Then deploy and verify from the contract directory:

```sh
cd contracts
GOLDKEY_TERMS_HASH="$(node ../scripts/terms-hash.mjs)"

forge create src/GoldKey.sol:GoldKey \
  --rpc-url "$GOLDKEY_RPC_URL" \
  --account "$GOLDKEY_DEPLOYER_ACCOUNT" \
  --constructor-args \
    "$GOLDKEY_OWNER" \
    "$GOLDKEY_USDC" \
    "$GOLDKEY_TREASURY" \
    "$GOLDKEY_METADATA_BASE_URI" \
    "$GOLDKEY_TERMS_URI" \
    "$GOLDKEY_TERMS_HASH" \
  --broadcast \
  --verify \
  --verifier blockscout \
  --verifier-url https://base-sepolia.blockscout.com/api/
```

Use separate multisig addresses for `GOLDKEY_OWNER` and `GOLDKEY_TREASURY` when
funding permits. The zero-cash bootstrap may use one dedicated EOA, but it should
propose a treasury Safe and transfer ownership after the first outside sale funds
those operations. The owner can pause sales and propose a treasury, but cannot
raise the price, expand supply, seize tokens, alter metadata, or stop holder transfers.

## 3. Configure the service

Copy `.env.example` to `.env` and fill the deployed addresses. For hosted testnet paygo, use chain `84532`, Coinbase's CDP facilitator, the CDP credentials, and `X402_ENABLED=true`; this rehearses the production authentication path. The unauthenticated x402.org facilitator remains useful for local testnet-only experiments. Keep `DEV_AUTH_BYPASS=false` outside a local demo.

For Coinbase's production facilitator, use its documented URL and an Ed25519 CDP secret API key. The server generates path-bound two-minute JWTs without storing them. Another facilitator can be configured with `X402_AUTH_HEADERS_JSON`. When x402 is enabled, startup calls the facilitator's authenticated `/supported` endpoint and fails closed unless it advertises protocol v2, the exact scheme, and the configured CAIP-2 network.

Four Render blueprints are included:

- `render.sepolia.yaml` creates an isolated Sepolia service and disk;
- `render.yaml` creates an isolated mainnet service and disk;
- `render.free-sepolia.yaml` creates a free Sepolia origin backed by PostgreSQL;
- `render.free.yaml` creates a free mainnet origin backed by PostgreSQL.

Never point both networks at the same SQLite file or PostgreSQL schema. Token IDs
and term numbers can overlap across chains. During Blueprint creation, enter the
values marked `sync: false` directly in Render. Do not commit them.

Run exactly one service instance per SQLite disk. PostgreSQL is required on the
free Render plan and supports later horizontal scaling:

```sh
npm start
```

Put it behind TLS and monitor `/readyz`; that route performs a live database
query. `/healthz` only confirms that the process can answer HTTP. Paid SQLite
deployments must preserve the `data/` volume and remain single-instance. Free
deployments must set a pooled Neon `DATABASE_URL` and rely on no local files.

Deploy `edge/` to its permanent `workers.dev` URL before deploying the contract.
The Worker owns immutable discovery, terms, schemas, quotes, and metadata, while
it proxies only allowlisted stateful routes to Render. This lets the Render origin
sleep or be replaced without changing the contract's public URLs.

## 4. End-to-end testnet acceptance

Do not move to mainnet until all of these succeed:

1. Mint one pass for exactly 50 test USDC.
2. Authenticate with an EOA and, separately, an ERC-1271 wallet.
3. Execute a tool, retry it with the same idempotency key, and confirm only one debit.
4. Issue a one-call child key and confirm the second distinct call is rejected.
5. Transfer the NFT and confirm the old owner session and child key fail immediately.
6. Confirm the new owner sees the same remaining quota.
7. From the current owner, attempt an immediate renewal. Confirm it reverts with `TermStillActive`, transfers no USDC, and leaves the term number and expiration unchanged. Base Sepolia time is not warped; successful post-expiry renewal is covered by the local Foundry warp test above.
8. From an unrelated account, attempt renewal and confirm it reverts without payment or term changes.
9. Send malformed paygo input and confirm it is rejected before x402 settlement. Then make one valid x402 paygo purchase, confirm an unpaid request returns `402` without the tool result, and confirm a settled 0.01-USDC request returns the result and reaches treasury.
10. Withdraw contract proceeds and confirm they can only reach the accepted treasury.
11. Compare the deployed `LICENSE_TERMS_HASH` with `node scripts/terms-hash.mjs`.

## 5. Mainnet launch

Repeat the deployment using:

- chain ID `8453`;
- Circle Base USDC `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`;
- a dedicated Base mainnet RPC;
- the permanent mainnet Worker URL for `/metadata/` and `/terms`;
- `https://base.blockscout.com/api/` as the Blockscout verifier URL.

Configure the production service with `NODE_ENV=production`, the deployed contract, the treasury Safe, the CDP facilitator URL `https://api.cdp.coinbase.com/platform/v2/x402`, and the Ed25519 CDP API key ID/secret. The service deliberately refuses Base Sepolia, x402.org, HTTP URLs, zero addresses, contract/USDC/treasury mismatches, a terms-hash mismatch, or missing v2 exact facilitator support on Base mainnet.

If the operator has no capital, do not self-purchase. Publish the fail-closed quote
and unsigned transaction flow after source verification, then make the first
outside buyer's normal 50-USDC mint the funded mainnet acceptance event. Confirm
ownership and authenticated access before counting revenue. Test x402 with an
outside paid call or after sale proceeds exist; never manufacture a customer sale.

Start with one free service instance and PostgreSQL, reconcile contract receipts
and API entitlements daily, and scale only from collected revenue.
