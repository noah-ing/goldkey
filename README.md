# GoldKey

GoldKey is a fixed-price, transferable NFT access pass sold directly to autonomous agents.

- Primary price: **50 USDC**
- Hard primary supply cap: **10,000**
- Primary-mint gross cap: **500,000 USDC** (`10,000 × 50 USDC`)
- Included value: **10,000 deterministic utility calls during one active term**
- Renewal after expiry: **50 USDC** for a fresh 10,000-call, 365-day term
- Public alternative: **0.01 USDC per call** through x402
- Mechanical break-even: **5,000 calls per key**, before gas and switching cost

The NFT is not sold on a speculative story. It is the transferable settlement object for a cost-saving API entitlement. At 10,000 calls, paygo costs 100 USDC and GoldKey costs 50 USDC. High-volume orchestrators can issue revocable child-agent keys so an entire swarm draws from one quota.

The 500,000-USDC figure is the maximum gross from first mints, not a sales forecast and not a cap on total revenue. Renewal and paygo revenue are separate and are not supply-capped. The commercial bottleneck is distribution to agents that genuinely exceed 5,000 eligible calls per term.

## What is included

- Fixed 50-USDC, 10,000-supply ERC-721 contract
- Onchain term number, expiration, renewal, immutable price/cap/terms hash
- Transfer-safe access: ownership is rechecked on every charged call
- Six deterministic agent utilities with no LLM inference cost
- Atomic 10,000-call quota and idempotent retry ledger
- Short-lived EOA/ERC-1271 wallet sessions
- Revocable, tool-scoped, capped child-agent credentials
- Exact unsigned USDC approval and mint transactions
- Deterministic commerce agent that recommends pass or paygo from actual economics
- x402 0.01-USDC paygo endpoint and Bazaar discovery metadata
- OpenAPI and machine-readable agent/offer descriptors
- Dynamic NFT metadata and SVG image
- CDP facilitator JWT authentication without the heavier wallet SDK
- Contract, API, accounting, transfer, and commerce tests

## Utility catalog

| Tool | Output |
|---|---|
| `json.canonicalize` | Stable `goldkey-c14n-v1` serialization and SHA-256 |
| `json.validate` | Bounded JSON Schema 2020-12 subset without mutation/coercion, remote refs, or user regex |
| `security.prompt_scan` | Versioned injection/exfiltration indicators and spans |
| `security.url_check` | Static scheme, credential, port, and private-host checks |
| `policy.spend_check` | Exact BigInt mandate/cap decision |
| `text.normalize` | NFC/NFKC normalization, removals, and before/after hashes |

Every successful NFT-gated tool result costs one quota unit. Exact NFT-gated idempotent retries are replayed without a second debit. Each paygo request is a separate 0.01-USDC x402 purchase. The service checks the tool name and request shape before payment verification; after verification it fully validates and executes the tool, buffers the result, settles payment, and releases the result only after successful settlement. A tool error cancels settlement. Paygo does not use the NFT idempotency ledger, so retrying a successfully settled paygo call is another purchase.

## Run it

Requires Node 22 or newer and Foundry for contract tests.

```sh
npm install
npm run check
npm run demo
```

`pg` was added while this workspace had no registry access. The first connected
`npm install` refreshes `package-lock.json`; commit that refreshed lock, then use
`npm ci` for reproducible builds.

Copy `.env.example` to `.env`, set the RPC and deployed addresses, then:

```sh
npm start
```

Important public endpoints:

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/goldkey.json` | Complete machine-readable offer and live supply |
| `GET /.well-known/agent.json` | Agent discovery card |
| `GET /openapi.json` | OpenAPI 3.1 descriptor |
| `GET /terms` | Exact license bytes represented by the onchain terms hash |
| `GET /schemas/commerce-response-v1.json` | Commerce response JSON Schema |
| `GET /v1/catalog` | Tool and price catalog |
| `POST /v1/purchase/quote` | Strict machine-readable buy/paygo decision |
| `POST /v1/commerce/respond` | Buy/paygo decision, sales response, unsigned transactions |
| `POST /v1/renewal/quote` | Next-term decision; renewal transactions only after expiry |
| `POST /v1/auth/challenge` | Exact wallet-signature challenge |
| `POST /v1/auth/verify` | Short-lived current-owner session |
| `POST /v1/keys` | Issue a capped child-agent credential |
| `POST /v1/tools/:name` | Execute with GoldKey quota |
| `POST /v1/paygo/execute` | Execute with one x402 payment |

## The autonomous sale

Send the commerce endpoint a buyer forecast:

```json
{
  "forecast_calls": 7200,
  "wallet": "0x000000000000000000000000000000000000dEaD",
  "switching_cost_usdc": "0.00",
  "risk_reserve_usdc": "0.00",
  "pass_purchase_budget_usdc": "50.00",
  "purchase_authority": false
}
```

It returns:

```json
{
  "recommendation": "BUY_1_KEY",
  "paygo_cost_usdc": "72.00",
  "key_count": 1,
  "key_purchase_cost_usdc": "50.00",
  "overflow_paygo_cost_usdc": "0.00",
  "optimized_total_cost_usdc": "50.00",
  "raw_savings_usdc": "22.00",
  "authorization_status": "INFO_ONLY",
  "next_action": "OBTAIN_PURCHASE_AUTHORITY",
  "unsigned_transactions": [
    { "purpose": "Approve exact USDC purchase amount" },
    { "purpose": "Mint GoldKey pass" }
  ]
}
```

No wallet authority means no submitted purchase. An authorized agent receives the same unsigned transaction data and decides whether to sign it under its own spend policy.

`pass_purchase_budget_usdc` limits primary-pass acquisition spend; it is not a total operating budget for pass purchases plus overflow paygo. `budget_usdc` is a deprecated compatibility alias for older clients.

The response action is mechanical:

| `next_action` | Meaning |
|---|---|
| `USE_PAYGO` | No pass purchase is currently cheaper |
| `MEASURE_USAGE` | Risk-adjusted savings are not positive; gather usage before buying |
| `PROVIDE_WALLET` | The quote is positive, but no recipient wallet was supplied |
| `OBTAIN_PURCHASE_AUTHORITY` | Unsigned transactions are present, but authority was not declared |
| `SIGN_UNSIGNED_TRANSACTIONS` | The caller declared authority and may evaluate and sign the returned transactions |

For marketplaces that exchange newline-delimited JSON, run:

```sh
npm run seller
```

Each input line is a quote request; each output line is a strict JSON commerce response. The exact LLM system prompt for conversational networks is in `prompts/COMMERCE_AGENT_SYSTEM.md`.

## Agent distribution

`distribution/goldkey-agent-utilities/` is a ClawHub-ready OpenClaw skill with a
no-dependency Node client for discovery, live quotes, authentication, quota, and
pass-gated tool calls. Before publishing, replace `{{GOLDKEY_PUBLIC_ORIGIN}}`,
`{{GOLDKEY_MAINNET_CONTRACT}}`, and `{{GOLDKEY_TERMS_HASH}}` in its client with
the accepted mainnet identity, confirm no release placeholders remain, and run
its `self-test`.

Publish the free integration under the `integrations`, `security`, and `finance`
categories. The external service remains paid at the posted prices; ClawHub is
the acquisition channel, not the payment processor. The x402 route declares the
Bazaar v2 discovery extension and becomes cataloged by CDP after its first
successful mainnet settlement through the CDP facilitator.

## Authentication and transfer

1. The owner requests an EIP-4361-style challenge for a token ID.
2. The service verifies the exact stored message with `viem`, including ERC-1271 wallets.
3. The service checks `ownerOf`, current term, and expiration onchain.
4. It issues an opaque 15-minute session; only its SHA-256 hash is stored.
5. Each charged request rechecks current ownership.
6. Transfer immediately cuts off the previous owner and all child keys while preserving the token's remaining quota.

Child-agent keys are useful for orchestrators: the owner can cap calls and tools per worker, revoke a worker without moving the NFT, and share one 10,000-call pool across a swarm.

## Accounting invariants

- `used_calls <= 10,000` for each `(token_id, onchain_term_number)`
- one successful distinct request debits exactly one unit
- same idempotency key plus same request hash returns the cached response without a second debit
- same key plus a different hash returns `409`
- child-key and token-quota debits commit or roll back together
- only the current owner or an approved operator can renew, and only after expiry
- renewal changes the onchain term, so the server cannot silently invent new quota
- contract proceeds can only be withdrawn to the accepted treasury
- contract primary gross at cap is exactly `10,000 × 50 USDC`

SQLite remains available for local development and a paid single-instance host.
Free production hosting uses the PostgreSQL adapter with Neon because Render's
free filesystem is ephemeral. Never share a SQLite file across hosts. Before a
mainnet sale, run the skipped live contention test against the actual Neon branch.

## Production sequence

1. Follow `ZERO_CASH_LAUNCH.md` when no operator capital is available.
2. Run every local test, then the live Neon contention/restart test.
3. Deploy and complete the full Base Sepolia acceptance list in `DEPLOYMENT.md`.
4. Publish discovery, quotes, terms, schemas, and metadata on the always-on
   Cloudflare Worker; keep Render as the replaceable stateful origin.
5. Publish the paygo endpoint and its Bazaar metadata only after facilitator
   verification and settlement pass.
6. Target swarm orchestrators, routers, and transaction agents first.
7. Submit buyer-provided or externally measured remaining-term usage to the quote endpoint.
8. Use quota results and the quote endpoint to report paygo comparisons without inventing realized savings.
9. Call `/v1/renewal/quote` before renewal. An active key can receive `RENEW_AFTER_EXPIRY`, but unsigned renewal transactions are produced only after expiry for the current owner.

Track settled USDC, key terms sold, qualified quote conversion, calls per key, child credentials per key, renewal rate, service cost per call, disputes, and contribution margin. Scale only after measured service cost is at most 0.0005 USDC/call and buyers that receive a qualified positive-savings quote convert at a commercially useful rate.

See `TERMS.md` for the exact hashed entitlement, `ZERO_CASH_LAUNCH.md` for the
capital-free route, `DEPLOYMENT.md` for the complete testnet/mainnet runbook,
`edge/README.md` for the always-on storefront, and `CREATE2_DEPLOYMENT.md` for
the offline sponsored-deployment manifest builder.
