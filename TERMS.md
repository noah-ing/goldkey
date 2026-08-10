# GoldKey Utility License Terms v1

Effective version: 1.0.0

GoldKey is a transferable credential for the GoldKey deterministic utility API. It is not gold, a financial product, an investment, a claim on revenue, or a promise of resale value.

## 1. Purchased entitlement

Each newly minted GoldKey costs exactly 50 USDC in the payment token's six-decimal atomic units. Each token starts one service term containing 10,000 successful eligible tool executions. The onchain `termExpiresAt(tokenId)` value is the final time at which that term may be used. The initial term starts when the token is minted and lasts 365 days.

Each renewal costs exactly 50 USDC. Only the current owner or an onchain-approved operator may renew, and renewal is available only after the current term expires. Renewal advances `termNumber(tokenId)`, starts a fresh 10,000-call allowance, and sets a new expiration 365 days after renewal. Unused executions from the expired term do not roll over. Renewal is never automatic.

## 2. Quota accounting

A valid tool request that returns a deterministic tool result consumes one execution, including a validation result of `valid: false`. Malformed requests, authentication failures, onchain ownership-check failures, internal service failures, and exact idempotent retries do not consume quota.

Quota is keyed by token ID and onchain term number. The API response reports the debit and remaining allowance. The current owner may create revocable, tool-scoped child-agent credentials with lower caps; every child execution also draws from the token's shared allowance.

## 3. Transfer behavior

The current onchain owner controls access. A transfer moves the token's current expiration and remaining quota to the new owner. Credentials issued by a previous owner stop working after transfer because ownership is checked again on every quota-bearing request. The operator cannot seize or burn a token through the contract.

## 4. Pay-as-you-go alternative

Eligible tools are separately available at a posted price of 0.01 USDC per successful execution through x402. At unchanged posted prices, one GoldKey is cheaper than paygo above 5,000 calls and saves at most 50 USDC at full use. Network gas, integration cost, and unused quota can change a buyer's realized savings.

The service checks a paygo request's tool name and request shape before payment verification. After verification, it fully validates and executes the tool while buffering the result. A tool error cancels settlement. The buffered result is released only after successful settlement. An absent, invalid, or failed payment receives an x402 error rather than the tool result. Paygo requests do not use GoldKey quota or its idempotency ledger; each successfully settled paygo request is an independent purchase.

## 5. Tool behavior

Tools are deterministic and versioned. Security scanners return indicators and evidence, not a guarantee that content or URLs are safe. URL checks that require DNS resolution cannot rule out DNS rebinding. The JSON canonicalizer uses the named `goldkey-c14n-v1` format and does not claim compliance with another canonicalization standard.

The operator may add tools and non-breaking versions. A materially changed tool receives a new version. Published input limits and prohibited uses may be enforced to protect service availability and network rules.

## 6. Availability and refunds

Access requires a working supported network, an active service term, current ownership, and service availability. Onchain purchases are final except where applicable law requires otherwise or the operator publishes a specific incident credit. No uptime, profit, appreciation, liquidity, or secondary-market price is guaranteed.

## 7. Privacy and credentials

The service stores wallet addresses, token IDs, hashed credentials, quota counters, request hashes, and non-content response metadata needed for idempotency. Raw tool inputs, tool outputs, wallet secrets, and child-agent secrets are not stored in the quota ledger. Buyers are responsible for keeping wallet keys and issued child credentials secure.

## 8. Contract binding

The deployed contract stores `LICENSE_TERMS_HASH`, the Keccak-256 hash of the exact UTF-8 bytes of this file at deployment. Buyers should compare that hash before minting. The fixed contract price and maximum primary supply cannot be increased after deployment. The maximum gross from first mints is therefore 500,000 USDC. Renewals and paygo are separate revenue and are not included in that primary-mint gross cap.
