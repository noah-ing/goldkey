# GoldKey Guard: product, economics, and operating gates

## What customers buy

GoldKey Guard is a paid authorization control plane for autonomous MCP, HTTPS, and EVM actions. In the supported deployment, the operator-controlled local `@goldkey/enforcer` is the exclusive execution path and the only component given protected upstream credentials, MCP transports, or the EVM signer for the protected action. It canonicalizes and installation-signs the exact proposed call, receives a signed `ALLOW`, `REVIEW`, or `BLOCK` authorization, verifies that the receipt binds the exact call and active operator policy, and invokes the operator-bound connector only for an unexpired `ALLOW`.

The audited package includes config-driven launchers for an exclusive stdio MCP proxy, an operator-pinned AgentCash facade, and a constrained Base wallet. A design partner supplies immutable policy and connector configuration rather than writing a custom authorization client. The lower-level SDK remains available for custom HTTPS and connector integrations.

The hosted authorizer receives the canonical proposed call, public installation identity, installation signature, and x402 payment evidence needed to sell the decision. It does not receive or hold the customer's protected upstream credential or protected-action signer, has no customer connector callback, and never invokes, signs, broadcasts, or forwards the protected action to the customer upstream.

This is not a hosted open proxy and it is not another advisory scanner. The product is only an enforcement boundary when the agent cannot bypass the local enforcer to reach the upstream credential, network route, or signer directly.

The design-partner beta is disabled by default at both the edge and origin. Enabling the origin requires x402, receipt-signing configuration, and a nonempty server-side operator-wallet allowlist. Only an exactly allowlisted operator wallet can register a policy or installation; public artifact availability or beta documentation does not grant eligibility. Live catalog and OpenAPI discovery, together with the separate live Guard terms, determine whether a deployment is enabled.

## Best initial customer

Target teams whose agents can create an irreversible or expensive effect:

- crypto treasury, trading, payment, and wallet automation;
- autonomous MCP deployments that can write, deploy, delete, message, or purchase;
- multiple agents sharing provider credentials or wallet authority;
- at least $10,000 of monthly automated value or individual actions with at least $1,000 of downside.

Low-value read-only agents and teams with an established policy gateway are weak prospects.

## Competitive boundary

Generic MCP gateway functionality is already inexpensive or free. Cloudflare MCP Server Portals and Portkey can proxy and govern MCP traffic. Coinbase's Policy Engine can enforce supported wallet rules. GoldKey must therefore win on a narrower provider-independent combination:

1. operator-signed, content-addressed policy versions that an agent cannot rewrite;
2. immutable connector and action allowlists, including MCP input-schema hashes and optional bounded argument schemas, HTTPS method/path and optional bounded query/body schemas, and conservative EVM constraints;
3. dual installation control: an allowlisted operator signs the binding, the installation proves possession of its Ed25519 key, and that key signs each exact call and lifecycle transition;
4. exact-call authorization spanning MCP, HTTPS, and conservative EVM actions;
5. DNS-safe local egress for the native HTTPS connector and exclusive local credential custody;
6. authoritative concurrent spend reservations;
7. transaction decoding and bounded simulation evidence;
8. independently verifiable, short-lived signed authorization receipts.

References:

- <https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/>
- <https://portkey.ai/features/mcp>
- <https://docs.cdp.coinbase.com/wallets/security-and-policies/policy-engine/overview>
- <https://docs.x402.org/extensions/offer-receipt>

## Pricing and unit economics

The existing deterministic Action Gate stays at 0.01 USDC. It is an advisory utility, not authoritative enforcement.

Guard authorization prices:

- MCP or HTTPS authorization decision: 0.05 USDC;
- supported EVM decode, policy check, bounded simulation when required, and authorization decision: 0.10 USDC.

`ALLOW`, `REVIEW`, and `BLOCK` are billable completed decisions at the route price; the customer is buying the authorization decision, not permission to execute. `REVIEW` and `BLOCK` never forward. An exact unexpired idempotent replay returns the stored authorization without another settlement.

The customer supplies upstream credentials only to the local enforcer. The 0.10-USDC EVM authorization includes decoding, static policy checks, and, only when those checks reach the simulation stage, one bounded GoldKey-hosted RPC simulation and fee-estimation workflow. A static `BLOCK` can complete without hosted RPC simulation. The buyer/operator bears all blockchain gas for the actual protected transaction; that gas, customer-side wallet or RPC usage, upstream execution charges, full traces, and specialist simulation providers are not included. GoldKey measures its RPC and compute cost per authorization. Target variable gross margin is at least 85%; a route is repriced or disabled if measured external variable cost exceeds 15% of its price.

Illustrative SaaS packaging after paid design partners validate retention:

- Community: free local enforcer, one connector, local-only policy and receipts;
- Team: $49/month, 5,000 weighted authorizations, three protected connectors, 30-day receipt retention;
- Scale: $199/month, 25,000 weighted authorizations, ten connectors, 90-day retention, exports and webhooks;
- Enterprise: custom deployment, SSO, SIEM, VPC, KMS/HSM receipt keys, and SLA.

Weighting: one basic policy decision, five credits for guarded MCP/HTTPS, and ten credits for a guarded EVM authorization whether or not static policy reaches simulation. Overage must preserve the same 85% margin floor. The legacy $50 GoldKey pass continues to cover its immutable deterministic utility allowance and does not include unlimited Guard work.

## Non-negotiable security properties

- Default deny; `REVIEW` and `BLOCK` never forward.
- An allowlisted operator wallet signs every immutable policy version and installation binding. The installation must separately prove possession of its Ed25519 key, and that key signs every proposed call, commit, and completion.
- The agent supplies the call, never the policy, clock, spent amount, destination origin, credential, or cap.
- Same installation and idempotency key with a different call hash is rejected.
- Reservations are atomic; concurrent approvals cannot exceed the stored period cap.
- The enforcer resolves every A and AAAA answer, rejects mixed or non-global results, pins the socket while preserving TLS hostname verification, and follows no redirect in v1.
- That socket guarantee applies to GoldKey's native HTTPS connector, not the AgentCash facade. AgentCash 0.17.1 does not expose a custom socket/redirect hook, so its adapter accepts only fixed query-free operator-vetted endpoints and a non-secret `Accept` header, rechecks public DNS before launch, and still requires independent OS/container egress controls. Do not use the AgentCash adapter for hostile arbitrary destinations.
- The signed policy pins MCP server identity, tool name, and input-schema hash and can pin a bounded argument schema. It pins each HTTPS credential-free origin, operation method and path and can pin bounded query and body schemas. Changing any pinned connector or schema requires a new signed policy version and installation activation.
- EVM v1 supports native transfers and canonical calldata for configured ERC-20 `transfer` or bounded `approve` calls to operator-trusted token addresses. Contract creation, unknown selectors, multicalls, permits, noncanonical calldata, and unlimited approvals are denied at the transaction-envelope layer. For an EVM `ALLOW`, the signed evidence records the point-in-time code hash and successful bounded simulation. V1 does not prove that an allowlisted contract is non-upgradeable or internally free of proxy or delegate-call behavior; operators must trust and deliberately configure each token address.
- Base L1-data and Isthmus operator-fee evidence are pinned point-in-time estimates, not absolute protocol guarantees. The local EVM connector therefore requires an operator-set estimated-network-fee cap, a segregated-wallet native-exposure cap, and a fresh balance/nonce/oracle recheck after server commit and immediately before signing. The signer is never called if the current execution maximum plus fee estimates exceeds either the signed reservation or local fee cap, the wallet cannot fund the estimated requirement, or the wallet balance exceeds its exposure cap. Operators must use an exclusive low-balance execution signer and must not replenish it while a transaction is pending; external funding or signer reuse can defeat that operational loss boundary.
- Paid-state recovery is narrow and fail-closed. Before settlement the hosted service durably claims the exact x402 payment-payload hash and the globally unique canonical Base-USDC payer/nonce identity. For an `ALLOW`, the local enforcer retains the exact public x402 `PaymentPayload` and the Base transaction hash returned in `PAYMENT-RESPONSE`, sends the normal signed `/commit` first, and uses `/reconcile-commit` only if `/commit` returns the exact `guard_payment_not_settled` error. Reconciliation revalidates the stored binding and the successful canonical USDC EIP-3009 transaction and transfer log, then atomically marks payment settled and commits `FORWARDING`. No protected action runs without a fresh `replay: false` commit acknowledgment.
- This is not unconditional crash recovery. A hard death before the client receives and durably stores the `PAYMENT-RESPONSE` transaction hash can leave a paid authorization stranded and require facilitator or onchain discovery and manual reconciliation. The enforcer remains fail-closed and does not automatically pay again or forward.
- A crash after an irreversible send becomes `outcome_unknown`; it is never automatically replayed unless the upstream provides a trustworthy idempotency contract.
- Receipts attest GoldKey's observations and decision. They never claim universal safety or an upstream outcome that GoldKey did not independently observe.

## Design-partner distribution gate

`@goldkey/enforcer` is an npm-format package marked `private: true`, which prevents registry publication; the versioned tarball is delivered over public HTTPS and is not confidential software. Design partners must download the exact version to a local file, independently compare its bytes with a release-pinned SHA-256 or npm-compatible SHA-512 SRI value, and only then install that local tarball with exact dependency versions. Do not use `latest` or install the URL directly before verification.

The current audited design-partner artifact is `goldkey-enforcer-0.2.0.tgz`, exactly 119,159 bytes, SHA-256 `aeb3d11c02a1ac15ebc8a9c4541b9ca481a32fe1ac23b8668d99ffb88487fe36`, and SHA-512 SRI `sha512-DeHLvAITG9dZ8amUbctB0ppDcq1Is8wbGIg+uz98hJxYnFy0ZUDqkfZkXpWc3gXomTH32KJfbJUoYyBZyoVkVg==`. It is byte-identical to the current package source, includes the config-driven launchers and examples, and pins exact dependencies in `npm-shrinkwrap.json`. Any code or documentation change inside the package requires a new build and digest before distribution. The adjacent downloadable integrity manifest is useful metadata but is not, by itself, an independent trust anchor. The prior 0.1.0 artifact remains available by its immutable versioned URL for compatibility but is not the current release.

## Thirty-day validation gate

Do not infer product-market fit from downloads, listings, self-tests, or courtesy payments. Continue investing only if a 30-day design-partner cohort produces:

- at least three paying organizations;
- at least two integrations continuously in the credential path for seven days;
- at least 1,000 protected calls and 50 genuine state-changing actions;
- at least one confirmed policy violation stopped before execution;
- no demonstrated credential or network bypass;
- p95 under 150 ms for deterministic authorization and under two seconds for bounded EVM simulation;
- at least 80% fully loaded contribution margin;
- at least two renewals or prepaid follow-on commitments.

Stop or reposition if fewer than two teams pay for a real inline integration, buyers refuse to place the enforcer in the exclusive credential path, support consumes more than 30% of revenue, or qualified customers will not pay at least $49/month.
