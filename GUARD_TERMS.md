# GoldKey Guard Service Terms v1

Effective: 2026-08-11

These terms cover GoldKey Guard authorization services. They are separate from the immutable GoldKey utility-pass terms in `TERMS.md`. A GoldKey NFT does not include unlimited Guard authorizations, simulations, forwarding, wallet gas, RPC fees, or third-party service charges.

## Service

GoldKey Guard evaluates a proposed MCP tool call, HTTPS request, or supported EVM transaction against an operator-controlled policy and returns a short-lived signed authorization receipt. `ALLOW`, `REVIEW`, and `BLOCK` are completed authorization results. The receipt attests to GoldKey's decision, the referenced policy version, and the hash of the exact canonical proposed call; it is not a guarantee that an action is safe, lawful, successful, or exactly-once.

The supported security architecture requires the operator-controlled local `@goldkey/enforcer` to be the exclusive execution path and the only component given a protected upstream credential, MCP transport, or protected-action EVM signer. The hosted GoldKey service receives the canonical call, public installation identity, installation signature, and x402 payment evidence needed to sell the decision. It does not receive or hold the protected upstream credential or protected-action signer and never invokes, signs, broadcasts, or forwards the protected action to the customer upstream. The local enforcer invokes an operator-bound connector only after validating an unexpired `ALLOW` receipt and receiving a fresh commit acknowledgment. Operators must prevent agents from bypassing the local enforcer and directly accessing protected credentials, signers, or upstream services; otherwise Guard is advisory, not an enforcement boundary.

The Guard beta is disabled by default at the edge and origin and is available only when live discovery advertises its routes and separate terms. Enabling the origin requires x402, receipt-signing configuration, and a nonempty server-side allowlist. During the beta, only an exactly allowlisted operator wallet may register policies or installations. Publication of software, documentation, or an API schema does not grant eligibility or promise availability.

## Pricing

- Guarded MCP tool or HTTPS authorization decision: 0.05 USDC per completed authorization.
- Supported EVM transaction authorization decision with decode, policy checks, and bounded simulation when required: 0.10 USDC per completed authorization.

Prices are presented before payment through x402. `ALLOW`, `REVIEW`, and `BLOCK` are billable completed decisions because the purchased service is the policy decision, not execution approval; `REVIEW` and `BLOCK` never forward. An exact unexpired idempotent replay returns the stored authorization without another settlement. The EVM authorization price includes at most one bounded GoldKey-hosted RPC simulation and fee-estimation workflow when static checks reach that stage; a static `BLOCK` can complete without simulation. The buyer/operator bears all blockchain gas for the actual protected transaction. That gas, customer-side RPC or wallet usage, upstream execution charges, full traces, specialist simulation services, and local-enforcer compute are separate.

## Policy and state

An allowlisted operator wallet signs immutable, content-addressed policy versions and explicitly signs each installation binding. The installation must separately prove possession of the bound Ed25519 private key; that key signs every proposed call, commit, and completion. Agents cannot change the active policy through an authorization request. GoldKey uses server time and authoritative stored spend reservations for configured limits. Policy changes require a new signed version and explicit installation activation; registered versions are not edited in place, although they can be revoked for future authorization.

The signed policy contains the connector and action allowlists. An MCP entry pins server identity, tool, and input-schema hash and may add a bounded argument schema. An HTTPS entry pins one credential-free origin, method, and path and may add bounded query and body schemas. EVM entries pin the supported chain, sender, recipients, tokens, spend and fee limits, and simulation requirement. Changing a pinned connector, action, or schema requires a new signed policy version and installation activation.

Authorizations expire quickly and bind the installation, policy hash, canonical proposed-call hash, idempotency key, decision, and evidence available at evaluation time. A caller must not reuse an authorization for a different call. Ambiguous or incomplete execution outcomes must be reconciled rather than automatically retried.

Paid-state reconciliation is a narrow recovery path for an `ALLOW`, not a promise of unconditional crash recovery. Before settlement the hosted service durably claims the exact x402 payment-payload hash and the globally unique canonical Base-USDC payer/nonce identity. The local enforcer retains the exact public x402 `PaymentPayload` and the Base transaction hash returned in `PAYMENT-RESPONSE`, submits the normal signed `/commit` first, and submits `/reconcile-commit` only if normal commit returns the exact `guard_payment_not_settled` error. GoldKey then revalidates the stored binding and verifies the successful canonical USDC EIP-3009 transaction and transfer log before atomically recording payment and `FORWARDING`. The protected action is not invoked without a fresh `replay: false` acknowledgment.

A hard death before the local client receives and durably stores the `PAYMENT-RESPONSE` transaction hash can leave a paid authorization stranded. Facilitator or onchain discovery and manual reconciliation may be required. The local enforcer must fail closed and must not automatically pay again, retry the protected action, or infer nonpayment from a timeout.

## Network and transaction limitations

The first Guard release permits only configured HTTPS connectors without redirects, configured MCP tools, native EVM transfers, and canonical calldata for explicitly allowed ERC-20 `transfer` or bounded `approve` calls to operator-trusted token addresses. Unknown selectors, arbitrary contract creation, multicalls, permits, noncanonical calldata, unlimited approvals, private or reserved network addresses, mixed DNS answers, and connector, method, path, input-schema, argument-schema, query-schema, or body-schema drift are denied by default. This release does not prove that an allowlisted contract is non-upgradeable or internally free of proxy or delegate-call behavior.

DNS checks, `eth_call`, gas estimation, transaction decoding, Base GasPriceOracle output, and code or block hashes are observations at a point in time. The Base L1-data value is an estimate, including when sourced from `getL1FeeUpperBound`, and the Isthmus operator-fee value uses the parameters visible at the checked block. Neither is a GoldKey guarantee or an absolute cap on the fee at inclusion. These observations cannot eliminate DNS changes, chain reorganization, malicious upstream behavior, smart-contract risk, fee-input changes, or differences between simulation and execution.

EVM enforcement requires the buyer/operator to configure a local estimated-network-fee cap, a local maximum native balance for a segregated execution wallet, and a fresh pre-broadcast fee/balance/nonce callback. The local enforcer refuses to invoke the signer when those checks fail. The practical wallet-loss boundary depends on keeping that signer and wallet exclusive to the enforcer and not externally funding or automatically replenishing the wallet while a transaction is pending. GoldKey does not control and cannot preserve that boundary if the wallet is reused, funded, or bypassed outside the local enforcer.

## Data and availability

The hosted service stores policy documents, public installation keys, proposed-call and result hashes, decisions, reservations, receipts, timing, completion status, settlement-claim identifiers, hashes binding the x402 payment payload and its Base-USDC payer/nonce identity, and a settlement transaction hash when known. It does not intentionally store protected raw call arguments, upstream responses, private keys, bearer credentials, or customer secrets. The customer-controlled local enforcer durably stores execution state and, for paid-state recovery, can store the exact public x402 `PaymentPayload` and returned transaction hash. Operators must secure that state and avoid placing secrets in policy metadata or proposed-call values.

`@goldkey/enforcer` is an npm-format package marked `private: true` to prevent registry publication, but its versioned tarball is delivered over public HTTPS and is not confidential software. Before installation, operators must download the exact version to a local file and independently verify it against the release-pinned SHA-256 or npm-compatible SHA-512 SRI value. Operators must not rely on `latest`, install the remote URL before verification, or treat an adjacent downloadable manifest as an independent trust anchor.

The service is provided without a promise of uninterrupted availability or fitness for a particular use. Operators remain responsible for approvals, access controls, recovery procedures, compliance, and the consequences of actions their systems execute.
