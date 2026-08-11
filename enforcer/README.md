# GoldKey local enforcer

This package is the enforcement data plane. It runs beside the agent and is the
only process allowed to hold upstream API credentials, MCP transports, or an EVM
signer. The hosted GoldKey service authorizes; it never receives or forwards the
operator's privileged request.

## Security boundary

The agent supplies only a connector ID, operation/tool, bounded JSON arguments,
and a fresh idempotency key. The operator constructs `GoldKeyEnforcer` with a
local Ed25519 installation identity, pinned receipt keys and policy hash,
immutable connector definitions, privileged callbacks, a durable
`FileOutcomeStore`, and lifecycle transports.

Do not give the agent direct network credentials, MCP server transports, wallet
keys, write access to the enforcer state/key directory, or a route around this
process. GoldKey cannot enforce calls that can bypass the sidecar.

## Bounded x402 authorization payment

`RemoteAuthorizer` can settle the hosted Guard decision price with
`@x402/fetch`, `@x402/core`, and the exact EVM client. Construct it in the
operator-owned sidecar process and pass a local signer through `payment`; never
put the payer key, signer, or `RemoteAuthorizer` constructor in an agent tool
callback.

```js
import { privateKeyToAccount } from "viem/accounts";
import {
  RemoteAuthorizer,
  SqlitePaymentBudgetStore,
} from "@goldkey/enforcer";

const payer = privateKeyToAccount(process.env.GOLDKEY_PAYER_PRIVATE_KEY);
const paymentBudget = new SqlitePaymentBudgetStore({
  filename: "/var/lib/goldkey/payment-budget.sqlite",
  periodSeconds: 86400,
  maxPeriodAtomic: "5000000",       // $5.00 per fixed UTC day
  maxOutstandingAtomic: "200000",  // at most $0.20 unresolved
  maxOutstandingCount: 2,
});
const authorizer = new RemoteAuthorizer({
  authorizeUrl: "https://goldkey-edge-storefront.noah-ing.workers.dev/v1/guard/paygo/authorize/network",
  fetchImpl: fetch,
  installationIdentity,
  receiptKeyset,
  policyHash,
  payment: {
    signer: payer,
    treasuryAddress: "0xd6b7E00FcD46966676F554fE0455BfF739e85b1b",
    maxAmountAtomic: "50000",
    timeoutMs: 15000,
    budgetStore: paymentBudget,
  },
});
```

Use a separate EVM authorizer URL and a local maximum of `"100000"` for EVM
decisions. The network/MCP/HTTPS price is exactly 50,000 atomic USDC ($0.05),
and the EVM price is exactly 100,000 atomic USDC ($0.10).

The budget store is mandatory for paid authorization. Put its parent directory
under the operator account with mode `0700`, do not expose the store object or
database path to agent tools, and use the same database for every process and
authorizer spending from that payer. A different database is a different
operator budget domain. The first opener pins the period and cap configuration;
later processes fail closed if they try to open that file with different
limits. Fixed periods are aligned to Unix epoch boundaries. SQLite
`BEGIN IMMEDIATE` serializes reserve decisions across processes, while amounts
remain decimal strings summed as `BigInt`, so fresh idempotency keys and
concurrent workers cannot bypass the cumulative cap. The global outstanding
amount/count caps also include in-progress reservations.

For each accepted challenge, the restricted signer validates the exact Base
USDC EIP-3009 typed data and durably reserves the installation ID, idempotency
key, call hash, amount, payer, payee, network, asset, EIP-3009 nonce, fixed
period, and `validBefore` before invoking the real `signTypedData`. The store
also rejects reuse of a payment identity. It is marked `TRANSMITTED` before the
`PAYMENT-SIGNATURE` can enter a network request and `SETTLED` only after the
authorizer validates a successful, matching `PAYMENT-RESPONSE`. A signer or
encoding failure before network transmission releases the reservation. Once
transmission is possible, a timeout, second 402, invalid response, or missing
proof remains unresolved and consumes both period and outstanding capacity
until EIP-3009 `validBefore`. At expiry it becomes `EXPIRED_UNKNOWN`: it stops
using the outstanding cap but remains conservatively charged to that period.

Operators can inspect `await paymentBudget.snapshot()` and perform explicit
recovery with
`paymentBudget.resolve({ reservationId, resolution: "SETTLED", transaction })`
or `resolution: "NOT_SETTLED"`. Use `NOT_SETTLED` only after an authoritative
facilitator/onchain check proves the authorization was not paid; it releases
exposure. `SETTLED` requires the Base transaction hash and keeps the amount
charged. These administrative methods must not be exposed as agent tools.

The initial unsigned request may receive one x402 challenge. Before the payer
is invoked, the transport requires exactly one x402-v2 `exact` option for the
exact authorization URL, `eip155:8453`, canonical Base USDC, the configured
treasury, the exact product price, canonical USDC EIP-3009 domain parameters,
and a timeout of at most 30 seconds. It also enforces `maxAmountAtomic`. Only
then does it create one `PAYMENT-SIGNATURE` and retry the identical request
once. A malformed, substituted, multiple-option, Permit2, over-budget, or
still-402 response fails closed. There is no alternate asset, network, payee,
scheme, price, or second payment attempt.

The SDK receives a restricted signer facade exposing only `address` and
`signTypedData`; the original signer remains inside the local authorizer and is
never passed to fetch, MCP, HTTPS, EVM-forwarding, commit, or completion
callbacks. The authorization deadline covers both HTTP attempts, signing, and
response parsing and is always capped at 30 seconds (the enclosing enforcer
defaults to the stricter 15-second deadline).

After a successful paid response, the authorizer validates and retains only the
exact public x402 v2 `PaymentPayload` that it sent and the Base transaction hash
from `PAYMENT-RESPONSE`. The local outcome file is mode `0600`; it keeps this
proof through commit so a payment can be reconciled without exposing the payer
private key. The proof is cleared after a fully successful execution.

## Config-driven launchers

Version 0.2.0 includes four executable entry points. Each uses one
operator-owned configuration document containing the shared `runtime` section
plus the relevant adapter section:

- `goldkey-mcp-stdio <config.yaml|config.json>` mirrors an explicitly selected
  subset of one local stdio MCP server. Startup pins every exposed tool name and
  canonical input-schema hash. Every forwarded call requires the caller's
  durable GoldKey idempotency value and crosses hosted authorization before the
  exact upstream call is committed and invoked once.
- `goldkey-agentcash <config.json>` exposes only the operator-pinned AgentCash
  x402 operations in the `agentcash` section. URL, method, headers, payment
  network, and maximum upstream purchase amount are not agent-controlled. This
  is an explicit local AgentCash facade, not transparent interception of other
  AgentCash clients.
- `goldkey-wallet execute --config <config.json> --request <request.json>` runs
  one exact configured Base operation.
- `goldkey-wallet-mcp --config <config.json>` exposes the configured native
  transfer, ERC-20 transfer, and bounded-approval operations as local MCP tools.

The packaged runtime loads or creates the private installation identity, pins a
local public receipt keyset and exact registered policy hash, opens the durable
outcome and payment-budget stores, and pays only an exact GoldKey Guard x402
challenge from the named environment wallet. No customer-written bootstrap
module is required. Complete the design-partner policy and installation
registration before execute mode; the launchers do not bypass the hosted
operator allowlist.

Use the packaged examples as schemas, not production policy. They contain only
placeholder policy hashes, destinations, and wallet addresses. Keep the config,
state, budget database, installation key, receipt keyset, AgentCash wallet, and
execution keystore under an operator-owned account. The Guard authorization
payer and Base execution signer must be separate wallets.

The discovery modes are deliberately narrower than execute mode:

- `goldkey-mcp-stdio --inspect <config>` starts the pinned upstream MCP process
  and sends only `initialize` and paginated `tools/list`; GoldKey does not load
  its runtime, invoke a tool, authorize, sign, or pay. Because the upstream is
  third-party code, inspect is not a claim that the upstream process itself is
  side-effect-free.
- `goldkey-agentcash --inspect <config> <request>` is offline: it does not start
  AgentCash, resolve DNS, authorize, sign, or pay.
- `goldkey-wallet probe --config <config> --request <request>` performs only
  local syntax, allowlist, and cap validation. It does not load RPC, either
  wallet, the runtime, or any payment path.

Remove the agent's original MCP config, direct upstream credential, AgentCash
wallet access, RPC signer access, and every alternate route to the protected
capability. If the agent can invoke the original capability directly, the local
enforcer cannot provide a security boundary. When the agent can execute shell
commands, run the enforcer under a separate OS account or container.

## Integrity-pinned package artifact

Run `npm run pack:integrity` in this directory to create
`dist/goldkey-enforcer-0.2.0.tgz` and its adjacent
`.tgz.integrity.json` manifest. The manifest records both a SHA-256 digest and
an npm-compatible SHA-512 SRI value. Verify one of those values before
installing the tarball; dependencies are exact-version pinned in
`npm-shrinkwrap.json`. The package remains marked private so this command cannot
publish it to a registry.

The permanent manifest is
`https://goldkey-edge-storefront.noah-ing.workers.dev/.well-known/goldkey-guard/goldkey-enforcer-0.2.0.tgz.integrity.json`.
Download the tarball named by that manifest, verify its byte length and SHA-256
or SHA-512 SRI locally, then install that exact local file. Never pipe the
download into a shell and never install an unverified similarly named package
from a registry.

## Receipt-key rotation

The pinned keyset is ordered: `keys[0]` is the active receipt signer. Every
retained key must remain public-only and include canonical `not_before` and
exclusive `signing_not_after` timestamps. An optional `revoked_at` can end that
interval earlier. The enforcer checks the signed receipt's `issued_at` against
this interval, so possession of a retired private key cannot authorize a fresh
call.

At cutover, pin the new key first and retain the old public key only for the
maximum outstanding receipt TTL (currently five minutes). A receipt issued
before `signing_not_after` can finish that bounded overlap; one issued at or
after the cutover is rejected before commit or forwarding. Private `d` or
symmetric `k` material is never accepted in the keyset.

## Irreversible-call ordering

Every call follows one fail-closed sequence:

1. Canonicalize and durably bind the idempotency key to the exact call hash.
2. Sign `goldkey.guard-request.v1` with the installation key.
3. Verify the signed authorization envelope, expiry, policy hash, installation,
   idempotency key, connector, call kind, evidence, and exact call hash.
4. Persist `AUTHORIZED` and perform local destination checks.
5. Persist `FORWARDING`.
6. Sign and remotely commit `goldkey.guard-commit.v1`, using
   `execution_id = receipt.receipt_id`. A paid call first uses the ordinary
   `/commit` route. Only an exact `guard_payment_not_settled` response permits
   the lifecycle adapter to submit the retained public payment proof to
   `/reconcile-commit`; the service independently verifies the Base USDC
   EIP-3009 calldata, receipt, and Transfer before committing.
7. Invoke the operator-bound upstream callback once.
8. Persist `SUCCEEDED` and optionally submit signed completion.

A crash, timeout, lost commit response, write error, or lost completion response
after `FORWARDING` becomes `UNKNOWN`. The same idempotency key is never retried
automatically.

Payment recovery is bounded, not magic exactly-once delivery. It requires the
local client to have received and durably retained the `PAYMENT-RESPONSE`
transaction hash. A hard process death after transmitting payment but before
receiving that hash remains safe against automatic forwarding/retry but can
leave the paid authorization stranded for manual facilitator or onchain
reconciliation. The payment-budget reservation remains conservative throughout
that ambiguity; do not claim unconditional crash recovery.

## Connector defaults

- MCP: tool and input-schema hashes come from immutable local configuration.
  The callback receives frozen arguments plus their exact canonical JSON bytes.
- HTTPS: method, origin, path, and every forwarded header come from immutable
  local configuration. Agent-supplied headers are ignored in full; they are not
  part of the API or forwarded request. Operator credentials may be supplied
  only as `trusted_headers`, alongside fixed protocol headers. The client resolves both A and AAAA,
  rejects the whole answer set if any address is private/reserved, pins the
  selected IP while retaining the original TLS hostname/SNI, disables connection
  reuse and redirect following, caps requests at 64 KiB and responses at 1 MiB,
  and shares a maximum 15-second deadline with authorization and commit.
- EVM: the configured signer is bound to one chain and sender. It receives only
  the exact frozen EIP-1559 transaction (empty access list, exact nonce, gas
  limit, max fee, and priority fee) and canonical bytes after authorization and
  commit. The receipt must bind the transaction hash, destination, pinned
  pending nonce, gas estimate, point-in-time Base L1-fee estimate, cumulative native-fee
  reservation, and wallet-global nonce lock. The signer callback must sign the
  supplied transaction verbatim; fee or nonce population after authorization is
  forbidden. Before commit, the enforcer independently requires an exact signed
  successful-simulation shape bound to the transaction hash, matching pending
  nonce, gas estimate within the frozen gas limit, canonical target-code hash,
  locally recomputed execution-plus-L1 fee reservation, and exact chain/sender/
  nonce wallet lock. Missing or inconsistent proof fields fail before commit.

## Mandatory EVM fee-exposure boundary

Every local EVM connector must configure both
`max_estimated_network_fee_atomic` and
`max_wallet_native_exposure_atomic`, plus an operator-owned
`recheckFeeExposure` callback. The SDK includes a Base adapter:

```js
import { createPublicClient, http } from "viem";
import { base } from "viem/chains";
import {
  GoldKeyEnforcer,
  createBaseFeeExposureRecheck,
} from "@goldkey/enforcer";

const baseClient = createPublicClient({
  chain: base,
  transport: http(process.env.BASE_RPC_URL),
});

const evmConnector = {
  id: "base-fee-wallet",
  kind: "evm_transaction",
  chain_id: 8453,
  from: executionAccount.address,
  // Wei. Choose deliberately for the operator's own loss tolerance.
  max_estimated_network_fee_atomic: "500000000000000",
  max_wallet_native_exposure_atomic: "2000000000000000",
  recheckFeeExposure: createBaseFeeExposureRecheck({ client: baseClient }),
  signAndBroadcast: operatorBoundSignAndBroadcast,
};
```

After the hosted commit and immediately before invoking `signAndBroadcast`, the
enforcer obtains a fresh pending nonce, a block-pinned native balance, and
block-pinned Base GasPriceOracle L1-data and Isthmus operator-fee estimates. It
refuses to call the signer unless:

- chain, sender, exact transaction hash, and pending nonce still match;
- execution fee maximum plus the current L1-data and operator-fee estimates fit
  the signed reservation and the local estimated-network-fee cap;
- the native balance can cover transaction value plus that estimate; and
- the native balance is no greater than the local wallet-exposure cap.

Use a dedicated low-balance execution wallet, keep its signer exclusive to this
enforcer, and do not automatically top it up while a transaction is pending.
This makes the balance cap the practical native-asset loss boundary at the final
check. Reusing the signer elsewhere or funding it after the check defeats that
operational boundary.

Base documents `getL1FeeUpperBound` as an upper-bound estimate from approximate
transaction length, and the Fjord design says its practical compression bound
covers more than 99.99% of historical transactions. The oracle inputs can change
between the checked block and inclusion, so GoldKey records the value as
`l1_fee_estimate_atomic` in `goldkey.evm-simulation-evidence.v2`; the pinned
Isthmus component is `operator_fee_estimate_atomic`. Neither is an absolute
protocol fee guarantee. The wallet exposure cap is therefore mandatory even
when the estimate is below the configured fee threshold. See Base's
[network-fee documentation](https://docs.base.org/base-chain/network-information/network-fees)
and the [Fjord predeploy specification](https://docs.base.org/base-chain/specs/upgrades/fjord/predeploys),
and the [Isthmus operator-fee specification](https://docs.base.org/base-chain/specs/upgrades/isthmus/exec-engine#operator-fee).

`commitAuthorization` is required and must be idempotent by `receipt_id`. It must
reject a commit whose installation, receipt hash, call hash, or execution ID
differs from authorization. Before forwarding, the callback must return an
object with `replay: false`; `replay: true`, a missing/non-boolean replay field,
`false`, or `{ ok: false }` is an ambiguous commit and fails closed to local
`UNKNOWN`. An unavailable or replayed commit always prevents upstream
forwarding, and the same idempotency key is never retried automatically.

`createGuardLifecycleHttpClient({ serviceOrigin, fetchImpl })` provides a
dependency-free adapter for the hosted lifecycle endpoints. `serviceOrigin` must
be exactly one credential-free HTTPS origin, without a trailing slash. For each
signed envelope the adapter derives
`/v1/guard/executions/{execution_id}/commit` or `/complete` from that envelope's
execution ID; callers do not supply a reusable static lifecycle URL. It sends
canonical JSON, disables redirect following, shares the enforcer abort signal,
and caps acknowledgments at 64 KiB.

When the verified authorizer provides payment proof, the adapter still calls
ordinary `/commit` first. It sends the bounded reconciliation wrapper only if
that exact request receives HTTP 409 with
`guard_payment_not_settled`. Any other error fails closed without disclosing
the payment proof or invoking the upstream action.

The adapter accepts a commit only when the JSON acknowledgment exactly repeats
the execution ID, installation ID, call hash, policy hash, `ALLOW` decision, and
`forwarding` status from the verified receipt, with a committed timestamp and
exactly `replay: false`. A completion must additionally report `completed` and
exactly match the signed outcome status and hash. Empty/204, replayed,
malformed, mismatched, denied, or unbound generic success responses fail closed
and prevent forwarding.

## Non-goals

This package does not sandbox arbitrary code, make agent-controlled policy
authoritative, or make a non-idempotent third-party write safely retryable. It
ships config-driven stdio MCP, AgentCash, and Base-wallet launchers, while the
lower-level SDK remains available for custom HTTPS connectors and other
operator-owned transports. Human review is intentionally not converted to
`ALLOW` locally.

The operator—not the agent—must sign and register the immutable policy version,
including optional bounded `arguments_schema`, `query_schema`, and
`body_schema` constraints. Installation registration requires both the
operator wallet signature and an Ed25519 proof of possession from the local
installation key. The hosted service may be restricted to an explicit
design-partner operator-wallet allowlist; this package does not bypass that
control.
