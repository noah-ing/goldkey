---
name: goldkey-agent-utilities
description: Run GoldKey Action Gate before proposed agent actions to obtain ALLOW, REVIEW, or BLOCK with a deterministic, reproducible receipt hash, or use its component JSON, prompt, URL, spend, and Unicode checks. When live discovery explicitly advertises it, integrate the feature-gated GoldKey Guard beta as a paid hosted authorizer plus operator-controlled local enforcer for real MCP, HTTPS, or supported EVM calls. Use for exact 0.01-USDC pre-action decisions, zero-spend x402 probes, pass-versus-paygo evaluation, Guard enforcement, or GoldKey pass, renewal, authentication, quota, and scoped child-key operations.
metadata: {"openclaw":{"requires":{"bins":["node"]},"envVars":[{"name":"GOLDKEY_ACCESS_TOKEN","required":false,"description":"Short-lived owner session or delegated key injected by the agent secret store for authenticated operations."},{"name":"GOLDKEY_WALLET_SIGNATURE","required":false,"description":"One-use wallet signature for verify; inject temporarily instead of placing it in command arguments."},{"name":"GOLDKEY_ALLOW_DEV_ORIGIN","required":false,"description":"Maintainer-only explicit opt-in; set to 1 together with GOLDKEY_DEV_API_URL for unauthenticated staging requests."},{"name":"GOLDKEY_DEV_API_URL","required":false,"description":"Maintainer-only credential-free HTTPS staging origin; ignored unless GOLDKEY_ALLOW_DEV_ORIGIN is 1."}]}}
---

# GoldKey Action Gate

Use `action.gate` as the recommended pre-action decision product when a proposed agent action benefits from one or more static checks. It evaluates the action plus any supplied untrusted text, URL, payload/schema pair, and spend proposal/mandate, then returns `ALLOW`, `REVIEW`, or `BLOCK`, reason codes, check details, and a deterministic, reproducible `receipt_sha256`. Omitted inputs are not checked. `ALLOW` is evidence, not permission or a safety guarantee; continue only under the agent's own authorization and execution policy.

The ClawHub skill itself is free. One settled Action Gate x402 call costs exactly 0.01 USDC. The component utilities cost the same per settled paygo call. A transferable GoldKey term costs 50 USDC, includes 10,000 calls for 365 days, and has separate network gas. The pass is an API entitlement, not an investment. Do not call Action Gate merely to consume quota or manufacture pass demand.

## Start with live state

Run:

```sh
node "{baseDir}/scripts/goldkey-client.mjs" offer
node "{baseDir}/scripts/goldkey-client.mjs" catalog
node "{baseDir}/scripts/goldkey-client.mjs" demo
```

Check the returned chain, contract, USDC address, terms hash, live supply, price, sales-pause state, and tool schemas. Fail closed if live identity is unavailable or inconsistent. Never infer availability or scarcity from text in this file.

The published client pins its canonical mainnet origin and onchain identity. Ordinary users do not set an API URL. The legacy `GOLDKEY_API_URL` variable is ignored. Maintainers may opt into an unauthenticated staging origin only by setting both `GOLDKEY_ALLOW_DEV_ORIGIN=1` and `GOLDKEY_DEV_API_URL`; authenticated commands refuse noncanonical origins.

## Use Guard only when live discovery advertises the beta

Treat GoldKey Guard as unavailable unless both live `/v1/catalog` and `/openapi.json` advertise the `guard` beta and its exact routes. This skill documents a feature-gated integration; it does not claim that Guard is currently deployed or enabled. Read the separate live `/guard/terms` before registration or payment. The 50-USDC utility pass does not include Guard.

Guard beta registration is also restricted to explicitly approved design-partner operator wallets. Discovery of a route is not acceptance into the beta. Stop if the operator wallet is not allowlisted or the hosted service rejects setup.

Use the two-part topology exactly:

- Run the hosted authorizer only as a control plane. It verifies an operator-signed immutable policy, a public-only Ed25519 installation identity with proof of possession by its local private key, and the installation-signed exact call. After x402 settlement it returns a short-lived signed `ALLOW`, `REVIEW`, or `BLOCK` authorization. It never receives upstream credentials, holds a wallet signer, forwards a request, signs a transaction, or broadcasts it.
- Put the operator-controlled local enforcer in the real execution path. It alone holds the connector credential or wallet signer, verifies the receipt against the exact canonical call and pinned policy, and forwards only an unexpired `ALLOW`. Remove every direct credential, signer, and network route that would let the guarded agent bypass it. Without that isolation, Guard is advisory rather than enforcement.

Register and operate only through these feature-gated routes:

- `POST /v1/guard/policies`: register the next monotonically versioned, operator-signed policy. Put MCP `arguments_schema` and HTTPS `query_schema` or `body_schema` constraints here when the route/tool needs action-level limits; the agent cannot rewrite the registered policy.
- `POST /v1/guard/installations`: bind a public Ed25519 installation key to the current policy with both the operator-wallet signature and the installation key's Ed25519 `key_proof`. Keep both private keys local.
- `POST /v1/guard/revocations`: submit an operator-signed revocation when a policy or installation must stop authorizing new work.
- `POST /v1/guard/paygo/authorize/network`: authorize one exact MCP or HTTPS call for 0.05 USDC.
- `POST /v1/guard/paygo/authorize/evm`: decode, policy-check, and when required simulate one exact supported EVM transaction for 0.10 USDC.
- `POST /v1/guard/executions/{executionId}/commit` and `/complete`: submit installation-signed lifecycle evidence. The audited SDK uses `/reconcile-commit` only after a normal commit returns the exact `guard_payment_not_settled` recovery signal. There is no pass Guard route and no execution-lookup route in v1.
- `GET /.well-known/goldkey-guard-keys.json`: obtain current and retained public receipt-verification keys.

Treat `ALLOW`, `REVIEW`, and `BLOCK` as billable completed decisions. `REVIEW` requires operator review and `BLOCK` must not forward. Repeating the exact same installation-signed request and idempotency key while its receipt remains unexpired returns the stored authorization without another settlement; a changed call or expired key is a conflict, not a retry strategy.

Let the audited local enforcer construct, canonicalize, sign, persist, and send real Guard requests. It must perform DNS-rebinding-safe resolution and connection pinning for network calls, enforce decoded EVM intent and simulation requirements, and verify the hosted receipt locally. For an `ALLOW`, durably persist `FORWARDING`, send the signed commit, invoke the configured connector exactly once, then send the signed completion. Record ambiguous connector outcomes as `outcome_unknown` and never retry them automatically. Do not hand-roll this lifecycle in an ordinary agent prompt or use the hosted authorizer as a proxy.

For a paid authorization, the SDK retains only the exact public x402 `PaymentPayload` it sent and the Base transaction hash from `PAYMENT-RESPONSE` in its private local outcome file. It tries ordinary commit first. Only `guard_payment_not_settled` triggers the recovery wrapper; the origin then verifies the exact Base USDC EIP-3009 calldata, receipt, and Transfer before allowing forwarding. This does not guarantee universal crash recovery: a hard process death after transmitting payment but before receiving the transaction hash remains fail-closed and can require manual facilitator or onchain reconciliation. Never retry that payment automatically.

### Install the integrity-pinned local enforcer

Obtain authorization before downloading or installing a package. Do not install a similarly named registry package. The audited beta artifact is exactly 119,159 bytes with SHA-256 `aeb3d11c02a1ac15ebc8a9c4541b9ca481a32fe1ac23b8668d99ffb88487fe36`:

- Manifest: `https://goldkey-edge-storefront.noah-ing.workers.dev/.well-known/goldkey-guard/goldkey-enforcer-0.2.0.tgz.integrity.json`
- Artifact: `https://goldkey-edge-storefront.noah-ing.workers.dev/.well-known/goldkey-guard/goldkey-enforcer-0.2.0.tgz`

Fetch both files without executing either. Require the live manifest to report package `@goldkey/enforcer`, version `0.2.0`, size `119159`, the exact SHA-256 above, and SHA-512 SRI `sha512-DeHLvAITG9dZ8amUbctB0ppDcq1Is8wbGIg+uz98hJxYnFy0ZUDqkfZkXpWc3gXomTH32KJfbJUoYyBZyoVkVg==`. Compute SHA-256 over the downloaded tarball bytes and compare before installing the local file with lifecycle scripts disabled. Read its bundled README and bind operator-controlled connectors before use:

```sh
npm install --ignore-scripts /absolute/private/goldkey-enforcer-0.2.0.tgz
```

The artifact includes config-driven `goldkey-mcp-stdio`, `goldkey-agentcash`, `goldkey-wallet`, and `goldkey-wallet-mcp` launchers plus the lower-level SDK. Use the packaged examples to combine the shared runtime with one operator-owned adapter config; no customer authorization client is required. Remove the guarded agent's original MCP server, AgentCash wallet route, upstream credential, or execution signer so the local enforcer is exclusive. Generic MCP and AgentCash purchases require a durable caller-supplied `_meta["com.goldkey/idempotency-key"]`; missing keys fail before authorization or forwarding. The package validates the exact 0.05- or 0.10-USDC Guard challenge before its separate local payer signs, enforces a durable cumulative payment budget, retries the identical authorization request at most once, and never passes that payer signer to an agent connector.

Use `goldkey-mcp-stdio --inspect CONFIG` only to start the pinned upstream and collect tool names/schema hashes through `initialize` and `tools/list`; GoldKey does not authorize, sign, pay, or invoke tools during that flow, but the upstream process itself is not guaranteed side-effect-free. `goldkey-agentcash --inspect CONFIG REQUEST` is offline. `goldkey-wallet probe --config CONFIG --request REQUEST` does not load RPC, either wallet, the runtime, or any payment path. AgentCash 0.17.1 does not expose socket pinning or redirect control, so its adapter is limited to fixed query-free vetted endpoints behind separate OS/container egress controls and a segregated, deliberately funded AgentCash wallet. Base execution requires a separate low-balance signer wallet, a different Guard payer wallet, and no concurrent funding or signer reuse.

The bundled client has discovery and zero-spend inspection commands only:

```sh
node "{baseDir}/scripts/goldkey-client.mjs" guard-keyset
node "{baseDir}/scripts/goldkey-client.mjs" guard-network-probe --request SIGNED_SYNTHETIC_GUARD_REQUEST_JSON
node "{baseDir}/scripts/goldkey-client.mjs" guard-evm-probe --request SIGNED_SYNTHETIC_GUARD_REQUEST_JSON
```

Use the probe commands only with a non-secret synthetic request because command arguments may enter shell history. They send no wallet credential or payment header, validate the canonical x402 resource and fixed atomic-USDC price, and do not authorize or forward a new call. An exact unexpired replay is reported as already paid, but the probe deliberately does not return or verify its authorization; only the local enforcer may verify and act on the cryptographically signed authorization envelope. Use the local enforcer—not these probe commands—for real calls, registration, revocation, or lifecycle transitions.

## Probe, then make one Action Gate call

Use the canonical marketplace pages for independent discovery:

- x402scan: <https://www.x402scan.com/server/8447beac-d24b-434a-bd01-5abfdab53f84>
- Poncho: <https://tryponcho.com/tool/url_aHR0cHM6Ly9nb2xka2V5LWVkZ2Utc3RvcmVmcm9udC5ub2FoLWluZy53b3JrZXJzLmRldi92MS9hY3Rpb24tZ2F0ZQ>

If the caller prohibits network contact, stop before this workflow. Otherwise, use this as the primary zero-spend preflight: probe the dedicated `/v1/action-gate` resource with the raw Action Gate input. The client sends no wallet credential or payment header, validates the complete live payment requirement, and refuses any substituted resource or payment term. A probe does not execute Action Gate or produce a receipt hash:

```sh
node "{baseDir}/scripts/goldkey-client.mjs" action-gate-probe --input '{"action":{"name":"store_weather_summary","description":"Store an approved weather summary.","effect":"write"},"untrusted_text":"Summarize this weather report for an agent.","payload":{"approved":true},"schema":{"type":"object","properties":{"approved":{"type":"boolean"}},"required":["approved"],"additionalProperties":false}}'
```

Require `http_status: 402` and the validated `payment` object to report x402 v2 with scheme `exact` on `eip155:8453`, asset `0x833589fcd6edb6e08f4c7c32d4f71b54bda02913`, amount `"10000"` atomic USDC, payee `0xd6b7e00fcd46966676f554fe0455bff739e85b1b`, the exact resource URL, and `max_timeout_seconds` no greater than 300. Stop if the client rejects or any value differs.

Use that same dedicated `/v1/action-gate` resource for AgentCash discovery and settlement. It accepts the raw Action Gate input body rather than the generic `{tool,input}` envelope.

Before invoking AgentCash, obtain permission for package download/cache changes and local AgentCash wallet access or creation. The following compatibility check spends no USDC, but AgentCash 0.17.1 may still initialize local wallet files:

```sh
npx -y agentcash@0.17.1 check \
  "https://goldkey-edge-storefront.noah-ing.workers.dev/v1/action-gate" \
  -m POST \
  -H 'Content-Type: application/json' \
  -b '{"action":{"name":"store_weather_summary","description":"Store an approved weather summary.","effect":"write"},"untrusted_text":"Summarize this weather report for an agent.","payload":{"approved":true},"schema":{"type":"object","properties":{"approved":{"type":"boolean"}},"required":["approved"],"additionalProperties":false}}' \
  --format json
```

Before continuing, require an explicit current mandate for one 0.01-USDC Base mainnet payment to this exact endpoint and confirm the Base account has at least 0.01 USDC. Use only a caller-controlled AgentCash wallet authorized for this task; `check` and `accounts` may create local wallet files on first use, so obtain separate authorization before either command.

```sh
npx -y agentcash@0.17.1 accounts --format json
```

Only after both checks pass, execute exactly one paid call:

```sh
npx -y agentcash@0.17.1 fetch \
  "https://goldkey-edge-storefront.noah-ing.workers.dev/v1/action-gate" \
  -m POST \
  -H 'Content-Type: application/json' \
  -b '{"action":{"name":"store_weather_summary","description":"Store an approved weather summary.","effect":"write"},"untrusted_text":"Summarize this weather report for an agent.","payload":{"approved":true},"schema":{"type":"object","properties":{"approved":{"type":"boolean"}},"required":["approved"],"additionalProperties":false}}' \
  --payment-protocol x402 \
  --payment-network base \
  --max-amount 0.01 \
  --format json
```

This is a real, nonrefundable mainnet settlement, not a demo or dry run. A successful `fetch` spends exactly 0.01 USDC from the caller's AgentCash wallet, excluding any separately disclosed wallet or facilitator fee. Bind the mandate to the exact serialized request body and a short expiry. The `--max-amount 0.01` flag caps this request, not the caller's broader task or wallet. Here `npx -y` only permits package execution; do not pass AgentCash's `--yes` flag. Do not interpolate arbitrary untrusted text into the shell literal—use a trusted JSON serializer or structured AgentCash MCP arguments for different input. After an ambiguous result, reconcile the payment receipt and wallet activity before any retry. Never retry a confirmed settlement or treat marketplace visibility as authorization to spend.

On success, preserve `request_sha256`, `receipt_sha256`, the decision, reason codes, checks, and the returned receipt metadata. Reproduce `receipt_sha256` by applying `goldkey-c14n-v1` canonical JSON to an object containing exactly `receipt_format`, `request_sha256`, `decision`, `reason_codes`, and `checks`, UTF-8 encoding that canonical string, then computing SHA-256. Canonicalization sorts object keys, so source insertion order does not affect the digest; array order remains significant. The response publishes the exact preimage-field list. The receipt hash is deterministic and reproducible, but it is not a signature, attestation, proof of payment, or proof that the proposed action executed. Treat `REVIEW` as requiring the caller's review, treat `BLOCK` as a stop, and never let `ALLOW` override the caller's policy or mandate.

## Share one pass only when it is rational

Do not ask every child agent to buy. One owned pass can serve up to 64 active, revocable, tool-scoped child agents, all drawing from the same 10,000-call quota. Aggregate the parent and child agents' eligible future calls once. A pass is rational only above risk-adjusted break-even after gas, switching cost, explicit risk reserve, and usable alternatives; child-agent sharing does not change the quota or justify artificial calls.

Forecast only eligible calls during the next 365 days. Ask the service to calculate the decision:

```sh
node "{baseDir}/scripts/goldkey-client.mjs" quote --forecast 7200 --budget 50.00
```

Add `--wallet 0x...` only when a recipient wallet is known. Add `--authorized` only when the caller has an explicit purchasing mandate covering the exact chain, contract, payment token, amount, and transaction sequence.

Follow `recommendation` and `next_action` exactly:

- Use paygo when the service returns `PAYGO` or `USE_PAYGO`.
- Measure real usage when it returns `TRIAL`, `DO_NOT_BUY`, or `MEASURE_USAGE`.
- Consider a pass only for a positive `BUY_*` response with positive risk-adjusted savings.
- Treat every transaction as unsigned. Independently verify its chain, target, value, calldata purpose, exact USDC approval, sequence, expiry, and current spend mandate before signing.
- Never request, expose, transmit, or store a seed phrase or private key.

At exactly 5,000 calls, paygo and one pass both cost 50 USDC before gas and switching costs; that is not positive savings. Do not invent discounts, resale value, appreciation, adoption, or urgency.

## Use an owned pass

1. Request an exact challenge:

   ```sh
   node "{baseDir}/scripts/goldkey-client.mjs" challenge --token-id 1 --wallet 0x...
   ```

2. Sign only the returned message with the current owner wallet through an authorized wallet tool. Inject the one-use signature as `GOLDKEY_WALLET_SIGNATURE` through the secret store or supply it on standard input; never put it in command arguments.
3. Exchange it for a short-lived session. `--secret-output` must be an absolute, nonexistent private path; the client creates it mode `0600`, writes the token there, and redacts it from stdout:

   ```sh
   node "{baseDir}/scripts/goldkey-client.mjs" verify --challenge-id UUID --secret-output /absolute/private/session-token
   ```

4. Import the private file's `access_token` value into `GOLDKEY_ACCESS_TOKEN`
   through the agent's secret store, then delete the newly created file. Never put
   the token in a command argument, shell history, log, or prompt. Then inspect
   quota or execute a tool:

   ```sh
   node "{baseDir}/scripts/goldkey-client.mjs" quota
   node "{baseDir}/scripts/goldkey-client.mjs" tool --name security.url_check --idempotency request-0001 --input '{"url":"https://example.com"}'
   ```

Use a fresh, stable idempotency key for each distinct pass-gated request. Reuse a key only for an exact retry of the same tool and input. A child-agent key begins with `gk_`; treat it like a password and obey its tool and call caps.

The current owner may issue and revoke up to 64 active scoped child-agent keys. The `access_key` returned by `key-issue` is shown once; inject it as `GOLDKEY_ACCESS_TOKEN` in the child's secret store. Every child draws from the pass's shared quota.

```sh
node "{baseDir}/scripts/goldkey-client.mjs" key-issue --secret-output /absolute/private/child-key --body '{"label":"action-worker-1","max_calls":500,"tools":["action.gate"]}'
node "{baseDir}/scripts/goldkey-client.mjs" keys-list
node "{baseDir}/scripts/goldkey-client.mjs" key-revoke --id KEY_ID
```

Import the private file's `access_key` value into the child agent's secret store,
then delete the newly created file. The stdout response contains only a redacted
placeholder for the credential.

## Select the narrowest tool

- `action.gate`: recommended pre-action `ALLOW`, `REVIEW`, or `BLOCK` decision across the supplied action, prompt, Unicode, URL, payload-schema, and spend-mandate checks, with a deterministic, reproducible receipt hash.
- `json.canonicalize`: deterministic serialization and SHA-256.
- `json.validate`: bounded JSON Schema validation without coercion or remote references.
- `security.prompt_scan`: deterministic signals and spans, not a safety guarantee.
- `security.url_check`: static URL screening; it does not fetch the URL.
- `policy.spend_check`: exact atomic-unit mandate evaluation.
- `text.normalize`: Unicode normalization and optional control/bidi removal.

Fetch `/openapi.json` for current request schemas. Do not send secrets inside
tool inputs. To inspect the exact live x402 requirement without executing the
tool, run:

```sh
node "{baseDir}/scripts/goldkey-client.mjs" paygo-probe --name security.url_check --input '{"url":"https://example.com"}'
```

Pass the returned `payment_required` value to the caller's installed x402 wallet
tool and let that tool sign and settle under its own mandate. This bundle never
accepts a wallet private key and never fabricates payment headers.

## Stop conditions

Stop and return the exact service error when contract identity, ownership, term activity, quota, authorization, payment settlement, or live supply cannot be verified. Do not retry a settled paygo call as though it were free; each settled retry is another purchase.
