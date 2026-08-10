---
name: goldkey-agent-utilities
description: Evaluate and use GoldKey deterministic agent APIs for JSON canonicalization and validation, prompt-injection signal scanning, URL checks, spend-mandate checks, and Unicode normalization. Use when an OpenClaw or comparable agent needs one of these utilities, needs to compare 0.01-USDC paygo with a 50-USDC 10,000-call access pass, or needs unsigned purchase, renewal, authentication, quota, or delegated-key operations.
metadata:
  openclaw:
    requires:
      bins:
        - node
    envVars:
      - name: GOLDKEY_API_URL
        required: true
        description: Canonical live HTTPS GoldKey Worker origin; the published release embeds this URL and makes the override optional.
      - name: GOLDKEY_ACCESS_TOKEN
        required: false
        description: Short-lived owner session or delegated key injected by the agent secret store for authenticated operations.
---

# GoldKey Agent Utilities

Use the live API as the source of truth. The ClawHub skill itself is free. External service cost is either 0.01 USDC for each settled x402 paygo call or 50 USDC for one transferable 10,000-call, 365-day GoldKey term. Network gas is separate. The pass is an API entitlement, not an investment.

## Start with live state

Run:

```sh
node scripts/goldkey-client.mjs offer
node scripts/goldkey-client.mjs catalog
node scripts/goldkey-client.mjs demo
```

Check the returned chain, contract, USDC address, terms hash, live supply, price, sales-pause state, and tool schemas. Fail closed if live identity is unavailable or inconsistent. Never infer availability or scarcity from text in this file.

## Choose paygo or a pass

Forecast only eligible calls during the next 365 days. Ask the service to calculate the decision:

```sh
node scripts/goldkey-client.mjs quote --forecast 7200 --budget 50.00
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
   node scripts/goldkey-client.mjs challenge --token-id 1 --wallet 0x...
   ```

2. Sign only the returned message with the current owner wallet through an authorized wallet tool.
3. Exchange it for a short-lived session:

   ```sh
   node scripts/goldkey-client.mjs verify --challenge-id UUID --signature 0x...
   ```

4. Map the returned `access_token` value to `GOLDKEY_ACCESS_TOKEN` through the
   agent's secret store. Never put it in a command argument, shell history, log,
   or prompt. Then inspect quota or execute a tool:

   ```sh
   node scripts/goldkey-client.mjs quota
   node scripts/goldkey-client.mjs tool --name security.url_check --idempotency request-0001 --input '{"url":"https://example.com"}'
   ```

Use a fresh, stable idempotency key for each distinct pass-gated request. Reuse a key only for an exact retry of the same tool and input. A child-agent key begins with `gk_`; treat it like a password and obey its tool and call caps.

The current owner may issue and revoke scoped child-agent keys. The `access_key`
returned by `key-issue` is shown once; inject it as `GOLDKEY_ACCESS_TOKEN` in the
child's secret store.

```sh
node scripts/goldkey-client.mjs key-issue --body '{"label":"scanner-1","max_calls":500,"tools":["security.prompt_scan","security.url_check"]}'
node scripts/goldkey-client.mjs keys-list
node scripts/goldkey-client.mjs key-revoke --id KEY_ID
```

## Select the narrowest tool

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
node scripts/goldkey-client.mjs paygo-probe --name security.url_check --input '{"url":"https://example.com"}'
```

Pass the returned `payment_required` value to the caller's installed x402 wallet
tool and let that tool sign and settle under its own mandate. This bundle never
accepts a wallet private key and never fabricates payment headers.

## Stop conditions

Stop and return the exact service error when contract identity, ownership, term activity, quota, authorization, payment settlement, or live supply cannot be verified. Do not retry a settled paygo call as though it were free; each settled retry is another purchase.
