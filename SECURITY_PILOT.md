# GoldKey guarded integration pilot

**Fixed fee:** USD 10,000  
**Delivery target:** 10 business days after access and kickoff  
**Structure:** two independently accepted USD 5,000 milestones  
**Environment:** customer-owned staging only

## Outcome

This engagement puts one bounded AI-agent action behind an operator-controlled enforcement path before the action can reach a privileged MCP tool, HTTPS operation, or supported Base/EVM wallet signer.

It is a scoped implementation and evidence package. It is not a compliance certification, a blanket penetration test, or a promise that every vulnerability will be found or prevented.

## Milestone 1: threat model and control design — USD 5,000

Delivered within four business days:

1. Architecture and trust-boundary map for one named workflow.
2. Inventory of identities, credentials, signers, connectors, actions, data classes, and bypass routes.
3. Prioritized risk register covering prompt/tool injection, credential exposure, SSRF and destination drift, schema drift, replay, idempotency failure, confused-deputy behavior, overbroad wallet authority, payment-budget bypass, and ambiguous outcomes.
4. Written design for the single exclusive path to the protected capability.
5. Immutable draft policy identifying connector, allowed action or tool, input-schema hash, destination and method restrictions, spend limits where applicable, and explicit fail-closed behavior.
6. Adversarial acceptance-test plan with negative controls.

Milestone 1 is accepted when the six artifacts are delivered and reviewed against the agreed staging architecture, with one consolidated correction round included.

## Milestone 2: guarded staging integration — USD 5,000

Delivered within six business days after Milestone 1 acceptance:

1. One customer-hosted staging integration for either a local stdio MCP server and selected tool subset, one fixed HTTPS origin/method/path operation, or one supported Base/EVM operation family using a segregated test wallet.
2. Operator-owned local sidecar configuration. The sidecar—not the agent—holds the protected upstream transport, credential, or signer.
3. Installation identity, policy-hash pinning, signed short-lived authorization receipts, and durable idempotency/outcome state.
4. Fail-closed connector checks for action, tool, schema, destination, or policy drift.
5. Adversarial A/B tests for allowed and denied actions, replay, altered arguments, wrong destination, stale receipt, wrong installation, wrong policy, timeout, and interrupted forwarding.
6. Configuration templates, exact artifact hashes, test results, known limitations, recovery steps, and operator runbook.
7. One 60-minute technical walkthrough and one consolidated correction round.

Milestone 2 acceptance requires:

- the authorized control call succeeds exactly once;
- an unlisted action and changed input schema are denied before forwarding;
- a receipt for another call, installation, policy, or expired window is rejected;
- the agent has no direct path to the protected staging credential, transport, or signer;
- a crash or timeout after forwarding is recorded as ambiguous and is not automatically retried; and
- the supplied tests pass from the agreed clean configuration.

## Customer inputs

The customer provides written authorization, a named technical owner, one non-production integration target, synthetic fixtures, segregated test credentials or signer, a customer-controlled execution host, and availability for kickoff, design review, acceptance, and handoff.

Do not provide production secrets, seed phrases, real customer records, or non-test funds.

## Exclusions

The fixed fee excludes production exploitation, testing without written authorization, custody of funds or private keys, an organization-wide penetration test, compliance certification, legal advice, arbitrary contract calls, unsupported chains, more than one integration target, production deployment, 24/7 monitoring, incident response, and ongoing support. Additional scope requires a written change order.

## Commercial and safety terms

- Milestone 1 must be funded in escrow or paid at kickoff.
- Milestone 2 must be funded before implementation begins.
- Exact systems, dates, test accounts, permitted techniques, prohibited actions, stop conditions, emergency contact, confidentiality, IP, liability, taxes, payment method, and dispute procedure are set in a signed statement of work.
- Either party may stop immediately when authorization or scope is uncertain.
- Customer-controlled blockers are documented and resolved through a written equivalent test or schedule adjustment; acceptance never requires weakening a control.
- Pre-existing GoldKey code and reusable methods remain their existing owner's intellectual property. Customer-specific reports and configuration are delivered under the signed statement of work after payment.

## Smaller first step

A USD 1,000 control-design sprint is available for teams that need the Milestone 1 boundary narrowed before committing to implementation. It includes one workflow threat model, one connector/credential boundary, a draft policy, an acceptance plan, and one technical review session.

Apply through the private form on the [live GoldKey storefront](https://goldkey-edge-storefront.noah-ing.workers.dev/#pilot-application). Start the action description with `Guarded integration:` or `Design sprint:`. No payment is collected with the application.
