# Security Policy

GoldKey Guard is beta software and has not been independently audited or
certified. Security reports are welcome; this policy does not create a bug
bounty, service-level agreement, or guarantee of payment.

## Supported versions

| Component | Status |
|---|---|
| Current main branch and hosted beta | Supported |
| Local enforcer v0.2.1 | Supported |
| Earlier enforcer prereleases | Unsupported; reproduce against v0.2.1 first |

## Report a vulnerability privately

Use GitHub's private advisory form:

https://github.com/noah-ing/goldkey/security/advisories/new

If that form is unavailable, open a public issue that asks for a private
reporting channel, but include no exploit details, credentials, customer data,
or vulnerable endpoint parameters in the issue.

Include, when possible:

- the affected component, version, and commit;
- the security boundary or invariant that can be bypassed;
- minimal reproduction steps using test accounts and testnet assets;
- expected and observed behavior;
- impact, preconditions, and any suggested remediation; and
- whether the issue is already public or under active exploitation.

Do not test against another person's wallet, installation, data, credentials,
or production workflow. Do not submit irreversible mainnet transactions,
degrade the hosted service, exfiltrate data, or retain data beyond what is
strictly necessary to demonstrate the issue.

## Priority areas

High-value reports include:

- forged, replayed, expired, or incorrectly bound authorization receipts;
- bypasses that let an agent reach a protected connector or signer directly;
- policy, schema, destination, spend, idempotency, or installation-binding
  failures;
- extraction of protected upstream credentials or signing material;
- payment or quota accounting errors that create unauthorized execution; and
- transaction-construction flaws that violate documented EVM constraints.

Reports about expected beta limitations, unsupported deployment topologies,
denial of service without a security boundary bypass, social engineering, or
issues that require prior compromise of the operator-controlled host may be
closed as out of scope.

## Handling and disclosure

The maintainer will aim to acknowledge a complete report within three business
days, provide a preliminary assessment within seven business days, and
coordinate remediation and disclosure based on severity and exploitability.
These are targets, not guarantees.

Please allow a reasonable remediation window before public disclosure.
Good-faith research that follows this policy, minimizes harm, and complies with
applicable law will not be pursued by the maintainer merely for identifying
and privately reporting a vulnerability.
