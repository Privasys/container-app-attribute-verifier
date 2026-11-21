# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately to
**security@privasys.org**. Do not open public issues for security
reports. We aim to acknowledge reports within 48 hours and to keep you
informed of progress; coordinated disclosure timelines are agreed per
report.

Please include what you can: affected commit or image digest, the kind
of material involved, reproduction steps, and an impact assessment.

## Scope

The verifier makes a small number of claims. A way to break any of them
is what we most want to hear about.

- **A proof means what it says.** A proof signed for a value its source
  did not prove: an unverified address, a Microsoft address without
  `xms_edov`, a card-check field that did not pass, a token signed by a
  key the provider never published, or a `material_at` later than the
  source's own time.
- **Material is the holder's.** Importing a provider token, mail code or
  card check that another holder obtained; rebinding another holder's
  proof; sharing a proof from a device it is not bound to.
- **Wallet only.** Getting any proof, mail or disclosure without a valid
  Wallet Instance Attestation bound to the signing device key.
- **Nothing about people is kept.** Any path that persists or logs a
  person's address, value, token or code.
- **Evidence stays checkable.** A key record or ledger state that a
  later build could rewrite without detection.
- **The configure gate.** Reaching a work endpoint before configuration,
  or configuring it without the platform authorisation the gate
  requires.

Out of scope: denial of service through resource exhaustion.

## What this project does not claim

The verifier is not certified and has not been independently audited.
The confidentiality of data at rest is the confidential VM's encrypted
volume. An `observed` proof (GitHub) records what the provider's API
answered over TLS at that time; it is not a signature of the provider.
