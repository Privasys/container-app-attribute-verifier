# Contributing

Thank you for your interest in the Privasys Attribute Verifier.

## Layout

| Path | Purpose |
| --- | --- |
| [`cmd/attribute-verifier`](cmd/attribute-verifier) | The service: wiring, data volume, key ledger, HTTP server. |
| [`internal/server`](internal/server) | HTTP surface, configure gate, request checks, rate limits. |
| [`internal/sources`](internal/sources) | The business logic per kind of material: OIDC ID tokens, GitHub, mail codes, card checks. |
| [`internal/archive`](internal/archive) | The provider-key ledger on [immutable-ledger](https://github.com/Privasys/immutable-ledger). |
| [`internal/proof`](internal/proof) | The proof and the disclosure token. |
| [`internal/holder`](internal/holder) | Holder and device signatures, commitments, challenges. |
| [`internal/wia`](internal/wia) | Wallet Instance Attestation checks. |
| [`internal/jose`](internal/jose) | Minimal JWS, JWK and canonical JSON. |
| [`internal/mail`](internal/mail) | Verification codes through Microsoft Graph. |
| [`internal/platform`](internal/platform) | Callbacks to the enclave manager. |

## Building and testing

```bash
go vet ./...
go test -race ./...
gofmt -l .
```

## Contributor Licence Agreement

Pull requests need the Privasys Contributor Licence Agreement; the CLA
check on the pull request walks you through it.
