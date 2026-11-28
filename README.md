# Privasys Attribute Verifier

A confidential app that checks the evidence behind an attribute in a
Privasys wallet and signs a proof of it. It is the counterpart of the
[Privasys Identity Verifier](https://github.com/Privasys/container-app-identity-verifier),
which does the same for identity documents.

The wallet sends it raw material:

- an identity provider's signed ID token (Google, Microsoft, LinkedIn, any
  OIDC provider), from a sign-in the wallet started;
- an access token for GitHub, which issues no ID token;
- a code the verifier mailed to an address;
- the reference of a £0 card check of a billing address.

The verifier checks the material against trust anchors it holds, takes the
values it proves, and signs one proof per attribute. It keeps nothing about
people: the wallet stores the raw material and the proofs, and can ask for
the same material to be checked again at any time.

## What a proof says

| field | meaning |
|---|---|
| `attr`, `value` | the attribute and its value |
| `method` | `proven`: the verifier checked cryptographic or back-office evidence, or read the provider's own verified verdict from its API (GitHub's primary verified email). `observed`: the verifier saw it itself, over TLS, from inside the enclave, and nobody vouches for it (a GitHub name or picture) |
| `source` | who vouches: `google`, `microsoft`, `linkedin`, `oidc:<issuer>`, `github`, `privasys_mail`, `card_bank` |
| `label` | display data, e.g. the card's brand and country |
| `material_at` | when the source asserted the value; never the time of a later re-check |
| `evidence` | what lets anyone check the proof later: the material's digest and, for a provider token, the provider's key as the verifier recorded it |
| `holder` | a commitment to the holder's key, and the hash of one device's hardware key |
| `measurement` | the image digest of the build that signed it |

Only what passed is signed. An address a provider has not verified, or a
billing address the card's bank did not fully confirm, is left out.

## Rules per source

- **Google**: issuer, audience (privasys.id's client), signature with the
  key Google published at the token's time, `email` only with
  `email_verified: true`.
- **Microsoft**: issuer of the token's own tenant, audience, signature,
  `oid` present, `email` only with `xms_edov: true` or from a tenant
  configured as vouching for its own addresses.
- **LinkedIn and other OIDC providers**: the same pattern from their
  definition.
- **GitHub**: the verifier calls `api.github.com` itself and records the
  primary address only if GitHub marks it verified. That address is
  `proven` (GitHub's verified flag counts as verified, as Google's
  `email_verified` does); name and picture are `observed`.
- **Mail code**: the verifier mails the code and checks it; the pending
  code is sealed in a token only the enclave can open, and dies after five
  wrong tries.
- **Card check**: the verifier asks the Privasys back office whether the
  check exists, was started by this holder and matches these fields, and
  signs the address only when the card's bank confirmed both the street line
  and the postcode, with the original check time. Card address checks are
  loose (UK banks compare the house number and the postcode digits only),
  and what they confirm is the billing address the bank holds, not where
  the holder lives now: the proof says `scope: billing_address`.

## Binding to the holder

Every call is signed by two keys:

- the **holder key**, derived by the wallet from its seed for this
  verifier only, the same on all the holder's devices;
- the **device key**, the device's hardware key, attested by a Wallet
  Instance Attestation.

Third parties never see the holder key, only a commitment to it with a
fresh random salt each time: the OIDC nonce of the sign-in the wallet
started, and the binding the back office stores with a card check. A token
or check obtained by one holder therefore cannot be imported by another,
and two imports by the same holder cannot be linked.

A proof is bound to one device. When it reaches another device of the same
holder, that device sends it back (`attest` kind `proof`), signed by the
holder key, and gets its own.

Apps never receive proofs. At sharing time the wallet asks for a
disclosure: a short-lived SD-JWT VC of one proof, addressed to one app and
bound to the device key, which privasys.id relays inside the sign-in.

## Provider keys over time

Providers publish their keys as unsigned JSON and drop old ones within
weeks. The verifier fetches every key set hourly over TLS and records each
key, with when it was first and last seen, in an
[immutable ledger](https://github.com/Privasys/immutable-ledger) on its
sealed volume. Every proof carries the key record signed by the verifier,
so it can be checked years later with no access to the verifier. Each
build that opens the ledger records itself and the state it found, so the
chain of builds and keys is continuous across upgrades.

A build writes its version record with its signing key, and the key signs
nothing until its digest is attested (see below). When the key is not yet
attested at start-up, the version record is written as soon as it is. A
ledger record signed in that same moment can therefore land just before the
build's version record. Match records to builds by the signing key (`kid`),
not by their order in the ledger.

## Attestation

| OID | value |
|---|---|
| `1.3.6.1.4.1.65230.4.1` | the app id (set by the platform) |
| `1.3.6.1.4.1.65230.4.2` | the image digest (set by the platform) |
| `1.3.6.1.4.1.65230.5.4.1` | SHA-256 of the configuration in force, secrets excluded |
| `1.3.6.1.4.1.65230.5.4.2` | the provider-key ledger's root |
| `1.3.6.1.4.1.65230.5.4.3` | SHA-256 of the signing key's SubjectPublicKeyInfo (DER); the `kid` is its base64url |

The `5.4.x` values are set by the app itself. A relying party trusts the
signing key only after checking, on the same certificate, `4.1` (this app)
and `4.2` (a published release) as well as `5.4.3`. Until its digest is
attested the key signs nothing, and the routes that sign answer 503.

## API

See [`privasys.json`](privasys.json). The work endpoints are `GET
/challenge`, `POST /attest`, `POST /mail/start` and `POST /disclose`.
`GET /.well-known/jwks.json`, `GET /evidence/keys/{source}/{kid}` and `GET
/ledger/root` serve what a reader needs to check a proof.

## Building

```sh
go test ./...
docker build -t attribute-verifier .
```

Licensed under the GNU Affero General Public License v3.0.
