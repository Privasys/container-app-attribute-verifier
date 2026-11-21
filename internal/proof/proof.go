// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package proof is the verifier's output: one signed statement per
// attribute, the same shape whatever the source.
//
// A proof says which attribute, its value, how it was established
// (method), who vouches for it (source), when the source asserted it, and
// the evidence that lets anyone check it later. It is bound to the holder
// two ways: a commitment to the holder key, the same on all their devices,
// and the hash of one device's hardware key. The wallet keeps it; the
// verifier keeps nothing.
//
// Apps never receive a proof. At sharing time the wallet asks for a
// disclosure: a fresh, short-lived SD-JWT VC addressed to one app and
// bound to the device key, which privasys.id relays inside the sign-in.
package proof

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/Privasys/container-app-attribute-verifier/internal/jose"
	"github.com/Privasys/container-app-attribute-verifier/internal/keys"
)

// JOSE types.
const (
	Typ           = "application/privasys-attribute-proof+jws"
	DisclosureTyp = "dc+sd-jwt"
	DisclosureVCT = "https://privasys.org/vct/attribute-disclosure"
)

// Methods: the only two.
const (
	// Proven: the verifier checked cryptographic or back-office evidence.
	Proven = "proven"
	// Observed: the verifier saw it itself, over TLS, from inside the
	// enclave. It cannot be replayed later from raw material.
	Observed = "observed"
)

// DisclosureTTL is how long a disclosure lives.
const DisclosureTTL = 5 * time.Minute

// Binding ties a proof to its holder and one device.
type Binding struct {
	Commitment string `json:"commitment"`
	Device     string `json:"device"`
}

// Proof is the signed payload.
type Proof struct {
	JTI         string         `json:"jti"`
	Iss         string         `json:"iss"`
	Iat         int64          `json:"iat"`
	Attr        string         `json:"attr"`
	Value       any            `json:"value"`
	Method      string         `json:"method"`
	Source      string         `json:"source"`
	Label       map[string]any `json:"label,omitempty"`
	MaterialAt  int64          `json:"material_at"`
	Evidence    map[string]any `json:"evidence"`
	Holder      Binding        `json:"holder"`
	Measurement string         `json:"measurement"`
}

// NewJTI returns a random proof id.
func NewJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return jose.B64(b)
}

// Sign signs p.
func Sign(s *keys.Signer, p Proof) (string, error) {
	if p.Method != Proven && p.Method != Observed {
		return "", fmt.Errorf("proof: method %q", p.Method)
	}
	return s.Sign(Typ, p)
}

// Verify checks a proof this verifier signed and returns it.
func Verify(s *keys.Signer, token string) (*Proof, error) {
	var p Proof
	parsed, err := jose.VerifyWith(token, &s.Key.PublicKey, Typ, &p)
	if err != nil {
		return nil, errors.New("the proof is not one this verifier signed")
	}
	if parsed.Header.Kid != s.Kid {
		return nil, errors.New("the proof was signed by another key; re-attest it from its material")
	}
	return &p, nil
}

// Disclosure is the SD-JWT VC payload an app receives through privasys.id.
type Disclosure struct {
	Iss      string         `json:"iss"`
	Sub      string         `json:"sub"`
	Aud      string         `json:"aud"`
	VCT      string         `json:"vct"`
	Claim    string         `json:"claim"`
	Value    any            `json:"value"`
	Method   string         `json:"method"`
	Source   string         `json:"source"`
	Label    map[string]any `json:"label,omitempty"`
	Evidence map[string]any `json:"evidence"`
	Nonce    string         `json:"nonce"`
	Iat      int64          `json:"iat"`
	Exp      int64          `json:"exp"`
	Cnf      struct {
		JWK jose.JWK `json:"jwk"`
	} `json:"cnf"`
}

// Disclose mints a disclosure of p for one app. Every claim is disclosed
// in the clear (it carries exactly the one value the holder agreed to
// share), so the serialisation is the JWS followed by "~": a valid SD-JWT
// with no disclosures, as the Identity Verifier issues.
func Disclose(s *keys.Signer, p *Proof, iss, sub, aud, nonce string, device jose.JWK, now time.Time) (string, error) {
	d := Disclosure{
		Iss: iss, Sub: sub, Aud: aud, VCT: DisclosureVCT,
		Claim: p.Attr, Value: p.Value, Method: p.Method, Source: p.Source, Label: p.Label,
		// Only what an app needs to judge the value. The material's
		// digest, the provider's subject and the holder commitment stay in
		// the wallet's proof.
		Evidence: map[string]any{
			"proof":       p.JTI,
			"material_at": p.MaterialAt,
			"attested_at": p.Iat,
			"measurement": p.Measurement,
		},
		Nonce: nonce,
		Iat:   now.Unix(),
		Exp:   now.Add(DisclosureTTL).Unix(),
	}
	d.Cnf.JWK = device
	tok, err := s.Sign(DisclosureTyp, d)
	if err != nil {
		return "", err
	}
	return tok + "~", nil
}
