// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package wia checks Wallet Instance Attestations.
//
// The verifier's proofs are free and open to the holder's wallet only. A
// holder-key signature cannot show that: anyone can make a seed. What can
// is the Wallet Instance Attestation privasys.id issues after checking the
// device's own attestation (App Attest, Android key attestation): a short
// JWT whose cnf.jwk is the device's hardware key. Every call that does
// work must carry one, bound to the key that signed the call.
package wia

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Privasys/container-app-attribute-verifier/internal/jose"
)

// JWKS is the set of wallet-provider keys, provisioned by configure.
type JWKS struct {
	Keys []jose.JWK `json:"keys"`
}

// Validate refuses anything but usable P-256 keys with ids.
func (j JWKS) Validate() error {
	if len(j.Keys) == 0 {
		return errors.New("wallet_provider_jwks has no keys")
	}
	for _, k := range j.Keys {
		if k.Kid == "" {
			return errors.New("every wallet-provider key needs a kid")
		}
		pub, err := k.Public()
		if err != nil {
			return err
		}
		if _, ok := pub.(*ecdsa.PublicKey); !ok {
			return errors.New("wallet-provider keys must be EC P-256")
		}
	}
	return nil
}

type claims struct {
	Exp json.Number `json:"exp"`
	Cnf struct {
		JWK jose.JWK `json:"jwk"`
	} `json:"cnf"`
}

// Verify checks token against the JWKS and that it binds device.
func Verify(j JWKS, token string, device *ecdsa.PublicKey, now time.Time) error {
	cnf, err := Device(j, token, now)
	if err != nil {
		return err
	}
	if !jose.SameECKey(cnf, jose.ECJWK(device)) {
		return errors.New("wia: cnf.jwk is not the device key that signed the request")
	}
	return nil
}

// Device checks token against the JWKS and returns the device key it names,
// without proof that the caller holds that key. Used only where the call
// itself creates nothing bound to the device (asking for a mail code), so a
// biometric prompt for the hardware key is not worth it there.
func Device(j JWKS, token string, now time.Time) (jose.JWK, error) {
	if token == "" {
		return jose.JWK{}, errors.New("a Wallet Instance Attestation is required")
	}
	p, err := jose.Parse(token)
	if err != nil {
		return jose.JWK{}, fmt.Errorf("wia: %w", err)
	}
	var key *jose.JWK
	for i := range j.Keys {
		if p.Header.Kid == "" || j.Keys[i].Kid == p.Header.Kid {
			key = &j.Keys[i]
			if p.Header.Kid != "" {
				break
			}
		}
	}
	if key == nil {
		return jose.JWK{}, errors.New("wia: no wallet-provider key matches")
	}
	pub, err := key.Public()
	if err != nil {
		return jose.JWK{}, err
	}
	if err := p.Verify(pub); err != nil {
		return jose.JWK{}, fmt.Errorf("wia: %w", err)
	}
	var c claims
	if err := p.Claims(&c); err != nil {
		return jose.JWK{}, errors.New("wia: unreadable claims")
	}
	exp, err := c.Exp.Int64()
	if err != nil || exp < now.Unix() {
		return jose.JWK{}, errors.New("wia: expired or without exp")
	}
	if _, err := c.Cnf.JWK.Public(); err != nil {
		return jose.JWK{}, errors.New("wia: cnf.jwk is not a usable key")
	}
	return c.Cnf.JWK, nil
}
