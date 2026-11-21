// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package keys holds the verifier's key material on its sealed volume.
//
// Everything here is generated inside the enclave on first boot and never
// leaves it: the signing key whose public half is the verifier's identity,
// the ledger's commitment key, and the key that seals mail codes. The
// volume is released to this app by its identity, not by its build, so the
// keys survive an upgrade and proofs signed before it still verify after.
package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Privasys/container-app-attribute-verifier/internal/jose"
)

// Signer is the verifier's signing key.
type Signer struct {
	Key *ecdsa.PrivateKey
	// Kid is base64url(SHA-256(SPKI DER)).
	Kid string
}

// Public is the public JWK, with kid, use and alg.
func (s *Signer) Public() jose.JWK {
	j := jose.ECJWK(&s.Key.PublicKey)
	j.Kid, j.Use, j.Alg = s.Kid, "sig", "ES256"
	return j
}

// Sign signs payload as a compact JWS of type typ.
func (s *Signer) Sign(typ string, payload any) (string, error) {
	return jose.Sign(s.Key, s.Kid, typ, payload)
}

func kidOf(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(der)
	return jose.B64(h[:]), nil
}

// LoadSigner reads dir/signing_key.pem, creating it on first boot.
func LoadSigner(dir string) (*Signer, error) {
	path := filepath.Join(dir, "signing_key.pem")
	raw, err := os.ReadFile(path)
	var key *ecdsa.PrivateKey
	switch {
	case err == nil:
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, errors.New("keys: signing_key.pem is not PEM")
		}
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("keys: signing key: %w", err)
		}
		key = k
	case errors.Is(err, os.ErrNotExist):
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		if err := writeAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("keys: %w", err)
	}
	kid, err := kidOf(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Signer{Key: key, Kid: kid}, nil
}

// Secret32 reads dir/name, a 32-byte secret, creating it on first boot.
func Secret32(dir, name string) ([32]byte, error) {
	var out [32]byte
	path := filepath.Join(dir, name)
	raw, err := os.ReadFile(path)
	if err == nil {
		if len(raw) != 32 {
			return out, fmt.Errorf("keys: %s is not 32 bytes", name)
		}
		copy(out[:], raw)
		return out, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return out, fmt.Errorf("keys: %w", err)
	}
	if _, err := rand.Read(out[:]); err != nil {
		return out, err
	}
	return out, writeAtomic(path, out[:])
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
