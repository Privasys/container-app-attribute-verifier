// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package jose holds the small amount of JOSE the verifier needs: compact
// JWS with ES256 (its own signatures, the wallet provider's) and RS256 (the
// identity providers'), public JWKs, and the canonical JSON both sides sign.
//
// It is deliberately minimal. Every token the verifier accepts names its
// algorithm, and only the algorithm the key type allows is honoured, so
// "alg: none" and algorithm confusion have no path in.
package jose

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// B64 encodes without padding, URL-safe.
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// UnB64 decodes URL-safe base64, with or without padding.
func UnB64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// Canonical is JSON with sorted object keys, no insignificant whitespace,
// and no HTML escaping: the bytes JavaScript's JSON.stringify produces for
// the same sorted object, so a wallet and the verifier sign the same thing.
// Values must be maps, slices, strings, booleans, nil or integers.
func Canonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	// encoding/json sorts map keys; round-trip structs through a map so
	// their keys are sorted too.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	if err := enc.Encode(generic); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Digest is base64url(SHA-256(canonical(v))).
func Digest(v any) (string, error) {
	c, err := Canonical(v)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(c)
	return B64(h[:]), nil
}

// JWK is a public key in the two shapes the verifier meets.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	// EC
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
}

// Public returns the key the JWK describes.
func (k JWK) Public() (crypto.PublicKey, error) {
	switch k.Kty {
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("jose: curve %q is not supported", k.Crv)
		}
		x, err1 := UnB64(k.X)
		y, err2 := UnB64(k.Y)
		if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
			return nil, errors.New("jose: malformed EC key")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("jose: EC point is not on the curve")
		}
		return pub, nil
	case "RSA":
		n, err1 := UnB64(k.N)
		e, err2 := UnB64(k.E)
		if err1 != nil || err2 != nil || len(n) < 256 || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("jose: malformed or short RSA key")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	}
	return nil, fmt.Errorf("jose: key type %q is not supported", k.Kty)
}

// Thumbprint is the RFC 7638 JWK thumbprint, base64url.
func (k JWK) Thumbprint() (string, error) {
	var m map[string]string
	switch k.Kty {
	case "EC":
		m = map[string]string{"crv": k.Crv, "kty": k.Kty, "x": k.X, "y": k.Y}
	case "RSA":
		m = map[string]string{"e": k.E, "kty": k.Kty, "n": k.N}
	default:
		return "", fmt.Errorf("jose: key type %q is not supported", k.Kty)
	}
	return Digest(m)
}

// ECJWK is the minimal public JWK (kty, crv, x, y) of a P-256 key.
func ECJWK(pub *ecdsa.PublicKey) JWK {
	b := pub.X.FillBytes(make([]byte, 32))
	c := pub.Y.FillBytes(make([]byte, 32))
	return JWK{Kty: "EC", Crv: "P-256", X: B64(b), Y: B64(c)}
}

// SameECKey compares two JWKs by their EC coordinates only.
func SameECKey(a, b JWK) bool {
	return a.Kty == "EC" && b.Kty == "EC" && a.Crv == b.Crv && a.X == b.X && a.Y == b.Y
}

// ParseSEC1 reads an uncompressed P-256 point (0x04 || X || Y).
func ParseSEC1(raw []byte) (*ecdsa.PublicKey, error) {
	if len(raw) != 65 || raw[0] != 4 {
		return nil, errors.New("jose: a P-256 public key must be 65 bytes, uncompressed")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(),
		X: new(big.Int).SetBytes(raw[1:33]), Y: new(big.Int).SetBytes(raw[33:])}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("jose: the public key is not on P-256")
	}
	return pub, nil
}

// SEC1 encodes a P-256 public key uncompressed.
func SEC1(pub *ecdsa.PublicKey) []byte {
	out := make([]byte, 65)
	out[0] = 4
	pub.X.FillBytes(out[1:33])
	pub.Y.FillBytes(out[33:])
	return out
}

// VerifyES256Raw checks a raw r||s ECDSA P-256 signature over SHA-256(msg).
func VerifyES256Raw(pub *ecdsa.PublicKey, msg, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	h := sha256.Sum256(msg)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, h[:], r, s)
}

// SignES256Raw signs SHA-256(msg) and returns r||s.
func SignES256Raw(key *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	h := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(cryptoRand, key, h[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// Header is the protected header of a compact JWS.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
}

// Sign produces a compact ES256 JWS over payload.
func Sign(key *ecdsa.PrivateKey, kid, typ string, payload any) (string, error) {
	h, err := json.Marshal(Header{Alg: "ES256", Typ: typ, Kid: kid})
	if err != nil {
		return "", err
	}
	p, err := Canonical(payload)
	if err != nil {
		return "", err
	}
	input := B64(h) + "." + B64(p)
	sig, err := SignES256Raw(key, []byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + B64(sig), nil
}

// Parsed is a compact JWS split into its parts, signature not yet checked.
type Parsed struct {
	Header  Header
	Payload []byte
	input   []byte
	sig     []byte
}

// Parse splits a compact JWS without verifying it.
func Parse(token string) (*Parsed, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jose: not a compact JWS")
	}
	hb, err := UnB64(parts[0])
	if err != nil {
		return nil, errors.New("jose: header is not base64url")
	}
	var h Header
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, errors.New("jose: header is not JSON")
	}
	pb, err := UnB64(parts[1])
	if err != nil {
		return nil, errors.New("jose: payload is not base64url")
	}
	sig, err := UnB64(parts[2])
	if err != nil {
		return nil, errors.New("jose: signature is not base64url")
	}
	return &Parsed{Header: h, Payload: pb, input: []byte(parts[0] + "." + parts[1]), sig: sig}, nil
}

// Verify checks the signature with pub, honouring only the algorithm the
// key type allows.
func (p *Parsed) Verify(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if p.Header.Alg != "ES256" {
			return fmt.Errorf("jose: alg %q with an EC key", p.Header.Alg)
		}
		if !VerifyES256Raw(k, p.input, p.sig) {
			return errors.New("jose: bad signature")
		}
		return nil
	case *rsa.PublicKey:
		if p.Header.Alg != "RS256" {
			return fmt.Errorf("jose: alg %q with an RSA key", p.Header.Alg)
		}
		h := sha256.Sum256(p.input)
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], p.sig); err != nil {
			return errors.New("jose: bad signature")
		}
		return nil
	}
	return errors.New("jose: unsupported key")
}

// Claims decodes the payload into v, keeping numbers exact.
func (p *Parsed) Claims(v any) error {
	dec := json.NewDecoder(bytes.NewReader(p.Payload))
	dec.UseNumber()
	return dec.Decode(v)
}

// VerifyWith parses and verifies token with pub and decodes its claims.
func VerifyWith(token string, pub crypto.PublicKey, wantTyp string, into any) (*Parsed, error) {
	p, err := Parse(token)
	if err != nil {
		return nil, err
	}
	if wantTyp != "" && p.Header.Typ != wantTyp {
		return nil, fmt.Errorf("jose: typ %q, want %q", p.Header.Typ, wantTyp)
	}
	if err := p.Verify(pub); err != nil {
		return nil, err
	}
	if into != nil {
		if err := p.Claims(into); err != nil {
			return nil, fmt.Errorf("jose: claims: %w", err)
		}
	}
	return p, nil
}
