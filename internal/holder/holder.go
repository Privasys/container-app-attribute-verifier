// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package holder checks who is asking.
//
// Every request carries two signatures over the same message:
//
//   - the holder key hk, derived by the wallet from its seed for this
//     verifier only, the same on every device of the holder. It proves
//     "the same holder who imported this material".
//   - the device key, the hardware key of the device making the call. A
//     proof is bound to it, and sharing a proof needs its signature, so
//     the hardware binding is as strong as the device.
//
// Third parties never see hk. They see a commitment to it,
// base64url(SHA-256(SEC1(hk) || salt)), with a fresh random salt each
// time, so two imports or two card checks by the same holder cannot be
// linked by anyone but this verifier.
package holder

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Privasys/container-app-attribute-verifier/internal/jose"
	"github.com/Privasys/container-app-attribute-verifier/internal/keys"
)

// SaltLen is the commitment salt length.
const SaltLen = 16

// Commitment is base64url(SHA-256(SEC1(pub) || salt)).
func Commitment(pubSEC1, salt []byte) string {
	h := sha256.New()
	h.Write(pubSEC1)
	h.Write(salt)
	return jose.B64(h.Sum(nil))
}

// DeviceBinding is base64url(SHA-256(SEC1(device))).
func DeviceBinding(pubSEC1 []byte) string {
	h := sha256.Sum256(pubSEC1)
	return jose.B64(h[:])
}

// Equal compares two encoded values in constant time.
func Equal(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Holder is the holder block of a request.
type Holder struct {
	HKPub string `json:"hk_pub"`
	Salt  string `json:"salt"`
	Sig   string `json:"sig"`
}

// Device is the device block of a request.
type Device struct {
	Pub string `json:"pub"`
	Sig string `json:"sig"`
}

// Checked is what a verified request establishes.
type Checked struct {
	HKPub      []byte
	Salt       []byte
	Commitment string
	DevicePub  *ecdsa.PublicKey
	DeviceSEC1 []byte
	Device     string // DeviceBinding
}

// CheckBoth verifies both signatures over msg and returns the bindings.
func CheckBoth(h *Holder, d *Device, msg []byte) (*Checked, error) {
	if h == nil || d == nil {
		return nil, errors.New("holder and device signatures are required")
	}
	hc, err := CheckHolder(h, msg)
	if err != nil {
		return nil, err
	}
	c, err := CheckDevice(d, msg)
	if err != nil {
		return nil, err
	}
	c.HKPub, c.Salt, c.Commitment = hc.HKPub, hc.Salt, hc.Commitment
	return c, nil
}

// CheckHolder verifies the holder-key signature alone. The holder key lives
// in software (derived from the seed), so signing with it needs no biometric;
// it proves which holder, not which device.
func CheckHolder(h *Holder, msg []byte) (*Checked, error) {
	if h == nil {
		return nil, errors.New("a holder signature is required")
	}
	hkRaw, err := jose.UnB64(h.HKPub)
	if err != nil {
		return nil, errors.New("holder.hk_pub is not base64url")
	}
	hk, err := jose.ParseSEC1(hkRaw)
	if err != nil {
		return nil, fmt.Errorf("holder.hk_pub: %w", err)
	}
	salt, err := jose.UnB64(h.Salt)
	if err != nil || len(salt) != SaltLen {
		return nil, fmt.Errorf("holder.salt must be %d bytes, base64url", SaltLen)
	}
	hsig, err := jose.UnB64(h.Sig)
	if err != nil || !jose.VerifyES256Raw(hk, msg, hsig) {
		return nil, errors.New("the holder signature does not verify")
	}
	return &Checked{HKPub: hkRaw, Salt: salt, Commitment: Commitment(hkRaw, salt)}, nil
}

// CheckDevice verifies the device signature over msg.
func CheckDevice(d *Device, msg []byte) (*Checked, error) {
	if d == nil {
		return nil, errors.New("a device signature is required")
	}
	raw, err := jose.UnB64(d.Pub)
	if err != nil {
		return nil, errors.New("device.pub is not base64url")
	}
	pub, err := jose.ParseSEC1(raw)
	if err != nil {
		return nil, fmt.Errorf("device.pub: %w", err)
	}
	sig, err := jose.UnB64(d.Sig)
	if err != nil || !jose.VerifyES256Raw(pub, msg, sig) {
		return nil, errors.New("the device signature does not verify")
	}
	return &Checked{DevicePub: pub, DeviceSEC1: raw, Device: DeviceBinding(raw)}, nil
}

// ── challenges ─────────────────────────────────────────────────────────

// ChallengeTyp is the JOSE typ of a challenge token.
const ChallengeTyp = "application/privasys-av-challenge+jws"

// ChallengeTTL bounds how long a challenge may be answered.
const ChallengeTTL = 2 * time.Minute

// Challenges issues stateless challenge tokens and remembers the ones
// spent until they expire, so each answers exactly one request.
type Challenges struct {
	signer *keys.Signer
	now    func() time.Time

	mu    sync.Mutex
	spent map[string]time.Time
}

// NewChallenges returns an issuer.
func NewChallenges(s *keys.Signer, now func() time.Time) *Challenges {
	return &Challenges{signer: s, now: now, spent: map[string]time.Time{}}
}

type challengeClaims struct {
	N   string `json:"n"`
	Exp int64  `json:"exp"`
}

// Issue returns a fresh challenge token.
func (c *Challenges) Issue() (string, int64, error) {
	n := make([]byte, 16)
	if _, err := rand.Read(n); err != nil {
		return "", 0, err
	}
	exp := c.now().Add(ChallengeTTL).Unix()
	tok, err := c.signer.Sign(ChallengeTyp, challengeClaims{N: jose.B64(n), Exp: exp})
	return tok, exp, err
}

// Spend checks a challenge token and marks it used.
func (c *Challenges) Spend(token string) error {
	var cl challengeClaims
	if _, err := jose.VerifyWith(token, &c.signer.Key.PublicKey, ChallengeTyp, &cl); err != nil {
		return errors.New("the challenge is not one this verifier issued")
	}
	now := c.now()
	if cl.Exp < now.Unix() {
		return errors.New("the challenge has expired; ask for a new one")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for n, exp := range c.spent {
		if exp.Before(now) {
			delete(c.spent, n)
		}
	}
	if _, used := c.spent[cl.N]; used {
		return errors.New("the challenge was already used")
	}
	c.spent[cl.N] = time.Unix(cl.Exp, 0)
	return nil
}
