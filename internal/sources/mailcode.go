// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package sources

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/container-app-attribute-verifier/internal/holder"
	"github.com/Privasys/container-app-attribute-verifier/internal/jose"
	"github.com/Privasys/container-app-attribute-verifier/internal/keys"
)

// The mail-code ceremony runs here, in attested code, so the result is
// "proven": the verifier mailed a code to the address and the holder
// typed it back.
//
// The pending code lives in a token the wallet holds, not in the
// verifier: a JWS over the address, the holder commitment, an expiry and
// an HMAC of the code under a key only the enclave has. The wallet cannot
// read the code out of it, even by trying every value offline. What the
// verifier does keep, in memory and only until expiry, is how many wrong
// answers each token has had, so the code dies after five.

// Mail-code parameters.
const (
	MailCodeTTL     = 15 * time.Minute
	MailMaxAttempts = 5
	MailTokenTyp    = "application/privasys-av-mail+jws"
)

// Sender mails one code.
type Sender interface {
	SendCode(ctx context.Context, to, code string, ttl time.Duration) error
}

// MailCodes runs the ceremony.
type MailCodes struct {
	Signer *keys.Signer
	Key    [32]byte
	Sender Sender
	Now    func() time.Time

	mu       sync.Mutex
	attempts map[string]int
	spent    map[string]time.Time
}

type mailClaims struct {
	JTI        string `json:"jti"`
	Email      string `json:"email"`
	Commitment string `json:"c"`
	Code       string `json:"h"`
	Exp        int64  `json:"exp"`
}

// NormaliseEmail lowercases a bare address and refuses anything that is
// not one.
func NormaliseEmail(raw string) (string, bool) {
	t := strings.TrimSpace(raw)
	if t == "" || len(t) > 254 {
		return "", false
	}
	a, err := mail.ParseAddress(t)
	if err != nil || a.Name != "" || a.Address != t {
		return "", false
	}
	at := strings.LastIndex(a.Address, "@")
	if at <= 0 || at == len(a.Address)-1 || strings.ContainsAny(a.Address, " \t\r\n,;") {
		return "", false
	}
	return strings.ToLower(a.Address), true
}

func (m *MailCodes) mac(jti, code string) string {
	h := hmac.New(sha256.New, m.Key[:])
	h.Write([]byte(jti))
	h.Write([]byte{0})
	h.Write([]byte(code))
	return jose.B64(h.Sum(nil))
}

// Start mails a code to email for the holder committed to by commitment,
// and returns the token the wallet answers with.
func (m *MailCodes) Start(ctx context.Context, email, commitment string) (string, int64, error) {
	if m.Sender == nil {
		return "", 0, errors.New("mail is not configured")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", 0, err
	}
	code := fmt.Sprintf("%06d", n.Int64())
	jtiB := make([]byte, 16)
	if _, err := rand.Read(jtiB); err != nil {
		return "", 0, err
	}
	jti := jose.B64(jtiB)
	exp := m.Now().Add(MailCodeTTL).Unix()
	tok, err := m.Signer.Sign(MailTokenTyp, mailClaims{JTI: jti, Email: email, Commitment: commitment,
		Code: m.mac(jti, code), Exp: exp})
	if err != nil {
		return "", 0, err
	}
	if err := m.Sender.SendCode(ctx, email, code, MailCodeTTL); err != nil {
		return "", 0, err
	}
	return tok, exp, nil
}

// ErrWrongCode carries how many tries are left.
type ErrWrongCode struct{ Left int }

func (e *ErrWrongCode) Error() string {
	return fmt.Sprintf("that code is not right; %d tries left", e.Left)
}

// Complete checks the code typed back and returns the proven address.
func (m *MailCodes) Complete(token, email, code, commitment string) (*Result, error) {
	var c mailClaims
	if _, err := jose.VerifyWith(token, &m.Signer.Key.PublicKey, MailTokenTyp, &c); err != nil {
		return nil, errors.New("mail_token is not one this verifier issued")
	}
	now := m.Now()
	if c.Exp < now.Unix() {
		return nil, errors.New("the code has expired; ask for a new one")
	}
	norm, ok := NormaliseEmail(email)
	if !ok || norm != c.Email {
		return nil, errors.New("the code was sent to another address")
	}
	if !holder.Equal(c.Commitment, commitment) {
		return nil, errors.New("the code was asked for by another holder")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.attempts == nil {
		m.attempts, m.spent = map[string]int{}, map[string]time.Time{}
	}
	for j, exp := range m.spent {
		if exp.Before(now) {
			delete(m.spent, j)
			delete(m.attempts, j)
		}
	}
	if _, used := m.spent[c.JTI]; used {
		return nil, errors.New("that code was already used, or had too many wrong tries")
	}
	if !hmac.Equal([]byte(m.mac(c.JTI, strings.TrimSpace(code))), []byte(c.Code)) {
		m.attempts[c.JTI]++
		left := MailMaxAttempts - m.attempts[c.JTI]
		if left <= 0 {
			m.spent[c.JTI] = time.Unix(c.Exp, 0)
			return nil, errors.New("too many wrong codes; ask for a new one")
		}
		return nil, &ErrWrongCode{Left: left}
	}
	m.spent[c.JTI] = time.Unix(c.Exp, 0)
	return &Result{Source: "privasys_mail", Method: "proven",
		Values:     []Value{{Attr: "email", Value: c.Email}},
		MaterialAt: now,
		Evidence: map[string]any{
			"kind":        "mail_code",
			"mail_token":  c.JTI,
			"verified_at": now.Unix(),
		}}, nil
}
