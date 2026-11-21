// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package sources holds the business logic for each kind of raw material:
// what makes it genuine, which values it proves, and how.
package sources

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Privasys/container-app-attribute-verifier/internal/archive"
	"github.com/Privasys/container-app-attribute-verifier/internal/holder"
	"github.com/Privasys/container-app-attribute-verifier/internal/jose"
)

// ImportFreshness is how recent a provider token must be when it is first
// imported. Re-attestation of a token imported earlier ignores its age.
const ImportFreshness = 10 * time.Minute

// Email rules.
const (
	// RuleEmailVerified: the address counts when email_verified is true.
	RuleEmailVerified = "email_verified"
	// RuleMicrosoft: the address counts when xms_edov is true (Microsoft
	// checked it belongs to the account's domain owner), or when the
	// token's tenant is one the configuration names as vouching for its
	// own addresses. email_verified is never sent by Microsoft and is
	// ignored. The same rule privasys.id applies to a direct sign-in.
	RuleMicrosoft = "microsoft"
)

// Provider is one OIDC provider the verifier accepts tokens from.
type Provider struct {
	// Name is the proof's source: google, microsoft, linkedin, or
	// oidc:<issuer> for any other.
	Name string `json:"name"`
	// Issuer is the exact iss, or for Microsoft the pattern with {tid}.
	Issuer  string `json:"issuer"`
	JWKSURL string `json:"jwks_url"`
	// Audiences are privasys.id's client ids at this provider.
	Audiences []string `json:"audiences"`
	// Claims maps a token claim to the canonical attribute it proves.
	Claims    map[string]string `json:"claims"`
	EmailRule string            `json:"email_rule"`
	// VouchingTenants are Microsoft tenants whose directory is the
	// customer's own, so the provider vouches for their addresses.
	VouchingTenants []string `json:"vouching_tenants,omitempty"`
}

var standardClaims = map[string]string{
	"email": "email", "name": "name", "given_name": "given_name",
	"family_name": "family_name", "picture": "picture", "locale": "locale",
}

// Defaults are the providers the verifier knows out of the box. Audiences
// come from configure.
func Defaults() map[string]*Provider {
	return map[string]*Provider{
		"google": {Name: "google", Issuer: "https://accounts.google.com",
			JWKSURL: "https://www.googleapis.com/oauth2/v3/certs",
			Claims:  standardClaims, EmailRule: RuleEmailVerified},
		"microsoft": {Name: "microsoft", Issuer: "https://login.microsoftonline.com/{tid}/v2.0",
			JWKSURL: "https://login.microsoftonline.com/common/discovery/v2.0/keys",
			Claims: map[string]string{"email": "email", "name": "name",
				"given_name": "given_name", "family_name": "family_name"},
			EmailRule: RuleMicrosoft},
		"linkedin": {Name: "linkedin", Issuer: "https://www.linkedin.com/oauth",
			JWKSURL: "https://www.linkedin.com/oauth/openid/jwks",
			Claims:  standardClaims, EmailRule: RuleEmailVerified},
	}
}

// Validate checks a provider definition.
func (p *Provider) Validate() error {
	switch {
	case p.Name == "":
		return errors.New("a provider needs a name")
	case !strings.HasPrefix(p.Issuer, "https://"):
		return fmt.Errorf("provider %s: issuer must be https", p.Name)
	case !strings.HasPrefix(p.JWKSURL, "https://"):
		return fmt.Errorf("provider %s: jwks_url must be https", p.Name)
	case len(p.Audiences) == 0:
		return fmt.Errorf("provider %s: no audiences", p.Name)
	case p.EmailRule != RuleEmailVerified && p.EmailRule != RuleMicrosoft:
		return fmt.Errorf("provider %s: email_rule %q", p.Name, p.EmailRule)
	}
	return nil
}

// Value is one attribute a piece of material proves.
type Value struct {
	Attr  string
	Value any
}

// Result is what checking a piece of material establishes.
type Result struct {
	Source     string
	Method     string
	Values     []Value
	MaterialAt time.Time
	Evidence   map[string]any
	Label      map[string]any
}

// Keys is the part of the archive OIDC needs.
type Keys interface {
	Lookup(ctx context.Context, source, kid string) (*archive.Record, error)
	Sign(r *archive.Record) (string, error)
}

// CheckIDToken applies the provider's rules to an ID token. commitment is
// what the token's nonce must equal: the holder commitment the wallet put
// in the sign-in request, so a token copied from anywhere else, even from
// privasys.id itself, cannot be imported into another wallet.
func CheckIDToken(ctx context.Context, p *Provider, ks Keys, token, commitment string, importing bool, now time.Time) (*Result, error) {
	parsed, err := jose.Parse(token)
	if err != nil {
		return nil, fmt.Errorf("id_token: %w", err)
	}
	if parsed.Header.Kid == "" {
		return nil, errors.New("id_token: no kid")
	}
	var c map[string]any
	if err := parsed.Claims(&c); err != nil {
		return nil, errors.New("id_token: unreadable claims")
	}
	iss, _ := c["iss"].(string)
	tid, _ := c["tid"].(string)
	if !issuerMatches(p, iss, tid) {
		return nil, fmt.Errorf("id_token: issuer %q is not %s", iss, p.Name)
	}
	if !audienceMatches(c["aud"], p.Audiences) {
		return nil, errors.New("id_token: not issued to privasys.id")
	}
	nonce, _ := c["nonce"].(string)
	if nonce == "" || !holder.Equal(nonce, commitment) {
		return nil, errors.New("id_token: the sign-in was not started by this holder")
	}
	iat, ok := unix(c["iat"])
	if !ok {
		return nil, errors.New("id_token: no iat")
	}
	if importing {
		if now.Sub(iat) > ImportFreshness || iat.After(now.Add(time.Minute)) {
			return nil, errors.New("id_token: too old to import; sign in again")
		}
		if exp, ok := unix(c["exp"]); !ok || exp.Before(now) {
			return nil, errors.New("id_token: expired")
		}
	}
	rec, err := ks.Lookup(ctx, p.Name, parsed.Header.Kid)
	if err != nil {
		return nil, fmt.Errorf("id_token: %w", err)
	}
	if !rec.Covers(iat) {
		return nil, errors.New("id_token: signed outside its key's lifetime")
	}
	pub, err := rec.JWK.Public()
	if err != nil {
		return nil, err
	}
	if err := parsed.Verify(pub); err != nil {
		return nil, fmt.Errorf("id_token: %w", err)
	}
	sub, _ := c["sub"].(string)
	if sub == "" {
		return nil, errors.New("id_token: no sub")
	}
	if p.EmailRule == RuleMicrosoft {
		if oid, _ := c["oid"].(string); oid == "" {
			return nil, errors.New("id_token: no oid")
		}
	}

	var values []Value
	seen := map[string]bool{}
	for claim, attr := range p.Claims {
		s, _ := c[claim].(string)
		s = strings.TrimSpace(s)
		if s == "" || seen[attr] {
			continue
		}
		if attr == "email" {
			if !emailProved(p, c, tid) {
				continue
			}
			s = strings.ToLower(s)
		}
		seen[attr] = true
		values = append(values, Value{Attr: attr, Value: s})
	}
	if len(values) == 0 {
		return nil, errors.New("id_token: proves no attribute")
	}
	signedKey, err := ks.Sign(rec)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(token))
	ev := map[string]any{
		"kind":         "oidc_id_token",
		"token_sha256": jose.B64(digest[:]),
		"iss":          iss,
		"sub":          sub,
		"kid":          parsed.Header.Kid,
		"key":          signedKey,
	}
	if tid != "" {
		ev["tid"] = tid
	}
	return &Result{Source: p.Name, Method: "proven", Values: values, MaterialAt: iat, Evidence: ev}, nil
}

func issuerMatches(p *Provider, iss, tid string) bool {
	if strings.Contains(p.Issuer, "{tid}") {
		return tid != "" && iss == strings.ReplaceAll(p.Issuer, "{tid}", tid)
	}
	if p.Name == "google" && iss == "accounts.google.com" {
		return true // Google's documented alternative form
	}
	return iss == p.Issuer
}

func audienceMatches(aud any, allowed []string) bool {
	var auds []string
	switch v := aud.(type) {
	case string:
		auds = []string{v}
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok {
				auds = append(auds, s)
			}
		}
	}
	for _, a := range auds {
		for _, b := range allowed {
			if a == b {
				return true
			}
		}
	}
	return false
}

func emailProved(p *Provider, c map[string]any, tid string) bool {
	if p.EmailRule == RuleMicrosoft {
		for _, t := range p.VouchingTenants {
			if strings.EqualFold(t, tid) {
				return true
			}
		}
		return truthy(c["xms_edov"])
	}
	return truthy(c["email_verified"])
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "1" || strings.EqualFold(x, "true")
	case json.Number:
		return x.String() == "1"
	case float64:
		return x == 1
	}
	return false
}

func unix(v any) (time.Time, bool) {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		if err != nil {
			f, ferr := x.Float64()
			if ferr != nil {
				return time.Time{}, false
			}
			n = int64(f)
		}
		return time.Unix(n, 0), true
	case float64:
		return time.Unix(int64(x), 0), true
	}
	return time.Time{}, false
}
