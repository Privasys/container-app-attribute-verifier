// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Privasys/container-app-attribute-verifier/internal/holder"
)

// A £0 card check asks the card's issuing bank whether the address the
// holder typed matches the one on file. The verdict reaches the payment
// provider over TLS, unsigned, so the verifier cannot check it directly.
// It asks the Privasys back office instead, which kept the verdict, and
// signs only the fields that passed. The back office is provider-agnostic
// and so is everything here: no payment provider is ever named.

// Identity supplies the attested app-identity headers the back office
// admits the verifier by.
type Identity interface {
	AppIdentity(ctx context.Context) (identity, challenge, evidence string, err error)
}

// CardChecks talks to the back office.
type CardChecks struct {
	BaseURL  string
	Client   *http.Client
	Identity Identity
}

// ErrNoCheck means the back office has no usable check: never existed,
// expired, or withdrawn by the holder. Nothing is signed.
var ErrNoCheck = errors.New("card check: no such check, or it was withdrawn")

// CardMaterial is what the wallet received from the check.
type CardMaterial struct {
	CheckID    string `json:"check_id"`
	Line1      string `json:"line1"`
	PostalCode string `json:"postal_code"`
	Country    string `json:"country"`
}

type verifyAnswer struct {
	Match         bool              `json:"match"`
	Checks        map[string]string `json:"checks"`
	CardBrand     *string           `json:"card_brand"`
	CardCountry   *string           `json:"card_country"`
	CheckedAt     json.RawMessage   `json:"checked_at"`
	HolderBinding string            `json:"holder_binding"`
	Error         string            `json:"error"`
}

// Check asks the back office about m and returns the passed fields.
// commitment must equal the holder binding recorded at check time.
func (cc *CardChecks) Check(ctx context.Context, m CardMaterial, commitment string) (*Result, error) {
	if cc == nil || cc.BaseURL == "" {
		return nil, errors.New("card checks are not configured")
	}
	if m.CheckID == "" {
		return nil, errors.New("card check: check_id is required")
	}
	var a verifyAnswer
	status, err := cc.post(ctx, "/api/v1/platform/address-checks/verify", m, &a)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound || status == http.StatusGone || a.Error == "not_found" || a.Error == "expired" || a.Error == "revoked" {
		return nil, ErrNoCheck
	}
	if status == http.StatusTooManyRequests {
		return nil, errors.New("card check: too many lookups of this check; try again later")
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("card check: the back office answered %d", status)
	}
	checkedAt, ok := parseCheckedAt(a.CheckedAt)
	if !ok {
		// The proof must carry when the bank checked the address; without it
		// nothing is signed rather than a proof dated at the epoch.
		return nil, errors.New("card check: the back office gave no check time")
	}
	if !a.Match {
		return nil, errors.New("card check: the address is not the one checked")
	}
	if a.HolderBinding == "" || !holder.Equal(a.HolderBinding, commitment) {
		return nil, errors.New("card check: the check was not started by this holder")
	}
	value := map[string]any{}
	if a.Checks["line1"] == "pass" && strings.TrimSpace(m.Line1) != "" {
		value["street_address"] = m.Line1
	}
	if a.Checks["postal_code"] == "pass" && strings.TrimSpace(m.PostalCode) != "" {
		value["postal_code"] = m.PostalCode
	}
	if len(value) == 0 {
		return nil, errors.New("card check: no field of the address passed")
	}
	// The label is data; the wallet writes the sentence ("Confirmed by a
	// UK Visa card's bank", or "Confirmed by your card's bank" when the
	// brand or country is unknown). The typed country is context only:
	// the bank does not check it.
	label := map[string]any{}
	if a.CardBrand != nil && *a.CardBrand != "" {
		label["brand"] = *a.CardBrand
	}
	if a.CardCountry != nil && *a.CardCountry != "" {
		label["country"] = *a.CardCountry
	}
	if m.Country != "" {
		label["address_country"] = m.Country
	}
	checks := map[string]string{}
	for k, v := range a.Checks {
		checks[k] = v
	}
	return &Result{Source: "card_bank", Method: "proven",
		Values:     []Value{{Attr: "address", Value: value}},
		MaterialAt: checkedAt,
		Label:      label,
		Evidence: map[string]any{
			"kind":       "card_check",
			"check_id":   m.CheckID,
			"checks":     checks,
			"checked_at": checkedAt.Unix(),
		}}, nil
}

// Statement records the hash of a proof the verifier signed for a check.
func (cc *CardChecks) Statement(ctx context.Context, checkID, sha256b64 string) error {
	status, err := cc.post(ctx, "/api/v1/platform/address-checks/"+url.PathEscape(checkID)+"/statement",
		map[string]string{"sha256": sha256b64}, nil)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return fmt.Errorf("card check: statement answered %d", status)
	}
	return nil
}

func (cc *CardChecks) post(ctx context.Context, path string, body, into any) (int, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(cc.BaseURL, "/")+path, bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if cc.Identity != nil {
		id, ch, ev, err := cc.Identity.AppIdentity(ctx)
		if err != nil {
			return 0, fmt.Errorf("card check: attested identity: %w", err)
		}
		req.Header.Set("X-Privasys-App-Identity", id)
		req.Header.Set("X-Privasys-App-Challenge", ch)
		req.Header.Set("X-Privasys-App-Evidence", ev)
	}
	resp, err := cc.Client.Do(req)
	if err != nil {
		return 0, errors.New("card check: the back office could not be reached")
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if into != nil && len(answer) > 0 {
		_ = json.Unmarshal(answer, into)
	}
	return resp.StatusCode, nil
}

// parseCheckedAt reads the check time as an RFC 3339 string (what the back
// office sends) or Unix seconds. A missing or zero time is not a time.
func parseCheckedAt(raw json.RawMessage) (time.Time, bool) {
	var str string
	if json.Unmarshal(raw, &str) == nil && str != "" {
		t, err := time.Parse(time.RFC3339, str)
		return t, err == nil && t.Unix() > 0
	}
	var n int64
	if json.Unmarshal(raw, &n) == nil && n > 0 {
		return time.Unix(n, 0), true
	}
	return time.Time{}, false
}
