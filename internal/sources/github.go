// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package sources

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/container-app-attribute-verifier/internal/jose"
)

// GitHub has no ID token, so nothing it says is signed. The verifier asks
// GitHub's API itself, over TLS, from inside the enclave, with the access
// token privasys.id obtained at sign-in, and records what it observed.
// The token is used once and dropped, so no GitHub proof can be replayed
// from material later, only rebound from the proof.
//
// The primary address GitHub marks verified is "proven": GitHub checked
// it, the verifier read that verdict from GitHub itself, and the flag
// counts as verified, as Google's email_verified does. Name and picture
// are what the account says about itself: "observed".

// GitHubAPI is GitHub's API origin; a test may point it elsewhere.
var GitHubAPI = "https://api.github.com"

// CheckGitHub reads the account behind accessToken.
func CheckGitHub(ctx context.Context, client *http.Client, accessToken string, now time.Time) (*Result, error) {
	if accessToken == "" {
		return nil, errors.New("github: an access token is required")
	}
	var user struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}
	userRaw, err := githubGet(ctx, client, accessToken, "/user", &user)
	if err != nil {
		return nil, err
	}
	if user.ID == 0 {
		return nil, errors.New("github: the token names no account")
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	emailsRaw, err := githubGet(ctx, client, accessToken, "/user/emails", &emails)
	if err != nil {
		return nil, err
	}
	var values []Value
	// GitHub marks each address verified or not. Only the primary, and only
	// when verified: that is the address the account answers to.
	for _, e := range emails {
		if e.Primary && e.Verified && e.Email != "" {
			values = append(values, Value{Attr: "email", Value: strings.ToLower(e.Email), Method: "proven"})
			break
		}
	}
	if n := strings.TrimSpace(user.Name); n != "" {
		values = append(values, Value{Attr: "name", Value: n})
	}
	if user.AvatarURL != "" {
		values = append(values, Value{Attr: "picture", Value: user.AvatarURL})
	}
	if len(values) == 0 {
		return nil, errors.New("github: the account has nothing verifiable to prove")
	}
	h := sha256.New()
	h.Write(userRaw)
	h.Write(emailsRaw)
	return &Result{Source: "github", Method: "observed", Values: values, MaterialAt: now,
		Evidence: map[string]any{
			"kind":            "github",
			"api":             GitHubAPI,
			"account_id":      user.ID,
			"login":           user.Login,
			"response_sha256": jose.B64(h.Sum(nil)),
			"observed_at":     now.Unix(),
		}}, nil
}

func githubGet(ctx context.Context, client *http.Client, token, path string, into any) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, GitHubAPI+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("github: the API could not be reached")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: %s answered %s", path, resp.Status)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return nil, fmt.Errorf("github: %s: unreadable answer", path)
	}
	return raw, nil
}
