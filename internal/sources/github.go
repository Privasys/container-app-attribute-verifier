// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package sources

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
// The primary address GitHub marks verified is "proven", but only when
// GitHub confirms the token was issued to privasys.id's own GitHub app
// (the GitHubApp below): GitHub checked the address, the verifier read
// that verdict from GitHub itself, and the flag counts as verified, as
// Google's email_verified does. A token from any other app the person
// authorised proves nothing about this sign-in, so its email stays
// "observed", as name and picture always are.

// GitHubAPI is GitHub's API origin; a test may point it elsewhere.
var GitHubAPI = "https://api.github.com"

// GitHubApp is privasys.id's GitHub app, the only one whose tokens can
// make a GitHub email proven. The secret never leaves the enclave and is
// left out of the attested configuration digest.
type GitHubApp struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
}

// Validate checks both parts are present and the id is a plain token.
func (a GitHubApp) Validate() error {
	if a.ClientID == "" || a.ClientSecret == "" {
		return errors.New("github: client_id and client_secret are both needed")
	}
	if a.ClientID[0] == '.' {
		return errors.New("github: client_id cannot start with a dot")
	}
	for _, c := range a.ClientID {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return errors.New("github: client_id has a character GitHub ids never have")
		}
	}
	return nil
}

// Merge keeps the held secret when the call leaves it out for the same app.
func (a GitHubApp) Merge(held GitHubApp) GitHubApp {
	if a.ClientID == "" {
		a.ClientID = held.ClientID
	}
	if a.ClientSecret == "" && a.ClientID == held.ClientID {
		a.ClientSecret = held.ClientSecret
	}
	return a
}

// Public is the app without the secret, for the attested digest.
func (a GitHubApp) Public() GitHubApp { a.ClientSecret = ""; return a }

// issuedTo reports whether GitHub says token belongs to app and to account
// userID ("Check a token": POST /applications/{client_id}/token, answered
// only to the app's own credentials; 404 when the token is not the app's).
func (a *GitHubApp) issuedTo(ctx context.Context, client *http.Client, token string, userID int64) (bool, error) {
	body, _ := json.Marshal(map[string]string{"access_token": token})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		GitHubAPI+"/applications/"+url.PathEscape(a.ClientID)+"/token", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(a.ClientID, a.ClientSecret)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := client.Do(req)
	if err != nil {
		return false, errors.New("github: the token check could not be reached")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusUnprocessableEntity:
		return false, nil
	default:
		return false, fmt.Errorf("github: the token check answered %s", resp.Status)
	}
	var info struct {
		User struct {
			ID int64 `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		return false, errors.New("github: the token check: unreadable answer")
	}
	return info.User.ID != 0 && info.User.ID == userID, nil
}

// CheckGitHub reads the account behind accessToken. app, when set, is
// privasys.id's GitHub app; without it no GitHub value is proven.
func CheckGitHub(ctx context.Context, client *http.Client, app *GitHubApp, accessToken string, now time.Time) (*Result, error) {
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
	ours := false
	if app != nil {
		if ours, err = app.issuedTo(ctx, client, accessToken, user.ID); err != nil {
			return nil, err
		}
	}
	emailMethod := ""
	if ours {
		emailMethod = "proven"
	}
	var values []Value
	// GitHub marks each address verified or not. Only the primary, and only
	// when verified: that is the address the account answers to.
	for _, e := range emails {
		if e.Primary && e.Verified && e.Email != "" {
			values = append(values, Value{Attr: "email", Value: strings.ToLower(e.Email), Method: emailMethod})
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
			"app_token":       ours,
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
