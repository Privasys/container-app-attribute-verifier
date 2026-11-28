// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package sources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeGitHub serves /user, /user/emails and the app token check. ourToken
// is the token issued to app "Iv1.ours" (secret "s3cret"); checkUser is the
// account the token check names.
func fakeGitHub(t *testing.T, emails, ourToken string, checkUser int64) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/applications/Iv1.ours/token":
			id, secret, ok := r.BasicAuth()
			if r.Method != http.MethodPost || !ok || id != "Iv1.ours" || secret != "s3cret" {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			var b struct {
				AccessToken string `json:"access_token"`
			}
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b.AccessToken != ourToken {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"user": map[string]any{"id": checkUser}})
			return
		case "/applications/Iv1.other/token":
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" && r.Header.Get("Authorization") != "Bearer foreign" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/user":
			_, _ = w.Write([]byte(`{"id":42,"login":"alice","name":"Alice","avatar_url":"https://avatars.example/a"}`))
		case "/user/emails":
			_, _ = w.Write([]byte(emails))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	old := GitHubAPI
	GitHubAPI = srv.URL
	t.Cleanup(func() { GitHubAPI = old })
}

const twoEmails = `[{"email":"Other@Example.com","primary":false,"verified":true},{"email":"Alice@Example.com","primary":true,"verified":true}]`

var ours = &GitHubApp{ClientID: "Iv1.ours", ClientSecret: "s3cret"}

func byAttr(res *Result) map[string]Value {
	got := map[string]Value{}
	for _, v := range res.Values {
		got[v.Attr] = v
	}
	return got
}

func TestGitHubEmailIsProvenOnlyForOurAppsToken(t *testing.T) {
	fakeGitHub(t, twoEmails, "tok", 42)
	res, err := CheckGitHub(context.Background(), http.DefaultClient, ours, "tok", time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if res.Method != "observed" {
		t.Fatalf("result method %q, want observed", res.Method)
	}
	got := byAttr(res)
	if e := got["email"]; e.Value != "alice@example.com" || e.Method != "proven" {
		t.Fatalf("email %+v, want the primary address, proven", e)
	}
	for _, a := range []string{"name", "picture"} {
		if v, ok := got[a]; !ok || v.Method != "" {
			t.Fatalf("%s %+v, want present and observed", a, v)
		}
	}
	if res.Evidence["app_token"] != true {
		t.Fatalf("evidence app_token %v, want true", res.Evidence["app_token"])
	}
}

func TestGitHubEmailStaysObserved(t *testing.T) {
	cases := []struct {
		name      string
		app       *GitHubApp
		token     string
		checkUser int64
	}{
		{"no app configured", nil, "tok", 42},
		{"a token another app was issued", ours, "foreign", 42},
		{"the token check names another account", ours, "tok", 7},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fakeGitHub(t, twoEmails, "tok", c.checkUser)
			res, err := CheckGitHub(context.Background(), http.DefaultClient, c.app, c.token, time.Unix(1700000000, 0))
			if err != nil {
				t.Fatal(err)
			}
			if e, ok := byAttr(res)["email"]; !ok || e.Method != "" {
				t.Fatalf("email %+v, want present and observed", e)
			}
		})
	}
}

func TestGitHubTokenCheckRefusedIsAnError(t *testing.T) {
	fakeGitHub(t, twoEmails, "tok", 42)
	bad := &GitHubApp{ClientID: "Iv1.other", ClientSecret: "wrong"}
	if _, err := CheckGitHub(context.Background(), http.DefaultClient, bad, "tok", time.Unix(1700000000, 0)); err == nil {
		t.Fatal("a refused token check must fail the import, not pass silently")
	}
}

func TestGitHubUnverifiedPrimaryEmailIsLeftOut(t *testing.T) {
	fakeGitHub(t, `[{"email":"alice@example.com","primary":true,"verified":false},{"email":"other@example.com","primary":false,"verified":true}]`, "tok", 42)
	res, err := CheckGitHub(context.Background(), http.DefaultClient, ours, "tok", time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range res.Values {
		if v.Attr == "email" {
			t.Fatalf("an email was kept: %+v", v)
		}
		if v.Method != "" {
			t.Fatalf("%s carries method %q, want observed", v.Attr, v.Method)
		}
	}
}

func TestGitHubAppConfig(t *testing.T) {
	held := GitHubApp{ClientID: "Iv1.ours", ClientSecret: "s3cret"}
	if m := (GitHubApp{}).Merge(held); m != held {
		t.Fatalf("an empty call keeps what is held, got %+v", m)
	}
	if m := (GitHubApp{ClientID: "Iv1.new"}).Merge(held); m.ClientSecret != "" {
		t.Fatal("a new app id must not inherit the old app's secret")
	}
	if held.Public().ClientSecret != "" {
		t.Fatal("Public must drop the secret")
	}
	for _, id := range []string{"", "a/b", "a?b", "a b"} {
		if (GitHubApp{ClientID: id, ClientSecret: "x"}).Validate() == nil {
			t.Fatalf("client_id %q accepted", id)
		}
	}
	if (GitHubApp{ClientID: "Iv1.ours"}).Validate() == nil {
		t.Fatal("a missing secret accepted")
	}
}
