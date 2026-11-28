// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func fakeGitHub(t *testing.T, emails string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
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

func TestGitHubVerifiedPrimaryEmailIsProven(t *testing.T) {
	fakeGitHub(t, `[{"email":"Other@Example.com","primary":false,"verified":true},{"email":"Alice@Example.com","primary":true,"verified":true}]`)
	res, err := CheckGitHub(context.Background(), http.DefaultClient, "tok", time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if res.Method != "observed" {
		t.Fatalf("result method %q, want observed", res.Method)
	}
	got := map[string]Value{}
	for _, v := range res.Values {
		got[v.Attr] = v
	}
	if e := got["email"]; e.Value != "alice@example.com" || e.Method != "proven" {
		t.Fatalf("email %+v, want the primary address, proven", e)
	}
	for _, a := range []string{"name", "picture"} {
		if v, ok := got[a]; !ok || v.Method != "" {
			t.Fatalf("%s %+v, want present and observed (no override)", a, v)
		}
	}
}

func TestGitHubUnverifiedPrimaryEmailIsLeftOut(t *testing.T) {
	fakeGitHub(t, `[{"email":"alice@example.com","primary":true,"verified":false},{"email":"other@example.com","primary":false,"verified":true}]`)
	res, err := CheckGitHub(context.Background(), http.DefaultClient, "tok", time.Unix(1700000000, 0))
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
