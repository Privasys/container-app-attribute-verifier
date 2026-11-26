// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	ledger "github.com/Privasys/immutable-ledger/ledger"

	"github.com/Privasys/container-app-attribute-verifier/internal/archive"
	"github.com/Privasys/container-app-attribute-verifier/internal/jose"
	"github.com/Privasys/container-app-attribute-verifier/internal/keys"
	"github.com/Privasys/container-app-attribute-verifier/internal/platform"
)

// refusingManager is an enclave manager that accepts every attestation
// extension except the signing key's while refuse is set, and records
// config-complete calls.
type refusingManager struct {
	mu       sync.Mutex
	refuse   bool
	complete int
}

func (m *refusingManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case strings.HasSuffix(r.URL.Path, "/config-complete"):
		m.complete++
	case strings.HasSuffix(r.URL.Path, "/attestation-extensions"):
		var in struct {
			OID string `json:"oid"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if m.refuse && in.OID == platform.OIDSigningKey {
			http.Error(w, "refused", http.StatusBadGateway)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

func TestConfigureFailsClosedWhenTheKeyCannotBeAttested(t *testing.T) {
	fm := &refusingManager{refuse: true}
	mts := httptest.NewServer(fm)
	defer mts.Close()
	mgr := platform.NewManager(mts.URL, "av", "tok")

	dir := t.TempDir()
	signer, err := keys.LoadSigner(dir)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := signer.SPKISHA256()
	att := platform.NewKeyAttestation(mgr, spki, true)
	clock := time.Unix(1_000_000, 0)
	att.Now = func() time.Time { return clock }
	signer.Gate = att.Require

	// Boot as main does, with the manager refusing from the start: the
	// ledger opens with its version record deferred, and the verifier runs.
	var ck [32]byte
	arch, err := archive.Open(ledger.NewMemBackend(), ck, signer, "m", http.DefaultClient, nil, time.Now)
	if err != nil {
		t.Fatalf("boot with an unattested key must not fail: %v", err)
	}
	if v, _ := arch.Versions(); len(v) != 0 {
		t.Fatalf("version record written with an unattested key: %+v", v)
	}
	var recorded sync.WaitGroup
	recorded.Add(1)
	hookRuns := 0
	att.OnAttested(func() {
		hookRuns++
		if err := arch.RecordVersion(); err != nil {
			t.Errorf("version record after attestation: %v", err)
		}
		recorded.Done()
	})
	srv, err := New(Options{DataDir: dir, Signer: signer, Archive: arch, Manager: mgr, KeyAttestation: att,
		Client: http.DefaultClient, Now: time.Now, RequireWIA: true, NoBackgroundRefresh: true})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	wp, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jose.ECJWK(&wp.PublicKey)
	jwk.Kid = "wp1"
	cfg, _ := json.Marshal(map[string]any{"wallet_provider_jwks": map[string]any{"keys": []jose.JWK{jwk}}})
	post := func(path string, body []byte) int {
		resp, err := http.Post(ts.URL+path, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// The key cannot be attested: configure refuses and the gate stays shut.
	if got := post("/configure", cfg); got != http.StatusServiceUnavailable {
		t.Fatalf("configure with an unattested key: %d, want 503", got)
	}
	fm.mu.Lock()
	if fm.complete != 0 {
		t.Fatalf("config-complete was called %d times with an unattested key", fm.complete)
	}
	fm.mu.Unlock()

	// A signing route refuses before doing any work; status, which signs
	// nothing, still answers.
	if got := post("/challenge", nil); got != http.StatusServiceUnavailable {
		t.Fatalf("challenge with an unattested key: %d, want 503", got)
	}
	if got := post("/status", nil); got != http.StatusOK {
		t.Fatalf("status: %d, want 200", got)
	}

	// The manager accepts again: configure completes, and after the retry
	// interval the gate opens for signing.
	fm.mu.Lock()
	fm.refuse = false
	fm.mu.Unlock()
	if got := post("/configure", cfg); got != http.StatusOK {
		t.Fatalf("configure once the key can be attested: %d, want 200", got)
	}
	clock = clock.Add(platform.RetryInterval + time.Second)
	if got := post("/challenge", nil); got != http.StatusOK {
		t.Fatalf("challenge once attested: %d, want 200", got)
	}

	// The deferred version record is written once, by the first publish.
	recorded.Wait()
	if v, _ := arch.Versions(); len(v) != 1 || v[0].Measurement != "m" || v[0].Sig == "" {
		t.Fatalf("version record after recovery: %+v", v)
	}
	// Another configure publishes again but neither reruns the hook nor
	// writes a second record.
	if got := post("/configure", cfg); got != http.StatusOK {
		t.Fatalf("second configure: %d", got)
	}
	time.Sleep(50 * time.Millisecond)
	if v, _ := arch.Versions(); len(v) != 1 || hookRuns != 1 {
		t.Fatalf("after a second publish: %d records, hook ran %d times", len(v), hookRuns)
	}
}
