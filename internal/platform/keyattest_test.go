// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package platform_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Privasys/container-app-attribute-verifier/internal/jose"
	"github.com/Privasys/container-app-attribute-verifier/internal/keys"
	"github.com/Privasys/container-app-attribute-verifier/internal/platform"
)

// fakeManager records attestation extensions, counts every call, and
// refuses the signing-key OID while refuse is set.
type fakeManager struct {
	mu     sync.Mutex
	refuse bool
	calls  int
	got    map[string][]byte
}

func newFakeManager(refuse bool) *fakeManager {
	return &fakeManager{refuse: refuse, got: map[string][]byte{}}
}

func (f *fakeManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		OID   string `json:"oid"`
		Value string `json:"value_b64"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.refuse && in.OID == platform.OIDSigningKey {
		http.Error(w, "refused", http.StatusBadGateway)
		return
	}
	v, _ := base64.StdEncoding.DecodeString(in.Value)
	f.got[in.OID] = v
	w.WriteHeader(http.StatusOK)
}

func (f *fakeManager) set(refuse bool) {
	f.mu.Lock()
	f.refuse = refuse
	f.mu.Unlock()
}

func (f *fakeManager) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func newSigner(t *testing.T) (*keys.Signer, []byte) {
	t.Helper()
	signer, err := keys.LoadSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	spki, err := signer.SPKISHA256()
	if err != nil {
		t.Fatal(err)
	}
	return signer, spki
}

func TestUnattestedKeyNeverSigns(t *testing.T) {
	fm := newFakeManager(true)
	ts := httptest.NewServer(fm)
	defer ts.Close()

	signer, spki := newSigner(t)
	att := platform.NewKeyAttestation(platform.NewManager(ts.URL, "av", "tok"), spki, true)
	clock := time.Unix(1_000_000, 0)
	att.Now = func() time.Time { return clock }
	signer.Gate = att.Require

	if _, err := signer.Sign("test", map[string]any{"n": 1}); !errors.Is(err, platform.ErrKeyNotAttested) {
		t.Fatalf("signed with an unattested key (err=%v)", err)
	}
	if fm.count() != 1 {
		t.Fatalf("first refusal made %d manager calls, want 1", fm.count())
	}
	// A burst inside the interval is refused at once, without calling the manager.
	for i := 0; i < 5; i++ {
		if _, err := signer.Sign("test", map[string]any{"n": i}); !errors.Is(err, platform.ErrKeyNotAttested) {
			t.Fatalf("burst signature %d was not refused (err=%v)", i, err)
		}
	}
	if fm.count() != 1 {
		t.Fatalf("burst reached the manager: %d calls, want 1", fm.count())
	}

	// The manager is back, but the next retry waits for the interval.
	fm.set(false)
	if _, err := signer.Sign("test", map[string]any{}); !errors.Is(err, platform.ErrKeyNotAttested) {
		t.Fatalf("retried before the interval (err=%v)", err)
	}
	clock = clock.Add(platform.RetryInterval + time.Second)
	if _, err := signer.Sign("test", map[string]any{"n": 2}); err != nil {
		t.Fatalf("sign after publish: %v", err)
	}
	if fm.count() != 2 {
		t.Fatalf("recovery made %d manager calls in all, want 2", fm.count())
	}
	// Once attested, no further publish per signature.
	if _, err := signer.Sign("test", map[string]any{"n": 3}); err != nil || fm.count() != 2 {
		t.Fatalf("attested key re-published or refused (calls=%d, err=%v)", fm.count(), err)
	}

	// The attested value is SHA-256 of the SPKI of the key in the JWKS, as a
	// relying party recomputes it, and the kid encodes the same digest.
	pub, err := signer.Public().Public()
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(pub)
	want := sha256.Sum256(der)
	if got := fm.got[platform.OIDSigningKey]; string(got) != string(want[:]) {
		t.Fatalf("attested %x, want %x", got, want)
	}
	if signer.Kid != jose.B64(want[:]) {
		t.Fatalf("kid %s is not the attested digest", signer.Kid)
	}
}

func TestGateOpenOnlyClearlyOffPlatform(t *testing.T) {
	signer, spki := newSigner(t)
	signer.Gate = platform.NewKeyAttestation(nil, spki, false).Require
	if _, err := signer.Sign("test", map[string]any{}); err != nil {
		t.Fatalf("clearly off the platform there is nothing to attest to: %v", err)
	}
}

func TestOnPlatformWithoutAManagerNeverSigns(t *testing.T) {
	signer, spki := newSigner(t)
	att := platform.NewKeyAttestation(nil, spki, true)
	signer.Gate = att.Require
	if _, err := signer.Sign("test", map[string]any{}); !errors.Is(err, platform.ErrKeyNotAttested) {
		t.Fatalf("signed on the platform without a manager (err=%v)", err)
	}
	if err := att.Publish(t.Context()); err == nil {
		t.Fatal("publish without a manager on the platform must fail")
	}
}

func TestOnPlatformMarkers(t *testing.T) {
	for _, k := range []string{"PRIVASYS_IMAGE_DIGEST", "PRIVASYS_MANAGER_URL",
		"PRIVASYS_CONTAINER_NAME", "PRIVASYS_CONTAINER_TOKEN"} {
		env := map[string]string{k: "x"}
		if !platform.OnPlatform(func(name string) string { return env[name] }) {
			t.Errorf("%s alone must mean on the platform", k)
		}
	}
	if platform.OnPlatform(func(string) string { return "" }) {
		t.Error("no marker must mean off the platform")
	}
}
