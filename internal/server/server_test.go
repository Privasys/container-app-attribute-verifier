// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	ledger "github.com/Privasys/immutable-ledger/ledger"

	"github.com/Privasys/container-app-attribute-verifier/internal/archive"
	"github.com/Privasys/container-app-attribute-verifier/internal/holder"
	"github.com/Privasys/container-app-attribute-verifier/internal/jose"
	"github.com/Privasys/container-app-attribute-verifier/internal/keys"
	"github.com/Privasys/container-app-attribute-verifier/internal/proof"
	"github.com/Privasys/container-app-attribute-verifier/internal/sources"
)

// ── a fake identity provider ─────────────────────────────────────────

type fakeIdP struct {
	key *rsa.PrivateKey
	kid string
	srv *httptest.Server
}

func newFakeIdP(t *testing.T) *fakeIdP {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: k, kid: "g1"}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e := []byte{1, 0, 1}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []jose.JWK{{Kty: "RSA", Kid: f.kid, Use: "sig",
			N: jose.B64(f.key.N.Bytes()), E: jose.B64(e)}}})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) token(t *testing.T, claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": f.kid, "typ": "JWT"})
	p, _ := json.Marshal(claims)
	input := jose.B64(h) + "." + jose.B64(p)
	d := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + jose.B64(sig)
}

// ── a test wallet ────────────────────────────────────────────────────

type wallet struct {
	hk, device *ecdsa.PrivateKey
	salt       []byte
	wia        string
}

func newWallet(t *testing.T, wp *ecdsa.PrivateKey) *wallet {
	hk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dev, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	w := &wallet{hk: hk, device: dev, salt: make([]byte, 16)}
	_, _ = rand.Read(w.salt)
	w.wia = mintWIA(t, wp, dev)
	return w
}

func mintWIA(t *testing.T, wp *ecdsa.PrivateKey, dev *ecdsa.PrivateKey) string {
	tok, err := jose.Sign(wp, "wp1", "wia+jwt", map[string]any{
		"exp": time.Now().Add(time.Hour).Unix(), "cnf": map[string]any{"jwk": jose.ECJWK(&dev.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (w *wallet) commitment() string { return holder.Commitment(jose.SEC1(&w.hk.PublicKey), w.salt) }

func (w *wallet) sign(t *testing.T, msg []byte) (*holder.Holder, *holder.Device) {
	hs, err := jose.SignES256Raw(w.hk, msg)
	if err != nil {
		t.Fatal(err)
	}
	ds, err := jose.SignES256Raw(w.device, msg)
	if err != nil {
		t.Fatal(err)
	}
	return &holder.Holder{HKPub: jose.B64(jose.SEC1(&w.hk.PublicKey)), Salt: jose.B64(w.salt), Sig: jose.B64(hs)},
		&holder.Device{Pub: jose.B64(jose.SEC1(&w.device.PublicKey)), Sig: jose.B64(ds)}
}

// ── harness ──────────────────────────────────────────────────────────

type sentMail struct {
	mu   sync.Mutex
	code string
	to   string
}

func (s *sentMail) SendCode(ctx context.Context, to, code string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.to, s.code = to, code
	return nil
}

type harness struct {
	t      *testing.T
	srv    *Server
	http   *httptest.Server
	idp    *fakeIdP
	wp     *ecdsa.PrivateKey
	mail   *sentMail
	office *httptest.Server
	// what the fake back office answers
	officeAnswer map[string]any
	statements   []string
}

func newHarness(t *testing.T) *harness {
	h := &harness{t: t, idp: newFakeIdP(t), mail: &sentMail{}}
	h.wp, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dir := t.TempDir()
	signer, err := keys.LoadSigner(dir)
	if err != nil {
		t.Fatal(err)
	}
	var ck [32]byte
	arch, err := archive.Open(ledger.NewMemBackend(), ck, signer, "sha256:test", http.DefaultClient, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	h.office = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/statement") {
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			h.statements = append(h.statements, b["sha256"])
			w.WriteHeader(204)
			return
		}
		if h.officeAnswer == nil {
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(h.officeAnswer)
	}))
	t.Cleanup(h.office.Close)
	srv, err := New(Options{DataDir: dir, Measurement: "sha256:test", Issuer: "https://av.test",
		Signer: signer, Archive: arch, Client: h.office.Client(), Now: time.Now, RequireWIA: true, NoBackgroundRefresh: true})
	if err != nil {
		t.Fatal(err)
	}
	h.srv = srv
	h.http = httptest.NewServer(srv.Handler())
	t.Cleanup(h.http.Close)

	// Point the Google definition at the fake provider.
	cfg := map[string]any{
		"wallet_provider_jwks": map[string]any{"keys": []jose.JWK{func() jose.JWK {
			j := jose.ECJWK(&h.wp.PublicKey)
			j.Kid = "wp1"
			return j
		}()}},
		"providers":  map[string]any{"google": map[string]any{"audiences": []string{"privasys-google-client"}}},
		"card_check": map[string]any{"base_url": h.office.URL},
	}
	h.post("/configure", cfg, 200)
	// The fake IdP's JWKS URL replaces Google's for the test.
	srv.mu.Lock()
	srv.providers["google"].JWKSURL = h.idp.srv.URL
	srv.mu.Unlock()
	srv.o.Archive.SetSources([]archive.Source{{Name: "google", JWKSURL: h.idp.srv.URL}})
	if err := srv.o.Archive.Refresh(context.Background(), "google"); err != nil {
		t.Fatal(err)
	}
	srv.mailCodes.Sender = h.mail
	return h
}

func (h *harness) post(path string, body any, want int) map[string]any {
	h.t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(h.http.URL+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != want {
		h.t.Fatalf("%s: status %d, want %d: %v", path, resp.StatusCode, want, out)
	}
	return out
}

func (h *harness) challenge() string {
	resp, err := http.Get(h.http.URL + "/challenge")
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out["challenge"].(string)
}

func (h *harness) attest(w *wallet, kind string, material map[string]any, want int) map[string]any {
	h.t.Helper()
	ch := h.challenge()
	msg, err := AttestMessage(kind, material, ch)
	if err != nil {
		h.t.Fatal(err)
	}
	hb, db := w.sign(h.t, msg)
	return h.post("/attest", map[string]any{"kind": kind, "material": material, "holder": hb,
		"device": db, "wia": w.wia, "challenge": ch}, want)
}

func (h *harness) googleToken(w *wallet, extra map[string]any) string {
	c := map[string]any{"iss": "https://accounts.google.com", "aud": "privasys-google-client",
		"sub": "1234", "email": "Alice@Example.com", "email_verified": true, "name": "Alice",
		"nonce": w.commitment(), "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range extra {
		c[k] = v
	}
	return h.idp.token(h.t, c)
}

func proofsOf(t *testing.T, out map[string]any) map[string]map[string]any {
	t.Helper()
	m := map[string]map[string]any{}
	for _, p := range out["proofs"].([]any) {
		pm := p.(map[string]any)
		m[pm["attr"].(string)] = pm
	}
	return m
}

// ── tests ────────────────────────────────────────────────────────────

func TestGoogleImportProvesVerifiedEmail(t *testing.T) {
	h := newHarness(t)
	w := newWallet(t, h.wp)
	out := h.attest(w, "oidc_id_token", map[string]any{"provider": "google", "id_token": h.googleToken(w, nil)}, 200)
	ps := proofsOf(t, out)
	if ps["email"]["value"] != "alice@example.com" || ps["email"]["method"] != "proven" || ps["email"]["source"] != "google" {
		t.Fatalf("email proof: %v", ps["email"])
	}
	if ps["name"] == nil {
		t.Fatal("name not proven")
	}
	p, err := proof.Verify(h.srv.o.Signer, ps["email"]["proof"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if p.Holder.Commitment != w.commitment() || p.Holder.Device != holder.DeviceBinding(jose.SEC1(&w.device.PublicKey)) {
		t.Fatal("proof not bound to the holder and device")
	}
	if _, ok := p.Evidence["key"].(string); !ok {
		t.Fatal("proof carries no signed key record")
	}
}

func TestGoogleUnverifiedEmailIsNotSigned(t *testing.T) {
	h := newHarness(t)
	w := newWallet(t, h.wp)
	out := h.attest(w, "oidc_id_token", map[string]any{"provider": "google",
		"id_token": h.googleToken(w, map[string]any{"email_verified": false})}, 200)
	if proofsOf(t, out)["email"] != nil {
		t.Fatal("an unverified address was signed")
	}
}

func TestTokenFromAnotherWalletIsRefused(t *testing.T) {
	h := newHarness(t)
	victim := newWallet(t, h.wp)
	thief := newWallet(t, h.wp)
	tok := h.googleToken(victim, nil)
	h.attest(thief, "oidc_id_token", map[string]any{"provider": "google", "id_token": tok}, 422)
}

func TestWrongAudienceAndStaleTokenRefused(t *testing.T) {
	h := newHarness(t)
	w := newWallet(t, h.wp)
	h.attest(w, "oidc_id_token", map[string]any{"provider": "google",
		"id_token": h.googleToken(w, map[string]any{"aud": "someone-else"})}, 422)
	old := time.Now().Add(-2 * time.Hour).Unix()
	stale := h.googleToken(w, map[string]any{"iat": old, "exp": old + 3600})
	h.attest(w, "oidc_id_token", map[string]any{"provider": "google", "id_token": stale}, 422)
}

func TestReattestOldTokenAfterKeyRotation(t *testing.T) {
	h := newHarness(t)
	w := newWallet(t, h.wp)
	tok := h.googleToken(w, nil)
	h.attest(w, "oidc_id_token", map[string]any{"provider": "google", "id_token": tok}, 200)
	// Google rotates: the old key leaves its key set for good.
	oldKid := h.idp.kid
	h.idp.kid = "g2"
	h.idp.key, _ = rsa.GenerateKey(rand.Reader, 2048)
	if err := h.srv.o.Archive.Refresh(context.Background(), "google"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.o.Archive.Lookup(context.Background(), "google", oldKid); err != nil {
		t.Fatalf("archived key lost: %v", err)
	}
	h.attest(w, "oidc_id_token", map[string]any{"provider": "google", "id_token": tok, "reattest": true}, 200)
}

func TestMissingWIARefused(t *testing.T) {
	h := newHarness(t)
	w := newWallet(t, h.wp)
	w.wia = ""
	h.attest(w, "oidc_id_token", map[string]any{"provider": "google", "id_token": h.googleToken(w, nil)}, 401)
	// A WIA for another device is refused too.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	w.wia = mintWIA(t, h.wp, other)
	h.attest(w, "oidc_id_token", map[string]any{"provider": "google", "id_token": h.googleToken(w, nil)}, 401)
}

func TestChallengeIsSingleUse(t *testing.T) {
	h := newHarness(t)
	w := newWallet(t, h.wp)
	ch := h.challenge()
	material := map[string]any{"provider": "google", "id_token": h.googleToken(w, nil)}
	msg, _ := AttestMessage("oidc_id_token", material, ch)
	hb, db := w.sign(t, msg)
	body := map[string]any{"kind": "oidc_id_token", "material": material, "holder": hb, "device": db, "wia": w.wia, "challenge": ch}
	h.post("/attest", body, 200)
	h.post("/attest", body, 401)
}

func TestMailCodeCeremony(t *testing.T) {
	h := newHarness(t)
	w := newWallet(t, h.wp)
	ch := h.challenge()
	msg, _ := MailStartMessage("bob@example.com", ch)
	hb, db := w.sign(t, msg)
	start := h.post("/mail/start", map[string]any{"email": "bob@example.com", "holder": hb, "device": db, "wia": w.wia, "challenge": ch}, 200)
	tok := start["mail_token"].(string)
	if h.mail.to != "bob@example.com" || len(h.mail.code) != 6 {
		t.Fatal("no code was sent")
	}
	if strings.Contains(tok, h.mail.code) {
		t.Fatal("the code is readable in the token")
	}
	wrong := "000000"
	if h.mail.code == wrong {
		wrong = "111111"
	}
	out := h.attest(w, "mail_code", map[string]any{"email": "bob@example.com", "code": wrong, "mail_token": tok}, 400)
	if out["attempts_left"].(float64) != 4 {
		t.Fatalf("attempts_left: %v", out)
	}
	// Another holder cannot redeem it.
	other := newWallet(t, h.wp)
	h.attest(other, "mail_code", map[string]any{"email": "bob@example.com", "code": h.mail.code, "mail_token": tok}, 422)
	ok := h.attest(w, "mail_code", map[string]any{"email": "bob@example.com", "code": h.mail.code, "mail_token": tok}, 200)
	if p := proofsOf(t, ok)["email"]; p["source"] != "privasys_mail" || p["method"] != "proven" {
		t.Fatalf("mail proof: %v", p)
	}
	// Single use.
	h.attest(w, "mail_code", map[string]any{"email": "bob@example.com", "code": h.mail.code, "mail_token": tok}, 422)
}

func TestMailResendIsLimited(t *testing.T) {
	h := newHarness(t)
	w := newWallet(t, h.wp)
	for i, want := range []int{200, 429} {
		ch := h.challenge()
		msg, _ := MailStartMessage("carol@example.com", ch)
		hb, db := w.sign(t, msg)
		h.post("/mail/start", map[string]any{"email": "carol@example.com", "holder": hb, "device": db, "wia": w.wia, "challenge": ch}, want)
		_ = i
	}
}

func TestCardCheckSignsOnlyAFullMatch(t *testing.T) {
	h := newHarness(t)
	w := newWallet(t, h.wp)
	visa, gb := "visa", "GB"
	material := map[string]any{"check_id": "chk1", "line1": "1 High St", "postal_code": "SW1A 1AA", "country": "GB"}
	// The postcode alone passing (a previous address with the same digits
	// does) signs nothing.
	h.officeAnswer = map[string]any{"match": true, "checks": map[string]string{"line1": "fail", "postal_code": "pass"},
		"card_brand": visa, "card_country": gb, "checked_at": "2025-11-21T05:20:00Z", "holder_binding": w.commitment()}
	h.attest(w, "card_check", material, 422)
	if len(h.statements) != 0 {
		t.Fatal("a statement was recorded for an unsigned check")
	}
	h.officeAnswer["checks"] = map[string]string{"line1": "pass", "postal_code": "pass"}
	out := h.attest(w, "card_check", material, 200)
	p := proofsOf(t, out)["address"]
	val := p["value"].(map[string]any)
	if val["postal_code"] != "SW1A 1AA" || val["street_address"] != "1 High St" {
		t.Fatalf("address value: %v", val)
	}
	if p["source"] != "card_bank" || p["label"].(map[string]any)["brand"] != "visa" {
		t.Fatalf("label: %v", p)
	}
	pr, _ := proof.Verify(h.srv.o.Signer, p["proof"].(string))
	if pr.MaterialAt != 1763702400 {
		t.Fatal("the proof does not carry the original check time")
	}
	if pr.Evidence["scope"] != "billing_address" {
		t.Fatal("the proof does not say it is a billing address")
	}
	if len(h.statements) != 1 {
		t.Fatal("no statement recorded at the back office")
	}
	// A check started by another holder is refused; a withdrawn one too.
	other := newWallet(t, h.wp)
	h.attest(other, "card_check", material, 422)
	h.officeAnswer = map[string]any{"error": "revoked"}
	h.attest(w, "card_check", material, 404)
}
func TestRebindToNewDeviceThenDisclose(t *testing.T) {
	h := newHarness(t)
	phone := newWallet(t, h.wp)
	out := h.attest(phone, "oidc_id_token", map[string]any{"provider": "google", "id_token": h.googleToken(phone, nil)}, 200)
	emailProof := proofsOf(t, out)["email"]["proof"].(string)

	// The iPad: same seed (same hk and salt), its own hardware key.
	ipad := &wallet{hk: phone.hk, salt: phone.salt}
	ipad.device, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ipad.wia = mintWIA(t, h.wp, ipad.device)

	// The phone's proof cannot be shared from the iPad.
	h.disclose(ipad, emailProof, 401)
	re := h.attest(ipad, "proof", map[string]any{"proof": emailProof}, 200)
	ipadProof := proofsOf(t, re)["email"]["proof"].(string)
	tok := h.disclose(ipad, ipadProof, 200)["token"].(string)
	if !strings.HasSuffix(tok, "~") {
		t.Fatal("not an SD-JWT")
	}
	var d proof.Disclosure
	if _, err := jose.VerifyWith(strings.TrimSuffix(tok, "~"), &h.srv.o.Signer.Key.PublicKey, proof.DisclosureTyp, &d); err != nil {
		t.Fatal(err)
	}
	if d.Aud != "rp-client" || d.Claim != "email" || d.Value != "alice@example.com" || !jose.SameECKey(d.Cnf.JWK, jose.ECJWK(&ipad.device.PublicKey)) {
		t.Fatalf("disclosure: %+v", d)
	}
	if _, leaked := d.Evidence["sub"]; leaked {
		t.Fatal("the provider subject reached the app")
	}

	// Another holder cannot rebind it.
	thief := newWallet(t, h.wp)
	h.attest(thief, "proof", map[string]any{"proof": emailProof}, 422)
}

func (h *harness) disclose(w *wallet, proofTok string, want int) map[string]any {
	p, err := proof.Verify(h.srv.o.Signer, proofTok)
	if err != nil {
		h.t.Fatal(err)
	}
	ts := time.Now().Unix()
	msg, _ := DiscloseMessage(p.JTI, "rp-client", "pairwise-sub", "n-123", ts)
	_, db := w.sign(h.t, msg)
	return h.post("/disclose", map[string]any{"proof": proofTok, "rp_id": "rp-client", "sub": "pairwise-sub",
		"nonce": "n-123", "ts": ts, "device": db, "wia": w.wia}, want)
}

func TestFrozenUntilConfigured(t *testing.T) {
	dir := t.TempDir()
	signer, _ := keys.LoadSigner(dir)
	var ck [32]byte
	arch, _ := archive.Open(ledger.NewMemBackend(), ck, signer, "m", http.DefaultClient, nil, time.Now)
	srv, err := New(Options{DataDir: dir, Signer: signer, Archive: arch, Client: http.DefaultClient, Now: time.Now, RequireWIA: true})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, _ := http.Get(ts.URL + "/challenge")
	if resp.StatusCode != 503 {
		t.Fatalf("challenge before configure: %d", resp.StatusCode)
	}
	resp, _ = http.Get(ts.URL + "/health")
	if resp.StatusCode != 200 {
		t.Fatal("health should stay open")
	}
}

func TestLedgerRecordsVersionAndRoot(t *testing.T) {
	h := newHarness(t)
	w := newWallet(t, h.wp)
	h.attest(w, "oidc_id_token", map[string]any{"provider": "google", "id_token": h.googleToken(w, nil)}, 200)
	resp, err := http.Get(h.http.URL + "/ledger/root")
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Root     archive.Root      `json:"root"`
		Versions []archive.Version `json:"versions"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Root.Version == 0 || len(out.Versions) != 1 || out.Versions[0].Measurement != "sha256:test" {
		t.Fatalf("ledger: %+v", out)
	}
	var _ = sources.ImportFreshness
}

func TestMicrosoftRule(t *testing.T) {
	h := newHarness(t)
	h.post("/configure", map[string]any{"providers": map[string]any{
		"google":    map[string]any{"audiences": []string{"privasys-google-client"}},
		"microsoft": map[string]any{"audiences": []string{"privasys-ms-client"}},
	}}, 200)
	h.srv.mu.Lock()
	h.srv.providers["microsoft"].JWKSURL = h.idp.srv.URL
	h.srv.providers["google"].JWKSURL = h.idp.srv.URL
	h.srv.mu.Unlock()
	h.srv.o.Archive.SetSources([]archive.Source{{Name: "microsoft", JWKSURL: h.idp.srv.URL}, {Name: "google", JWKSURL: h.idp.srv.URL}})
	tid := "9188040d-6c67-4c5b-b112-36a304b66dad"
	tok := func(w *wallet, extra map[string]any) string {
		c := map[string]any{"iss": "https://login.microsoftonline.com/" + tid + "/v2.0", "tid": tid,
			"aud": "privasys-ms-client", "sub": "ms-sub", "oid": "00000000-0000-0000-1234-56789abcdef0",
			"email": "dave@outlook.com", "name": "Dave", "nonce": w.commitment(),
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
		for k, v := range extra {
			c[k] = v
		}
		return h.idp.token(t, c)
	}
	w := newWallet(t, h.wp)
	// email_verified means nothing for Microsoft; only xms_edov proves it.
	out := h.attest(w, "oidc_id_token", map[string]any{"provider": "microsoft", "id_token": tok(w, map[string]any{"email_verified": true})}, 200)
	if proofsOf(t, out)["email"] != nil {
		t.Fatal("a Microsoft address was signed without xms_edov")
	}
	out = h.attest(w, "oidc_id_token", map[string]any{"provider": "microsoft", "id_token": tok(w, map[string]any{"xms_edov": true})}, 200)
	if proofsOf(t, out)["email"]["value"] != "dave@outlook.com" {
		t.Fatal("xms_edov did not prove the address")
	}
	// No oid: refused. Issuer naming another tenant: refused.
	h.attest(w, "oidc_id_token", map[string]any{"provider": "microsoft", "id_token": tok(w, map[string]any{"oid": ""})}, 422)
	h.attest(w, "oidc_id_token", map[string]any{"provider": "microsoft", "id_token": tok(w, map[string]any{"tid": "other-tenant"})}, 422)
}

// Asking for a code needs no device signature (no biometric prompt); the
// WIA alone names the device. Redeeming still needs the device key.
func TestMailStartWithoutDeviceSignature(t *testing.T) {
	h := newHarness(t)
	w := newWallet(t, h.wp)
	ch := h.challenge()
	msg, _ := MailStartMessage("erin@example.com", ch)
	hb, _ := w.sign(t, msg)
	start := h.post("/mail/start", map[string]any{"email": "erin@example.com", "holder": hb, "wia": w.wia, "challenge": ch}, 200)
	ok := h.attest(w, "mail_code", map[string]any{"email": "erin@example.com", "code": h.mail.code, "mail_token": start["mail_token"]}, 200)
	if proofsOf(t, ok)["email"]["value"] != "erin@example.com" {
		t.Fatal("no proof")
	}
	// Without a WIA, refused.
	ch = h.challenge()
	msg, _ = MailStartMessage("erin2@example.com", ch)
	hb, _ = w.sign(t, msg)
	h.post("/mail/start", map[string]any{"email": "erin2@example.com", "holder": hb, "challenge": ch}, 401)
}

// A check without a usable time signs nothing: never a proof dated 1970.
func TestCardCheckWithoutTimeSignsNothing(t *testing.T) {
	h := newHarness(t)
	w := newWallet(t, h.wp)
	h.officeAnswer = map[string]any{"match": true, "checks": map[string]string{"line1": "pass", "postal_code": "pass"},
		"holder_binding": w.commitment()}
	h.attest(w, "card_check", map[string]any{"check_id": "c2", "line1": "1 High St", "postal_code": "SW1A 1AA"}, 422)
	h.officeAnswer["checked_at"] = 1763700000
	out := h.attest(w, "card_check", map[string]any{"check_id": "c2", "line1": "1 High St", "postal_code": "SW1A 1AA"}, 200)
	pr, _ := proof.Verify(h.srv.o.Signer, proofsOf(t, out)["address"]["proof"].(string))
	if pr.MaterialAt != 1763700000 {
		t.Fatal("Unix-seconds check time not read")
	}
}
