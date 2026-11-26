// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package platform talks to the enclave manager that runs this container:
// it carries values into the per-container RA-TLS leaf, lifts the
// configure gate, and mints the attested identity the control plane
// admits the verifier by.
package platform

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Object identifiers under the app's attestation arc.
const (
	// OIDConfiguration carries SHA-256 of the configuration in force
	// (wallet-provider keys, providers, mail sender, back office), secrets
	// excluded, so a client can pin what the verifier trusts.
	OIDConfiguration = "1.3.6.1.4.1.65230.5.4.1"
	// OIDLedgerRoot carries the provider-key ledger's live root.
	OIDLedgerRoot = "1.3.6.1.4.1.65230.5.4.2"
	// OIDSigningKey carries SHA-256 of the SPKI (DER) of the key that signs
	// every proof and disclosure. Its JWKS is served over the gateway's
	// public TLS; this ties it to the attested build. A relying party checks
	// it on the same leaf as the app id (4.1) and code digest (4.2).
	OIDSigningKey = "1.3.6.1.4.1.65230.5.4.3"
)

// ErrKeyNotAttested refuses a signature: the signing key's digest is not
// (yet) in the attested leaf.
var ErrKeyNotAttested = errors.New("the signing key is not attested yet; try again shortly")

// RetryInterval bounds the gate's self-heal publish: at most one attempt per
// interval, shared by every request, so a burst of signing calls while
// unattested gets an immediate refusal instead of each calling the manager.
const RetryInterval = 10 * time.Second

// OnPlatform says whether ANY sign in env says this runs on the platform: the
// launcher-injected image digest, a manager URL, or a container name or
// token. Only when none is present is a missing manager taken to mean "off
// the platform" rather than "manager unreachable".
func OnPlatform(getenv func(string) string) bool {
	for _, k := range []string{"PRIVASYS_IMAGE_DIGEST", "PRIVASYS_MANAGER_URL",
		"PRIVASYS_CONTAINER_NAME", "PRIVASYS_CONTAINER_TOKEN"} {
		if getenv(k) != "" {
			return true
		}
	}
	return false
}

// KeyAttestation publishes the signing key's digest at OIDSigningKey and
// gates signing on it. The leaf state does not survive a restart, so every
// process starts unattested and publishes on configure, on resume, or from
// the gate's (rate-limited) self-heal.
type KeyAttestation struct {
	m          *Manager
	digest     []byte
	onPlatform bool
	// Now is the retry clock (tests move it by hand).
	Now func() time.Time

	mu         sync.Mutex
	done       bool
	lastRetry  time.Time
	onAttested func()
	notified   bool
}

// OnAttested registers fn to run once, after the first successful publish
// (from configure, resume or the gate's self-heal). Registered after that
// publish, it runs at once. fn runs on its own goroutine: the publish can be
// the gate's self-heal inside a signature whose caller holds a lock fn needs
// (the ledger signs under its own mutex), and Go mutexes are not reentrant.
func (k *KeyAttestation) OnAttested(fn func()) {
	if k == nil {
		return
	}
	k.mu.Lock()
	k.onAttested = fn
	k.mu.Unlock()
	k.notify()
}

func (k *KeyAttestation) notify() {
	k.mu.Lock()
	if !k.done || k.notified || k.onAttested == nil {
		k.mu.Unlock()
		return
	}
	k.notified = true
	fn := k.onAttested
	k.mu.Unlock()
	go fn()
}

// NewKeyAttestation returns the gate for a key whose SPKI digest is digest.
// It is open only when the app is clearly off the platform (onPlatform false
// and no manager); on the platform without a manager it always refuses.
func NewKeyAttestation(m *Manager, digest []byte, onPlatform bool) *KeyAttestation {
	return &KeyAttestation{m: m, digest: digest, onPlatform: onPlatform || m != nil, Now: time.Now}
}

// offPlatform is the only case in which the gate is open without a publish.
func (k *KeyAttestation) offPlatform() bool { return k == nil || (!k.onPlatform && k.m == nil) }

// Publish installs the digest on the leaf. An error leaves signing closed.
func (k *KeyAttestation) Publish(ctx context.Context) error {
	if k.offPlatform() {
		return nil
	}
	if k.m == nil {
		return errors.New("on the platform but without manager credentials")
	}
	if err := k.m.SetExtension(ctx, OIDSigningKey, k.digest); err != nil {
		return err
	}
	k.mu.Lock()
	k.done = true
	k.mu.Unlock()
	k.notify()
	return nil
}

// Require is the signing gate: nil once the digest is published (or clearly
// off the platform). Otherwise it retries the publish, at most once per
// RetryInterval across all callers, and refuses until one succeeds.
func (k *KeyAttestation) Require() error {
	if k.offPlatform() {
		return nil
	}
	k.mu.Lock()
	if k.done {
		k.mu.Unlock()
		return nil
	}
	now := k.Now()
	if !k.lastRetry.IsZero() && now.Sub(k.lastRetry) < RetryInterval {
		k.mu.Unlock()
		return ErrKeyNotAttested
	}
	k.lastRetry = now
	k.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := k.Publish(ctx); err != nil {
		log.Printf("attribute-verifier: refusing to sign, signing-key OID not attested: %v", err)
		return fmt.Errorf("%w (%v)", ErrKeyNotAttested, err)
	}
	return nil
}

// Manager is the in-enclave callback client.
type Manager struct {
	baseURL, container, token string
	client                    *http.Client
}

// NewManager returns a client, or nil off the platform.
func NewManager(managerURL, container, token string) *Manager {
	if managerURL == "" || container == "" || token == "" {
		return nil
	}
	if _, err := url.Parse(managerURL); err != nil {
		return nil
	}
	return &Manager{baseURL: strings.TrimRight(managerURL, "/"), container: container, token: token,
		client: &http.Client{Timeout: 10 * time.Second}}
}

// SetExtension installs an attestation extension on the next leaf.
func (m *Manager) SetExtension(ctx context.Context, oid string, value []byte) error {
	if m == nil {
		return nil
	}
	return m.post(ctx, "/api/v1/containers/"+url.PathEscape(m.container)+"/attestation-extensions",
		map[string]string{"oid": oid, "value_b64": base64.StdEncoding.EncodeToString(value)}, nil)
}

// PublishRoot installs the ledger root.
func (m *Manager) PublishRoot(ctx context.Context, rootHex string) error {
	raw, err := hex.DecodeString(rootHex)
	if err != nil {
		return fmt.Errorf("platform: root is not hex: %w", err)
	}
	return m.SetExtension(ctx, OIDLedgerRoot, raw)
}

// ConfigComplete lifts the runtime's configure gate.
func (m *Manager) ConfigComplete(ctx context.Context) error {
	if m == nil {
		return nil
	}
	return m.post(ctx, "/api/v1/containers/"+url.PathEscape(m.container)+"/config-complete", map[string]any{}, nil)
}

// headerIdentityContext binds a quote to the header identity flow.
var headerIdentityContext = sha256.Sum256([]byte("privasys-ratls-attest-v2-header-identity"))

// AppIdentity returns the headers of one control-plane call: the identity
// leaf, a fresh challenge (8 bytes of Unix seconds and 24 random), and a
// quote over both, each in standard base64. No secret is configured: the
// control plane admits the call by the quote.
func (m *Manager) AppIdentity(ctx context.Context) (identity, challenge, evidence string, err error) {
	if m == nil {
		return "", "", "", fmt.Errorf("platform: not running on the platform")
	}
	var leaf struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := m.post(ctx, "/api/v1/egress-identity", map[string]any{"v": 2}, &leaf); err != nil {
		return "", "", "", err
	}
	pair, err := tls.X509KeyPair([]byte(leaf.CertPEM), []byte(leaf.KeyPEM))
	if err != nil {
		return "", "", "", fmt.Errorf("platform: identity leaf: %w", err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "", "", "", fmt.Errorf("platform: identity leaf: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", "", "", err
	}
	ch := make([]byte, 32)
	binary.BigEndian.PutUint64(ch[:8], uint64(time.Now().Unix()))
	if _, err := rand.Read(ch[8:]); err != nil {
		return "", "", "", err
	}
	spkiHash := sha256.Sum256(spki)
	var quoted struct {
		Quote string `json:"quote"`
	}
	if err := m.post(ctx, "/api/v1/egress-evidence", map[string]any{
		"v":           2,
		"spki_sha256": base64.RawURLEncoding.EncodeToString(spkiHash[:]),
		"context":     base64.RawURLEncoding.EncodeToString(ch),
		"hctx":        base64.RawURLEncoding.EncodeToString(headerIdentityContext[:]),
	}, &quoted); err != nil {
		return "", "", "", err
	}
	quote, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(quoted.Quote, "="))
	if err != nil {
		return "", "", "", fmt.Errorf("platform: the quote is not base64url")
	}
	return base64.StdEncoding.EncodeToString(pair.Certificate[0]),
		base64.StdEncoding.EncodeToString(ch),
		base64.StdEncoding.EncodeToString(quote), nil
}

func (m *Manager) post(ctx context.Context, path string, body, into any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("platform: %s: %w", path, err)
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("platform: %s: %d %s", path, resp.StatusCode, strings.TrimSpace(string(answer)))
	}
	if into == nil {
		return nil
	}
	return json.Unmarshal(answer, into)
}
