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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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
)

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
