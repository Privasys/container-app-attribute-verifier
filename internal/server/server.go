// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package server is the verifier's HTTP surface.
//
// Everything that does work is free and open to the holder's wallet only:
// each call carries a Wallet Instance Attestation bound to the device key
// that signs it. Nothing about a person is kept. What the verifier holds
// is its keys, its configuration, and the ledger of provider keys.
package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/container-app-attribute-verifier/internal/archive"
	"github.com/Privasys/container-app-attribute-verifier/internal/holder"
	"github.com/Privasys/container-app-attribute-verifier/internal/jose"
	"github.com/Privasys/container-app-attribute-verifier/internal/keys"
	"github.com/Privasys/container-app-attribute-verifier/internal/mail"
	"github.com/Privasys/container-app-attribute-verifier/internal/platform"
	"github.com/Privasys/container-app-attribute-verifier/internal/proof"
	"github.com/Privasys/container-app-attribute-verifier/internal/ratelimit"
	"github.com/Privasys/container-app-attribute-verifier/internal/sources"
	"github.com/Privasys/container-app-attribute-verifier/internal/wia"
)

// Version is set at build time.
var Version = "dev"

// DisclosureSkew bounds the age of a disclosure request's timestamp.
const DisclosureSkew = 5 * time.Minute

// Options wires a server.
type Options struct {
	DataDir     string
	Measurement string
	// Issuer, when set, is the verifier's public origin; otherwise it is
	// taken from the request's Host.
	Issuer  string
	Signer  *keys.Signer
	Archive *archive.Archive
	Manager *platform.Manager
	// KeyAttestation publishes the signing key's digest at
	// platform.OIDSigningKey; Signer.Gate refuses to sign until it has.
	KeyAttestation *platform.KeyAttestation
	MailKey        [32]byte
	Client         *http.Client
	Manifest       []byte
	Now            func() time.Time
	// RequireWIA is baked into the image as true; tests turn it off.
	RequireWIA bool
	// NoBackgroundRefresh stops configure from fetching key sets on its own
	// (tests drive the archive themselves).
	NoBackgroundRefresh bool
}

// Server is the verifier.
type Server struct {
	o          Options
	challenges *holder.Challenges
	mailCodes  *sources.MailCodes

	mailPerDevice  *ratelimit.Limiter
	mailPerAddress *ratelimit.Limiter
	mailResend     *ratelimit.Limiter
	attestLimit    *ratelimit.Limiter
	discloseLimit  *ratelimit.Limiter

	mu         sync.RWMutex
	cfg        *Config
	providers  map[string]*sources.Provider
	cards      *sources.CardChecks
	configured bool
}

// New loads any persisted configuration and returns a server.
func New(o Options) (*Server, error) {
	cfg, err := loadConfig(o.DataDir)
	if err != nil {
		return nil, err
	}
	s := &Server{o: o,
		challenges:     holder.NewChallenges(o.Signer, o.Now),
		mailCodes:      &sources.MailCodes{Signer: o.Signer, Key: o.MailKey, Now: o.Now},
		mailPerDevice:  &ratelimit.Limiter{Max: 10, Window: time.Hour, Now: o.Now},
		mailPerAddress: &ratelimit.Limiter{Max: 5, Window: time.Hour, Now: o.Now},
		mailResend:     &ratelimit.Limiter{Max: 1, Window: time.Minute, Now: o.Now},
		attestLimit:    &ratelimit.Limiter{Max: 120, Window: time.Hour, Now: o.Now},
		discloseLimit:  &ratelimit.Limiter{Max: 600, Window: time.Hour, Now: o.Now},
	}
	if err := s.apply(cfg); err != nil {
		return nil, err
	}
	return s, nil
}

// Configured says whether the configure gate has been lifted.
func (s *Server) Configured() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configured
}

func (s *Server) apply(cfg *Config) error {
	provs, err := cfg.providers()
	if err != nil {
		return err
	}
	var sender sources.Sender
	if cfg.Mail != nil {
		m, err := mail.New(*cfg.Mail, s.o.Client)
		if err != nil {
			return err
		}
		sender = m
	}
	var cards *sources.CardChecks
	if cfg.CardCheck != nil {
		cards = &sources.CardChecks{BaseURL: cfg.CardCheck.BaseURL, Client: s.o.Client}
		if s.o.Manager != nil {
			cards.Identity = s.o.Manager
		}
	}
	srcs := make([]archive.Source, 0, len(provs))
	for _, p := range provs {
		srcs = append(srcs, archive.Source{Name: p.Name, JWKSURL: p.JWKSURL})
	}
	s.o.Archive.SetSources(srcs)

	s.mu.Lock()
	s.cfg, s.providers, s.cards = cfg, provs, cards
	s.mailCodes.Sender = sender
	s.configured = cfg.WalletProviderJWKS != nil
	s.mu.Unlock()
	return nil
}

// Resume republishes the attested values after a restart and lifts the
// manager's gate when the persisted configuration is complete.
func (s *Server) Resume(ctx context.Context) {
	if !s.Configured() {
		return
	}
	// Not best-effort in effect: on failure the signing gate stays closed and
	// retries the publish at the next signature.
	if err := s.o.KeyAttestation.Publish(ctx); err != nil {
		log.Printf("attribute-verifier: signing-key OID publish failed, signing stays closed: %v", err)
	}
	s.publishConfig(ctx)
	s.o.Archive.Republish()
	if err := s.o.Manager.ConfigComplete(ctx); err != nil {
		log.Printf("attribute-verifier: config-complete on resume: %v", err)
	}
}

func (s *Server) publishConfig(ctx context.Context) {
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()
	d, err := cfg.digest()
	if err != nil {
		log.Printf("attribute-verifier: config digest: %v", err)
		return
	}
	if err := s.o.Manager.SetExtension(ctx, platform.OIDConfiguration, d); err != nil {
		log.Printf("attribute-verifier: publish config digest: %v", err)
	}
}

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"status": "healthy"})
	})
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"version": Version, "measurement": s.o.Measurement})
	})
	mux.HandleFunc("GET /.well-known/jwks.json", s.jwks)
	mux.HandleFunc("GET /jwks", s.jwks)
	mux.HandleFunc("GET /.well-known/jwt-vc-issuer", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"issuer": s.issuer(r), "jwks": map[string]any{"keys": []jose.JWK{s.o.Signer.Public()}}})
	})
	mux.HandleFunc("GET /.well-known/privasys-manifest", func(w http.ResponseWriter, r *http.Request) {
		if s.o.Manifest == nil {
			writeError(w, 404, "manifest not bundled in this build")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(s.o.Manifest)
	})
	mux.HandleFunc("POST /configure", s.configure)
	mux.HandleFunc("GET /challenge", s.gated(s.challenge))
	mux.HandleFunc("POST /challenge", s.gated(s.challenge))
	mux.HandleFunc("POST /attest", s.gated(s.attest))
	mux.HandleFunc("POST /mail/start", s.gated(s.mailStart))
	mux.HandleFunc("POST /disclose", s.gated(s.disclose))
	// Reads answer POST too: the platform's RPC proxy invokes every tool as POST.
	mux.HandleFunc("GET /evidence/keys/{source}/{kid}", s.gated(s.evidenceKey))
	mux.HandleFunc("POST /evidence/keys/{source}/{kid}", s.gated(s.evidenceKey))
	mux.HandleFunc("GET /ledger/root", s.gated(s.ledgerRoot))
	mux.HandleFunc("POST /ledger/root", s.gated(s.ledgerRoot))
	// Status signs nothing, so it answers even while signing is closed.
	mux.HandleFunc("POST /status", s.configuredOnly(s.status))
	mux.HandleFunc("GET /status", s.configuredOnly(s.status))
	mux.HandleFunc("GET /signing-key/status", s.signingKeyStatus)
	return mux
}

// gated admits a route once configured AND once the signing key is attested:
// every gated route signs. Signer.Gate refuses the signature itself either
// way; this check answers 503 before any work is done.
func (s *Server) gated(h http.HandlerFunc) http.HandlerFunc {
	return s.configuredOnly(func(w http.ResponseWriter, r *http.Request) {
		if err := s.o.KeyAttestation.Require(); err != nil {
			writeError(w, http.StatusServiceUnavailable, platform.ErrKeyNotAttested.Error())
			return
		}
		h(w, r)
	})
}

func (s *Server) configuredOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.Configured() {
			writeError(w, http.StatusServiceUnavailable, "app is awaiting initial configuration")
			return
		}
		h(w, r)
	}
}

// signingKeyStatus says what the certificate should attest at
// platform.OIDSigningKey, for an auditor to compare against the leaf.
func (s *Server) signingKeyStatus(w http.ResponseWriter, r *http.Request) {
	d, err := s.o.Signer.SPKISHA256()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"digest": fmt.Sprintf("%x", d), "kid": s.o.Signer.Kid, "oid": platform.OIDSigningKey})
}

func (s *Server) issuer(r *http.Request) string {
	if s.o.Issuer != "" {
		return s.o.Issuer
	}
	if h := r.Host; h != "" {
		return "https://" + strings.TrimSpace(strings.Split(h, ",")[0])
	}
	return "urn:privasys:attribute-verifier"
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"keys": []jose.JWK{s.o.Signer.Public()}})
}

// ── configure ────────────────────────────────────────────────────────

func (s *Server) configure(w http.ResponseWriter, r *http.Request) {
	var in Config
	if err := decode(w, r, 1<<20, &in); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	s.mu.RLock()
	held := s.cfg
	s.mu.RUnlock()
	next, err := held.merge(&in)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if next.WalletProviderJWKS == nil {
		writeError(w, 400, "wallet_provider_jwks is required to complete configuration")
		return
	}
	if err := saveConfig(s.o.DataDir, next); err != nil {
		writeError(w, 500, "could not persist the configuration")
		return
	}
	if err := s.apply(next); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	// Before the gate lifts: no proof is issued by a verifier whose
	// certificate does not attest the key that signs it.
	if err := s.o.KeyAttestation.Publish(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "the signing key could not be attested: "+err.Error())
		return
	}
	s.publishConfig(r.Context())
	if !s.o.NoBackgroundRefresh {
		go s.o.Archive.RefreshAll(context.Background())
	}
	if err := s.o.Manager.ConfigComplete(r.Context()); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	d, _ := next.digest()
	writeJSON(w, 200, s.statusBody(map[string]any{"status": "configured", "configuration_digest": fmt.Sprintf("%x", d)}))
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.statusBody(map[string]any{}))
}

func (s *Server) statusBody(out map[string]any) map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := []string{}
	for n := range s.providers {
		names = append(names, n)
	}
	out["providers"] = names
	out["mail"] = s.mailCodes.Sender != nil
	out["card_check"] = s.cards != nil
	out["require_wia"] = s.o.RequireWIA
	if root, err := s.o.Archive.CurrentRoot(); err == nil {
		out["ledger"] = root
	}
	return out
}

// ── challenge ────────────────────────────────────────────────────────

func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	tok, exp, err := s.challenges.Issue()
	if err != nil {
		writeError(w, 500, "could not issue a challenge")
		return
	}
	writeJSON(w, 200, map[string]any{"challenge": tok, "expires_at": exp})
}

// ── common request checks ────────────────────────────────────────────

func (s *Server) checkWIA(token string, c *holder.Checked) error {
	s.mu.RLock()
	jwks := s.cfg.WalletProviderJWKS
	s.mu.RUnlock()
	if !s.o.RequireWIA && token == "" {
		return nil
	}
	if jwks == nil {
		return errors.New("no wallet-provider keys configured")
	}
	return wia.Verify(*jwks, token, c.DevicePub, s.o.Now())
}

// holderWithWIA checks the holder signature and a WIA without a device
// signature; the device the WIA names keys the rate limits.
func (s *Server) holderWithWIA(h *holder.Holder, token string, msg []byte) (*holder.Checked, error) {
	c, err := holder.CheckHolder(h, msg)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	jwks := s.cfg.WalletProviderJWKS
	s.mu.RUnlock()
	if jwks == nil {
		if s.o.RequireWIA {
			return nil, errors.New("no wallet-provider keys configured")
		}
		c.Device = "unattested"
		return c, nil
	}
	if token == "" && !s.o.RequireWIA {
		c.Device = "unattested"
		return c, nil
	}
	dev, err := wia.Device(*jwks, token, s.o.Now())
	if err != nil {
		return nil, err
	}
	pub, err := dev.Public()
	if err != nil {
		return nil, err
	}
	if ec, ok := pub.(*ecdsa.PublicKey); ok {
		c.Device = holder.DeviceBinding(jose.SEC1(ec))
	}
	return c, nil
}

func tooMany(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
	writeError(w, http.StatusTooManyRequests, "too many requests; try again later")
}

// ── attest ───────────────────────────────────────────────────────────

type attestRequest struct {
	Kind      string          `json:"kind"`
	Material  json.RawMessage `json:"material"`
	Holder    *holder.Holder  `json:"holder"`
	Device    *holder.Device  `json:"device"`
	WIA       string          `json:"wia"`
	Challenge string          `json:"challenge"`
}

// AttestMessage is what the holder key and the device key both sign.
func AttestMessage(kind string, material any, challenge string) ([]byte, error) {
	d, err := jose.Digest(material)
	if err != nil {
		return nil, err
	}
	return jose.Canonical(map[string]any{"op": "attest", "kind": kind, "material": d, "challenge": challenge})
}

func (s *Server) attest(w http.ResponseWriter, r *http.Request) {
	var req attestRequest
	if err := decode(w, r, 256<<10, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	var material any
	dec := json.NewDecoder(strings.NewReader(string(req.Material)))
	dec.UseNumber()
	if err := dec.Decode(&material); err != nil || material == nil {
		writeError(w, 400, "material is required")
		return
	}
	msg, err := AttestMessage(req.Kind, material, req.Challenge)
	if err != nil {
		writeError(w, 400, "material is not canonical JSON")
		return
	}
	checked, err := holder.CheckBoth(req.Holder, req.Device, msg)
	if err != nil {
		writeError(w, 401, err.Error())
		return
	}
	if err := s.checkWIA(req.WIA, checked); err != nil {
		writeError(w, 401, err.Error())
		return
	}
	if ok, wait := s.attestLimit.Allow(checked.Device); !ok {
		tooMany(w, wait)
		return
	}
	if err := s.challenges.Spend(req.Challenge); err != nil {
		writeError(w, 401, err.Error())
		return
	}

	ctx := r.Context()
	var (
		res      *sources.Result
		rebound  *proof.Proof
		cardID   string
		checkErr error
	)
	switch req.Kind {
	case "oidc_id_token":
		var m struct {
			Provider string `json:"provider"`
			IDToken  string `json:"id_token"`
			// Reattest marks material imported earlier: its age is not
			// held against it.
			Reattest bool `json:"reattest"`
		}
		if err := json.Unmarshal(req.Material, &m); err != nil {
			writeError(w, 400, "material: "+err.Error())
			return
		}
		s.mu.RLock()
		p := s.providers[m.Provider]
		s.mu.RUnlock()
		if p == nil {
			writeError(w, 400, fmt.Sprintf("provider %q is not configured", m.Provider))
			return
		}
		res, checkErr = sources.CheckIDToken(ctx, p, s.o.Archive, m.IDToken, checked.Commitment, !m.Reattest, s.o.Now())
	case "github":
		var m struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal(req.Material, &m); err != nil {
			writeError(w, 400, "material: "+err.Error())
			return
		}
		res, checkErr = sources.CheckGitHub(ctx, s.o.Client, m.AccessToken, s.o.Now())
	case "mail_code":
		var m struct {
			Email     string `json:"email"`
			Code      string `json:"code"`
			MailToken string `json:"mail_token"`
		}
		if err := json.Unmarshal(req.Material, &m); err != nil {
			writeError(w, 400, "material: "+err.Error())
			return
		}
		res, checkErr = s.mailCodes.Complete(m.MailToken, m.Email, m.Code, checked.Commitment)
		var wrong *sources.ErrWrongCode
		if errors.As(checkErr, &wrong) {
			writeJSON(w, 400, map[string]any{"error": checkErr.Error(), "attempts_left": wrong.Left})
			return
		}
	case "card_check":
		var m sources.CardMaterial
		if err := json.Unmarshal(req.Material, &m); err != nil {
			writeError(w, 400, "material: "+err.Error())
			return
		}
		s.mu.RLock()
		cards := s.cards
		s.mu.RUnlock()
		res, checkErr = cards.Check(ctx, m, checked.Commitment)
		cardID = m.CheckID
	case "proof":
		var m struct {
			Proof string `json:"proof"`
		}
		if err := json.Unmarshal(req.Material, &m); err != nil {
			writeError(w, 400, "material: "+err.Error())
			return
		}
		rebound, checkErr = proof.Verify(s.o.Signer, m.Proof)
		if checkErr == nil && !holder.Equal(rebound.Holder.Commitment, checked.Commitment) {
			checkErr = errors.New("the proof belongs to another holder")
		}
	default:
		writeError(w, 400, fmt.Sprintf("kind %q is not one of oidc_id_token, github, mail_code, card_check, proof", req.Kind))
		return
	}
	if checkErr != nil {
		status := 422
		if errors.Is(checkErr, sources.ErrNoCheck) {
			status = 404
		}
		writeError(w, status, checkErr.Error())
		return
	}

	now := s.o.Now()
	bind := proof.Binding{Commitment: checked.Commitment, Device: checked.Device}
	var proofs []proof.Proof
	if rebound != nil {
		p := *rebound
		ev := map[string]any{}
		for k, v := range rebound.Evidence {
			ev[k] = v
		}
		ev["rebound_from"] = rebound.JTI
		p.JTI, p.Iat, p.Holder, p.Evidence = proof.NewJTI(), now.Unix(), bind, ev
		p.Measurement = s.o.Measurement
		proofs = append(proofs, p)
	} else {
		for _, v := range res.Values {
			proofs = append(proofs, proof.Proof{
				JTI: proof.NewJTI(), Iss: s.issuer(r), Iat: now.Unix(),
				Attr: v.Attr, Value: v.Value, Method: res.Method, Source: res.Source, Label: res.Label,
				MaterialAt: res.MaterialAt.Unix(), Evidence: res.Evidence, Holder: bind,
				Measurement: s.o.Measurement,
			})
		}
	}
	out := make([]map[string]any, 0, len(proofs))
	for _, p := range proofs {
		tok, err := proof.Sign(s.o.Signer, p)
		if err != nil {
			writeError(w, 500, "could not sign the proof")
			return
		}
		if cardID != "" {
			// The back office keeps the hash of every statement made about
			// a check, for the retention period. No record, no proof.
			h := sha256.Sum256([]byte(tok))
			if err := s.cards.Statement(ctx, cardID, jose.B64(h[:])); err != nil {
				writeError(w, 502, "the back office could not record the statement")
				return
			}
		}
		out = append(out, map[string]any{"attr": p.Attr, "value": p.Value, "method": p.Method,
			"source": p.Source, "label": p.Label, "proof": tok})
	}
	writeJSON(w, 200, map[string]any{"proofs": out})
}

// ── mail ─────────────────────────────────────────────────────────────

type mailStartRequest struct {
	Email     string         `json:"email"`
	Holder    *holder.Holder `json:"holder"`
	Device    *holder.Device `json:"device"`
	WIA       string         `json:"wia"`
	Challenge string         `json:"challenge"`
}

// MailStartMessage is what both keys sign to ask for a code.
func MailStartMessage(email, challenge string) ([]byte, error) {
	return jose.Canonical(map[string]any{"op": "mail_start", "email": email, "challenge": challenge})
}

func (s *Server) mailStart(w http.ResponseWriter, r *http.Request) {
	var req mailStartRequest
	if err := decode(w, r, 16<<10, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	email, ok := sources.NormaliseEmail(req.Email)
	if !ok {
		writeError(w, 400, "that is not an email address")
		return
	}
	msg, _ := MailStartMessage(req.Email, req.Challenge)
	// Asking for a code binds nothing to the device, so the hardware key
	// (and the biometric prompt it costs) is not needed here: the holder
	// key and the Wallet Instance Attestation are. The device key signs at
	// redemption, where the proof is bound to it. A device signature is
	// still accepted when sent.
	var checked *holder.Checked
	var err error
	if req.Device != nil {
		if checked, err = holder.CheckBoth(req.Holder, req.Device, msg); err == nil {
			err = s.checkWIA(req.WIA, checked)
		}
	} else {
		checked, err = s.holderWithWIA(req.Holder, req.WIA, msg)
	}
	if err != nil {
		writeError(w, 401, err.Error())
		return
	}
	addrKey := func() string { h := sha256.Sum256([]byte(email)); return jose.B64(h[:]) }()
	if ok, wait := s.mailResend.Allow(addrKey); !ok {
		tooMany(w, wait)
		return
	}
	if ok, wait := s.mailPerDevice.Allow(checked.Device); !ok {
		tooMany(w, wait)
		return
	}
	if ok, wait := s.mailPerAddress.Allow(addrKey); !ok {
		tooMany(w, wait)
		return
	}
	if err := s.challenges.Spend(req.Challenge); err != nil {
		writeError(w, 401, err.Error())
		return
	}
	s.mu.RLock()
	enabled := s.mailCodes.Sender != nil
	s.mu.RUnlock()
	if !enabled {
		writeError(w, 503, "this verifier cannot send mail")
		return
	}
	tok, exp, err := s.mailCodes.Start(r.Context(), email, checked.Commitment)
	if err != nil {
		// The address is not logged: it is the holder's.
		log.Printf("attribute-verifier: mail start: %v", err)
		writeError(w, 502, "the code could not be sent")
		return
	}
	writeJSON(w, 200, map[string]any{"mail_token": tok, "expires_at": exp,
		"code_length": 6, "max_attempts": sources.MailMaxAttempts, "resend_after": 60})
}

// ── disclose ─────────────────────────────────────────────────────────

type discloseRequest struct {
	Proof  string         `json:"proof"`
	RPID   string         `json:"rp_id"`
	Sub    string         `json:"sub"`
	Nonce  string         `json:"nonce"`
	TS     int64          `json:"ts"`
	Device *holder.Device `json:"device"`
	WIA    string         `json:"wia"`
}

// DiscloseMessage is what the device key signs to share a proof.
func DiscloseMessage(proofJTI, rpID, sub, nonce string, ts int64) ([]byte, error) {
	return jose.Canonical(map[string]any{"op": "disclose", "proof": proofJTI, "rp_id": rpID,
		"sub": sub, "nonce": nonce, "ts": ts})
}

func (s *Server) disclose(w http.ResponseWriter, r *http.Request) {
	var req discloseRequest
	if err := decode(w, r, 64<<10, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if req.RPID == "" || req.Sub == "" || req.Nonce == "" {
		writeError(w, 400, "rp_id, sub and nonce are required")
		return
	}
	p, err := proof.Verify(s.o.Signer, req.Proof)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	now := s.o.Now()
	if d := now.Sub(time.Unix(req.TS, 0)); d > DisclosureSkew || d < -DisclosureSkew {
		writeError(w, 401, "stale request timestamp")
		return
	}
	msg, _ := DiscloseMessage(p.JTI, req.RPID, req.Sub, req.Nonce, req.TS)
	checked, err := holder.CheckDevice(req.Device, msg)
	if err != nil {
		writeError(w, 401, err.Error())
		return
	}
	if !holder.Equal(checked.Device, p.Holder.Device) {
		writeError(w, 401, "the proof is bound to another device; rebind it first")
		return
	}
	if err := s.checkWIA(req.WIA, checked); err != nil {
		writeError(w, 401, err.Error())
		return
	}
	if ok, wait := s.discloseLimit.Allow(checked.Device); !ok {
		tooMany(w, wait)
		return
	}
	tok, err := proof.Disclose(s.o.Signer, p, s.issuer(r), req.Sub, req.RPID, req.Nonce, jose.ECJWK(checked.DevicePub), now)
	if err != nil {
		writeError(w, 500, "could not sign the disclosure")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

// ── evidence ─────────────────────────────────────────────────────────

func (s *Server) evidenceKey(w http.ResponseWriter, r *http.Request) {
	rec, err := s.o.Archive.Lookup(r.Context(), r.PathValue("source"), r.PathValue("kid"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	signed, err := s.o.Archive.Sign(rec)
	if err != nil {
		writeError(w, 500, "could not sign the record")
		return
	}
	writeJSON(w, 200, map[string]any{"record": rec, "signed": signed})
}

func (s *Server) ledgerRoot(w http.ResponseWriter, r *http.Request) {
	root, err := s.o.Archive.CurrentRoot()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	versions, err := s.o.Archive.Versions()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	signed, err := s.o.Signer.Sign("application/privasys-av-ledger-root+jws", map[string]any{
		"root": root, "measurement": s.o.Measurement, "at": s.o.Now().Unix()})
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"root": root, "signed": signed, "versions": versions})
}

// ── helpers ──────────────────────────────────────────────────────────

func decode(w http.ResponseWriter, r *http.Request, max int64, into any) error {
	body := http.MaxBytesReader(w, r.Body, max)
	raw, err := io.ReadAll(body)
	if err != nil {
		return errors.New("request body too large or unreadable")
	}
	if len(raw) == 0 {
		return errors.New("a JSON body is required")
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return errors.New("invalid JSON body")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
