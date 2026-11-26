// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package archive keeps every identity-provider signing key the verifier
// has seen, for as long as proofs that used it must stay checkable.
//
// Providers publish their keys as plain JSON over HTTPS. The document is
// not signed: only TLS vouches for it, and only at the moment it is
// fetched. Providers also drop old keys within weeks, so years later
// nothing they publish shows a key was ever theirs. The archive is what
// does: attested code fetched the key over TLS at a known time and
// recorded it, with when it was first and last seen, in a tamper-evident
// ledger whose root the verifier's attested certificate carries.
//
// A proof carries a key record signed by the verifier, so it can be
// checked with no access to the verifier at all; the ledger is the
// verifier's own memory, used to re-attest years later. It holds
// provider keys only, never anything about people.
package archive

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	ledger "github.com/Privasys/immutable-ledger/ledger"

	"github.com/Privasys/container-app-attribute-verifier/internal/jose"
	"github.com/Privasys/container-app-attribute-verifier/internal/keys"
	"github.com/Privasys/container-app-attribute-verifier/internal/platform"
)

// RecordTyp is the JOSE typ of a signed key record.
const RecordTyp = "application/privasys-provider-key+jws"

// Slack widens a key's window on both sides: a token signed a little
// before the verifier first saw its key, or a little after it last did,
// still checks. Refreshes run hourly, so a few hours is ample.
const Slack = 6 * time.Hour

// touchEvery bounds how often an unchanged key's last_seen is rewritten.
const touchEvery = 6 * time.Hour

// minRefetch bounds how often an unknown kid may trigger a fetch.
const minRefetch = time.Minute

// Source is one provider key set.
type Source struct {
	// Name is the archive's name for the set: google, microsoft, linkedin.
	Name    string `json:"name"`
	JWKSURL string `json:"jwks_url"`
}

// Record is one archived key.
type Record struct {
	Source    string   `json:"source"`
	Kid       string   `json:"kid"`
	JWK       jose.JWK `json:"jwk"`
	JWKSURL   string   `json:"jwks_url"`
	FirstSeen int64    `json:"first_seen"`
	LastSeen  int64    `json:"last_seen"`
}

// Covers reports whether a token issued at iat falls in the key's window.
func (r *Record) Covers(iat time.Time) bool {
	return !iat.Before(time.Unix(r.FirstSeen, 0).Add(-Slack)) &&
		!iat.After(time.Unix(r.LastSeen, 0).Add(Slack))
}

// Publisher puts the ledger root into the attested certificate.
type Publisher interface {
	PublishRoot(ctx context.Context, rootHex string) error
}

// Archive is the key ledger plus its fetcher.
type Archive struct {
	signer      *keys.Signer
	measurement string
	client      *http.Client
	now         func() time.Time
	pub         Publisher

	mu      sync.Mutex
	store   *ledger.Store
	sources map[string]Source
	fetched map[string]time.Time
}

// Open opens the ledger on backend under commitment key ck.
func Open(backend ledger.Backend, ck [32]byte, signer *keys.Signer, measurement string,
	client *http.Client, pub Publisher, now func() time.Time) (*Archive, error) {
	store, err := ledger.OpenOrCreate(backend, ck, ledger.WithHistoryChain())
	if err != nil {
		return nil, fmt.Errorf("archive: %w", err)
	}
	a := &Archive{signer: signer, measurement: measurement, client: client, now: now, pub: pub,
		store: store, sources: map[string]Source{}, fetched: map[string]time.Time{}}
	if err := a.recordVersion(); err != nil {
		// The signing key is not attested yet (platform.KeyAttestation
		// refused the signature). The verifier still starts and answers 503
		// on signing routes; the record is written by RecordVersion once the
		// key's first publish succeeds.
		if !errors.Is(err, platform.ErrKeyNotAttested) {
			return nil, err
		}
		log.Printf("attribute-verifier: version record deferred until the signing key is attested: %v", err)
	}
	return a, nil
}

// RecordVersion writes this build's version record if it is not in the
// ledger yet. Idempotent: it is called again on the key's first successful
// attestation, after a deferred Open.
func (a *Archive) RecordVersion() error {
	return a.recordVersion()
}

// SetSources replaces the key sets the archive refreshes.
func (a *Archive) SetSources(srcs []Source) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sources = map[string]Source{}
	for _, s := range srcs {
		a.sources[s.Name] = s
	}
}

func recordKey(source, kid string) []byte { return []byte("k/" + source + "\x00" + kid) }

// Lookup returns the archived key, fetching the source once if the kid is
// unknown (a rotation the hourly refresh has not seen yet).
func (a *Archive) Lookup(ctx context.Context, source, kid string) (*Record, error) {
	if rec, err := a.get(source, kid); err != nil || rec != nil {
		return rec, err
	}
	a.mu.Lock()
	last := a.fetched[source]
	a.mu.Unlock()
	if a.now().Sub(last) >= minRefetch {
		if err := a.Refresh(ctx, source); err != nil {
			return nil, err
		}
		if rec, err := a.get(source, kid); err != nil || rec != nil {
			return rec, err
		}
	}
	return nil, fmt.Errorf("archive: %s has never published key %q", source, kid)
}

func (a *Archive) get(source, kid string) (*Record, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	raw, ok, err := a.store.Get(recordKey(source, kid))
	if err != nil {
		return nil, fmt.Errorf("archive: %w", err)
	}
	if !ok {
		return nil, nil
	}
	var r Record
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("archive: %w", err)
	}
	return &r, nil
}

// RefreshAll fetches every source.
func (a *Archive) RefreshAll(ctx context.Context) {
	a.mu.Lock()
	names := make([]string, 0, len(a.sources))
	for n := range a.sources {
		names = append(names, n)
	}
	a.mu.Unlock()
	for _, n := range names {
		if err := a.Refresh(ctx, n); err != nil {
			log.Printf("archive: refresh %s: %v", n, err)
		}
	}
}

// Run refreshes every source now and then every interval until ctx ends.
func (a *Archive) Run(ctx context.Context, interval time.Duration) {
	a.RefreshAll(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.RefreshAll(ctx)
		}
	}
}

// Refresh fetches one source's key set over TLS and records what it holds.
func (a *Archive) Refresh(ctx context.Context, name string) error {
	a.mu.Lock()
	src, ok := a.sources[name]
	a.fetched[name] = a.now()
	a.mu.Unlock()
	if !ok {
		return fmt.Errorf("archive: unknown key source %q", name)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.JWKSURL, nil)
	if err != nil {
		return err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("archive: fetch %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("archive: fetch %s: %s", name, resp.Status)
	}
	var set struct {
		Keys []jose.JWK `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return fmt.Errorf("archive: %s: %w", name, err)
	}
	return a.record(src, set.Keys)
}

func (a *Archive) record(src Source, ks []jose.JWK) error {
	now := a.now().Unix()
	a.mu.Lock()
	defer a.mu.Unlock()
	var ops []ledger.Op
	for _, k := range ks {
		if k.Kid == "" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		if _, err := k.Public(); err != nil {
			continue
		}
		key := recordKey(src.Name, k.Kid)
		raw, ok, err := a.store.Get(key)
		if err != nil {
			return fmt.Errorf("archive: %w", err)
		}
		rec := Record{Source: src.Name, Kid: k.Kid, JWK: k, JWKSURL: src.JWKSURL, FirstSeen: now, LastSeen: now}
		if ok {
			var held Record
			if err := json.Unmarshal(raw, &held); err != nil {
				return fmt.Errorf("archive: %w", err)
			}
			// A kid that comes back with different key material is a new
			// key under an old name. Keep the first: a proof already
			// relies on it, and silently replacing it would let the
			// later key vouch for tokens the earlier one signed.
			if mustThumb(held.JWK) != mustThumb(k) {
				log.Printf("archive: %s key %s changed material; keeping the first", src.Name, k.Kid)
				continue
			}
			if now-held.LastSeen < int64(touchEvery/time.Second) {
				continue
			}
			rec.FirstSeen = held.FirstSeen
		}
		val, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		ops = append(ops, ledger.Put(key, val))
	}
	if len(ops) == 0 {
		return nil
	}
	if _, _, err := a.store.PutBatch(ops); err != nil {
		return fmt.Errorf("archive: %w", err)
	}
	a.publishLocked()
	return nil
}

func mustThumb(k jose.JWK) string {
	t, _ := k.Thumbprint()
	return t
}

func (a *Archive) publishLocked() {
	if a.pub == nil {
		return
	}
	root, _ := a.store.Root()
	go func(h string) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := a.pub.PublishRoot(ctx, h); err != nil {
			log.Printf("archive: publish root: %v", err)
		}
	}(hex.EncodeToString(root[:]))
}

// Republish puts the current root back into the certificate after a
// restart: the extension lives only in the manager's memory.
func (a *Archive) Republish() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.publishLocked()
}

// Root is the ledger's state, for anchoring.
type Root struct {
	Root        string `json:"root"`
	Version     uint64 `json:"version"`
	HistoryHead string `json:"history_head"`
}

// CurrentRoot returns the root, version and history head.
func (a *Archive) CurrentRoot() (Root, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rootLocked()
}

func (a *Archive) rootLocked() (Root, error) {
	root, version := a.store.Root()
	head, _, err := a.store.HistoryHead()
	if err != nil {
		return Root{}, err
	}
	return Root{Root: hex.EncodeToString(root[:]), Version: version, HistoryHead: hex.EncodeToString(head[:])}, nil
}

// signedRecord is what a proof carries for its key.
type signedRecord struct {
	Record
	Ledger      Root   `json:"ledger"`
	Measurement string `json:"measurement"`
	SignedAt    int64  `json:"signed_at"`
}

// Sign returns the record signed by the verifier, with the ledger state
// it was read at.
func (a *Archive) Sign(r *Record) (string, error) {
	root, err := a.CurrentRoot()
	if err != nil {
		return "", err
	}
	return a.signer.Sign(RecordTyp, signedRecord{Record: *r, Ledger: root,
		Measurement: a.measurement, SignedAt: a.now().Unix()})
}

// ── continuity across versions ───────────────────────────────────────

// Version is the ledger's entry for one build of the verifier: the first
// time a build opens the ledger it records itself, the key it signs with,
// and the state it found, signed by that key. Read in order, the entries
// chain every build to the ledger its predecessors kept.
type Version struct {
	Measurement string `json:"measurement"`
	Kid         string `json:"kid"`
	Found       Root   `json:"found"`
	At          int64  `json:"at"`
	Sig         string `json:"sig,omitempty"`
}

var versionIndexKey = []byte("v/index")

func (a *Archive) recordVersion() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	idx, err := a.versionIndexLocked()
	if err != nil {
		return err
	}
	for _, m := range idx {
		if m == a.measurement+"|"+a.signer.Kid {
			return nil
		}
	}
	found, err := a.rootLocked()
	if err != nil {
		return err
	}
	v := Version{Measurement: a.measurement, Kid: a.signer.Kid, Found: found, At: a.now().Unix()}
	sig, err := a.signer.Sign("application/privasys-av-version+jws", v)
	if err != nil {
		return err
	}
	v.Sig = sig
	name := a.measurement + "|" + a.signer.Kid
	val, _ := json.Marshal(v)
	idx = append(idx, name)
	ib, _ := json.Marshal(idx)
	if _, _, err := a.store.PutBatch([]ledger.Op{
		ledger.Put([]byte("v/"+name), val),
		ledger.Put(versionIndexKey, ib),
	}); err != nil {
		return fmt.Errorf("archive: %w", err)
	}
	return nil
}

func (a *Archive) versionIndexLocked() ([]string, error) {
	raw, ok, err := a.store.Get(versionIndexKey)
	if err != nil {
		return nil, fmt.Errorf("archive: %w", err)
	}
	var idx []string
	if ok {
		if err := json.Unmarshal(raw, &idx); err != nil {
			return nil, fmt.Errorf("archive: %w", err)
		}
	}
	return idx, nil
}

// Versions lists every build that has kept this ledger, oldest first.
func (a *Archive) Versions() ([]Version, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	idx, err := a.versionIndexLocked()
	if err != nil {
		return nil, err
	}
	out := make([]Version, 0, len(idx))
	for _, name := range idx {
		raw, ok, err := a.store.Get([]byte("v/" + name))
		if err != nil || !ok {
			return nil, errors.New("archive: a version entry is missing")
		}
		var v Version
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
