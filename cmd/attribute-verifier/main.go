// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// The Privasys Attribute Verifier: checks the raw material behind a wallet
// attribute (a provider's signed ID token, a mail code, a card check)
// against trust anchors it holds, and signs a proof. It keeps nothing
// about people.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	pebblebackend "github.com/Privasys/immutable-ledger/backend/pebble"

	"github.com/Privasys/container-app-attribute-verifier/internal/archive"
	"github.com/Privasys/container-app-attribute-verifier/internal/keys"
	"github.com/Privasys/container-app-attribute-verifier/internal/platform"
	"github.com/Privasys/container-app-attribute-verifier/internal/server"
)

var version = "dev"

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("PORT environment variable is required")
	}
	dataDir := env("ATTRIBUTE_VERIFIER_DATA_DIR", "/data")
	// The image digest the platform attests at OID 3.2, injected by the
	// launcher: stamped into every proof so a reader can tell which audited
	// build made it.
	measurement := env("PRIVASYS_IMAGE_DIGEST", "unbound")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		log.Fatalf("data dir: %v", err)
	}

	signer, err := keys.LoadSigner(dataDir)
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}
	ck, err := keys.Secret32(dataDir, "ledger_ck")
	if err != nil {
		log.Fatalf("ledger key: %v", err)
	}
	mailKey, err := keys.Secret32(dataDir, "mail_code_key")
	if err != nil {
		log.Fatalf("mail key: %v", err)
	}
	mgr := platform.NewManager(env("PRIVASYS_MANAGER_URL", "http://127.0.0.1:9443"),
		os.Getenv("PRIVASYS_CONTAINER_NAME"), os.Getenv("PRIVASYS_CONTAINER_TOKEN"))

	backend, err := pebblebackend.Open(filepath.Join(dataDir, "key-ledger"), nil)
	if err != nil {
		log.Fatalf("key ledger: %v", err)
	}
	defer backend.Close()
	client := &http.Client{Timeout: 20 * time.Second}
	var pub archive.Publisher
	if mgr != nil {
		pub = mgr
	}
	arch, err := archive.Open(backend, ck, signer, measurement, client, pub, time.Now)
	if err != nil {
		log.Fatalf("key ledger: %v", err)
	}

	manifest, _ := os.ReadFile(env("ATTRIBUTE_VERIFIER_MANIFEST", "/privasys.json"))
	server.Version = version
	srv, err := server.New(server.Options{
		DataDir: dataDir, Measurement: measurement, Issuer: os.Getenv("ATTRIBUTE_VERIFIER_ISSUER"),
		Signer: signer, Archive: arch, Manager: mgr, MailKey: mailKey, Client: client,
		Manifest: manifest, Now: time.Now,
		// Enforced in the measured image. There is deliberately no owner
		// environment channel on the platform, so a deployed verifier
		// cannot be quietly opened to non-wallet callers.
		RequireWIA: env("ATTRIBUTE_VERIFIER_REQUIRE_WIA", "true") == "true",
	})
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	srv.Resume(ctx)
	go arch.Run(ctx, time.Hour)

	hs := &http.Server{Addr: ":" + port, Handler: srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	log.Printf("attribute-verifier %s listening on :%s (kid=%s, configured=%v)", version, port, signer.Kid, srv.Configured())
	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
