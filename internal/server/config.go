// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package server

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Privasys/container-app-attribute-verifier/internal/jose"
	"github.com/Privasys/container-app-attribute-verifier/internal/mail"
	"github.com/Privasys/container-app-attribute-verifier/internal/sources"
	"github.com/Privasys/container-app-attribute-verifier/internal/wia"
)

// Config is what configure delivers, persisted on the sealed volume so a
// restart does not need it again.
type Config struct {
	WalletProviderJWKS *wia.JWKS `json:"wallet_provider_jwks,omitempty"`
	// Providers overrides or adds OIDC providers. For a known provider
	// (google, microsoft, linkedin) only audiences and vouching_tenants
	// are read; any other name must be a full definition.
	Providers map[string]*sources.Provider `json:"providers,omitempty"`
	Mail      *mail.Settings               `json:"mail,omitempty"`
	CardCheck *CardCheckConfig             `json:"card_check,omitempty"`
	// GitHub is privasys.id's GitHub app (IDP_GITHUB_CLIENT_ID and
	// _SECRET): a GitHub email is proven only for a token issued to it.
	GitHub *sources.GitHubApp `json:"github,omitempty"`
}

// CardCheckConfig names the back office.
type CardCheckConfig struct {
	BaseURL string `json:"base_url"`
}

const configFile = "config.json"

func loadConfig(dir string) (*Config, error) {
	raw, err := os.ReadFile(filepath.Join(dir, configFile))
	if errors.Is(err, os.ErrNotExist) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &c, nil
}

func saveConfig(dir string, c *Config) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, configFile+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, configFile))
}

// merge applies an incoming configure call over what is held: a part the
// call leaves out keeps its value.
func (c *Config) merge(in *Config) (*Config, error) {
	out := *c
	if in.WalletProviderJWKS != nil {
		if err := in.WalletProviderJWKS.Validate(); err != nil {
			return nil, err
		}
		out.WalletProviderJWKS = in.WalletProviderJWKS
	}
	if in.Providers != nil {
		merged := map[string]*sources.Provider{}
		for k, v := range c.Providers {
			merged[k] = v
		}
		for k, v := range in.Providers {
			if v == nil {
				delete(merged, k)
				continue
			}
			v.Name = k
			merged[k] = v
		}
		out.Providers = merged
	}
	if in.Mail != nil {
		held := mail.Settings{}
		if c.Mail != nil {
			held = *c.Mail
		}
		m := in.Mail.Merge(held)
		if err := m.Validate(); err != nil {
			return nil, err
		}
		out.Mail = &m
	}
	if in.CardCheck != nil {
		if !strings.HasPrefix(in.CardCheck.BaseURL, "https://") {
			return nil, errors.New("card_check.base_url must be https")
		}
		out.CardCheck = in.CardCheck
	}
	if in.GitHub != nil {
		held := sources.GitHubApp{}
		if c.GitHub != nil {
			held = *c.GitHub
		}
		a := in.GitHub.Merge(held)
		if err := a.Validate(); err != nil {
			return nil, err
		}
		out.GitHub = &a
	}
	if _, err := out.providers(); err != nil {
		return nil, err
	}
	return &out, nil
}

// providers resolves the effective provider set: the built-in ones with
// configured audiences, plus fully defined others.
func (c *Config) providers() (map[string]*sources.Provider, error) {
	out := map[string]*sources.Provider{}
	defaults := sources.Defaults()
	for name, in := range c.Providers {
		if d, known := defaults[name]; known {
			p := *d
			p.Audiences = in.Audiences
			p.VouchingTenants = in.VouchingTenants
			if len(p.Audiences) == 0 {
				continue
			}
			out[name] = &p
			continue
		}
		p := *in
		p.Name = name
		if !strings.HasPrefix(name, "oidc:") {
			return nil, fmt.Errorf("provider %q: a provider other than google, microsoft or linkedin is named oidc:<issuer>", name)
		}
		if p.Claims == nil {
			p.Claims = map[string]string{"email": "email", "name": "name", "given_name": "given_name",
				"family_name": "family_name", "picture": "picture", "locale": "locale"}
		}
		if p.EmailRule == "" {
			p.EmailRule = sources.RuleEmailVerified
		}
		if err := p.Validate(); err != nil {
			return nil, err
		}
		out[name] = &p
	}
	return out, nil
}

// digest is SHA-256 over the configuration in force, secrets excluded.
func (c *Config) digest() ([]byte, error) {
	pub := *c
	if c.Mail != nil {
		m := c.Mail.Public()
		pub.Mail = &m
	}
	if c.GitHub != nil {
		a := c.GitHub.Public()
		pub.GitHub = &a
	}
	// Canonical sorts map keys, so the provider order is stable.
	b, err := jose.Canonical(pub)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}
