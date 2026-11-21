// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package mail sends verification codes through Microsoft Graph, as an
// Entra app registration holding the Mail.Send application permission:
// the same sender privasys.id uses.
//
// A message is not kept in the sender's Sent Items, and neither the
// address nor the code is ever logged.
package mail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Settings is the sender.
type Settings struct {
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	Sender       string `json:"sender"`
}

// Validate says whether these settings could send anything.
func (s Settings) Validate() error {
	if s.TenantID == "" || s.ClientID == "" || s.ClientSecret == "" {
		return errors.New("mail: tenant_id, client_id and client_secret are all needed")
	}
	a, err := mail.ParseAddress(s.Sender)
	if err != nil || a.Address != s.Sender || a.Name != "" {
		return errors.New("mail: sender must be an email address")
	}
	return nil
}

// Merge fills fields the call left out from what is held, so the secret
// need not be resent to change the rest.
func (s Settings) Merge(held Settings) Settings {
	for _, f := range []struct{ into, from *string }{
		{&s.TenantID, &held.TenantID}, {&s.ClientID, &held.ClientID},
		{&s.ClientSecret, &held.ClientSecret}, {&s.Sender, &held.Sender},
	} {
		if *f.into == "" {
			*f.into = *f.from
		}
	}
	return s
}

// Public is the settings without the secret, for the attested digest.
func (s Settings) Public() Settings { s.ClientSecret = ""; return s }

// Mailer sends through one app registration.
type Mailer struct {
	settings Settings
	client   *http.Client
	LoginURL string
	GraphURL string

	mu      sync.Mutex
	token   string
	expires time.Time
}

// New returns a mailer.
func New(s Settings, client *http.Client) (*Mailer, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &Mailer{settings: s, client: client,
		LoginURL: "https://login.microsoftonline.com", GraphURL: "https://graph.microsoft.com"}, nil
}

// SendCode mails a verification code.
func (m *Mailer) SendCode(ctx context.Context, to, code string, ttl time.Duration) error {
	// Only six digits and a number are interpolated: nothing to escape.
	// Inline styles and tables, because mail clients strip stylesheets.
	body := fmt.Sprintf(
		`<!DOCTYPE html><html><body style="margin:0;padding:0;background:#f6f8fa;">`+
			`<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background:#f6f8fa;"><tr><td align="center" style="padding:32px 16px;">`+
			`<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:12px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#1f2937;">`+
			`<tr><td style="padding:32px 28px 8px;font-size:16px;line-height:24px;">Your Privasys verification code is:</td></tr>`+
			`<tr><td align="center" style="padding:16px 28px;">`+
			`<div style="display:inline-block;background:#e9fbf3;border:1px solid #b9f0d8;border-radius:12px;padding:18px 20px 18px 28px;font-size:34px;line-height:40px;font-weight:700;letter-spacing:8px;color:#0e3b2b;font-family:'SF Mono',Menlo,Consolas,'Courier New',monospace;">%s</div>`+
			`</td></tr>`+
			`<tr><td style="padding:8px 28px 16px;font-size:15px;line-height:23px;">Type it into your wallet to confirm this address is yours. The code stops working in %d minutes.</td></tr>`+
			`<tr><td style="padding:0 28px 32px;font-size:13px;line-height:20px;color:#6b7280;">If you did not ask for this, nothing has happened to your account and you can ignore this message. Whoever asked cannot see it.</td></tr>`+
			`</table></td></tr></table></body></html>`,
		code, int(ttl.Minutes()))
	return m.send(ctx, to, "Privasys verification code", body)
}

func (m *Mailer) send(ctx context.Context, to, subject, body string) error {
	token, err := m.accessToken(ctx)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{
		"message": map[string]any{
			"subject":      subject,
			"body":         map[string]string{"contentType": "HTML", "content": body},
			"toRecipients": []map[string]any{{"emailAddress": map[string]string{"address": to}}},
		},
		"saveToSentItems": false,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		m.GraphURL+"/v1.0/users/"+url.PathEscape(m.settings.Sender)+"/sendMail", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return errors.New("mail: Microsoft Graph could not be reached")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted {
		return nil
	}
	return fmt.Errorf("mail: Microsoft Graph refused the message: %d %s", resp.StatusCode, graphCode(resp.Body))
}

// graphCode keeps the error's code and drops its text, which may quote the
// message it refused.
func graphCode(body io.Reader) string {
	var out struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(body, 1<<16)).Decode(&out)
	return out.Error.Code
}

func (m *Mailer) accessToken(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.token != "" && time.Now().Before(m.expires) {
		return m.token, nil
	}
	form := url.Values{
		"client_id":     {m.settings.ClientID},
		"client_secret": {m.settings.ClientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
		"grant_type":    {"client_credentials"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		m.LoginURL+"/"+url.PathEscape(m.settings.TenantID)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := m.client.Do(req)
	if err != nil {
		return "", errors.New("mail: the Microsoft sign-in could not be reached")
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", errors.New("mail: the Microsoft sign-in gave an unreadable answer")
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("mail: the Microsoft sign-in refused the app registration: %s", out.Error)
	}
	m.token, m.expires = out.AccessToken, time.Now().Add(time.Duration(out.ExpiresIn-60)*time.Second)
	return m.token, nil
}
