package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

// ---------- Lokale Anmeldung ----------

type authPage struct {
	Next     string
	Username string
	Email    string
	Error    string
}

func (a *App) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"))
	if currentUser(r) != nil {
		redirect(w, r, next)
		return
	}
	a.render(w, r, http.StatusOK, "login.html", "Anmelden", authPage{Next: next})
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.AllowLocalLogin && a.dir == nil {
		a.notFound(w, r)
		return
	}
	username := strings.TrimSpace(r.PostFormValue("benutzer"))
	password := r.PostFormValue("passwort")
	next := safeNext(r.PostFormValue("next"))
	ipKey, userKey := "login-ip:"+a.clientIP(r), "login-user:"+strings.ToLower(username)

	fail := func(status int, msg string) {
		a.render(w, r, status, "login.html", "Anmelden", authPage{Next: next, Username: username, Error: msg})
	}
	if !a.limiter.allow(ipKey) || !a.limiter.allow(userKey) {
		fail(http.StatusTooManyRequests, "Zu viele Fehlversuche. Bitte warte 15 Minuten.")
		return
	}

	id, err := a.authenticate(r.Context(), username, password)
	switch {
	case err == nil:
	case errors.Is(err, errBadCredentials):
		a.limiter.fail(ipKey)
		a.limiter.fail(userKey)
		fail(http.StatusUnauthorized, "Benutzername oder Passwort ist falsch.")
		return
	case errors.Is(err, errNotPermitted):
		a.limiter.fail(ipKey)
		fail(http.StatusForbidden, "Dein Konto ist für diese Anwendung nicht freigeschaltet. Wende dich an die IT.")
		return
	case errors.Is(err, errUserDisabled):
		fail(http.StatusForbidden, "Dein Konto ist gesperrt.")
		return
	case errors.Is(err, errDirectoryDown):
		slog.Error("LDAP", "err", err)
		fail(http.StatusServiceUnavailable, "Der Verzeichnisdienst ist gerade nicht erreichbar. Bitte versuche es gleich noch einmal.")
		return
	default:
		a.serverError(w, r, err)
		return
	}
	a.limiter.reset(userKey)
	if err := a.createSession(w, id); err != nil {
		a.serverError(w, r, err)
		return
	}
	redirect(w, r, next)
}

// authenticate prüft zuerst ein lokales Konto mit Passwort und danach – falls konfiguriert – LDAP.
// LDAP-Konten werden über ihre Verzeichnis-ID verknüpft, nie über den Benutzernamen: Ein lokal
// registriertes Konto „jdoe“ kann also nicht das Verzeichniskonto „jdoe“ übernehmen und umgekehrt.
func (a *App) authenticate(ctx context.Context, username, password string) (int64, error) {
	if a.cfg.AllowLocalLogin {
		var id int64
		var hash string
		var disabled bool
		err := a.db.QueryRow(`SELECT id, password_hash, disabled FROM users WHERE username = ? AND password_hash <> ''`, username).
			Scan(&id, &hash, &disabled)
		switch {
		case err == nil:
			if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil {
				if disabled {
					return 0, errUserDisabled
				}
				return id, nil
			}
		case errors.Is(err, sql.ErrNoRows):
			bcrypt.CompareHashAndPassword(a.dummyHash, []byte(password)) // gleiche Laufzeit, keine Benutzer-Enumeration
		default:
			return 0, err
		}
	}
	if a.dir == nil {
		return 0, errBadCredentials
	}
	ident, err := a.dir.Authenticate(ctx, username, password)
	if err != nil {
		return 0, err
	}
	return a.upsertLDAPUser(ident)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	a.destroySession(w, r)
	redirect(w, r, "/")
}

func (a *App) handleRegisterForm(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.AllowRegistration {
		a.notFound(w, r)
		return
	}
	a.render(w, r, http.StatusOK, "register.html", "Registrieren", authPage{Next: safeNext(r.URL.Query().Get("next"))})
}

func (a *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.AllowRegistration {
		a.notFound(w, r)
		return
	}
	p := authPage{
		Next:     safeNext(r.PostFormValue("next")),
		Username: strings.TrimSpace(r.PostFormValue("benutzer")),
		Email:    cleanLine(r.PostFormValue("email"), 200),
	}
	pw, pw2 := r.PostFormValue("passwort"), r.PostFormValue("passwort2")
	key := "register:" + a.clientIP(r)
	switch {
	case !a.limiter.allow(key):
		p.Error = "Zu viele Registrierungen von deiner Adresse. Bitte später erneut versuchen."
	case !validUsername(p.Username):
		p.Error = "Der Benutzername muss 3–32 Zeichen lang sein und darf nur Buchstaben, Ziffern sowie . _ - enthalten."
	case p.Email != "" && !strings.Contains(p.Email, "@"):
		p.Error = "Die E-Mail-Adresse ist ungültig."
	case len([]rune(pw)) < minPasswordLen:
		p.Error = fmt.Sprintf("Das Passwort muss mindestens %d Zeichen haben.", minPasswordLen)
	case len(pw) > 72:
		p.Error = "Das Passwort ist zu lang (max. 72 Bytes)."
	case pw != pw2:
		p.Error = "Die Passwörter stimmen nicht überein."
	}
	if p.Error != "" {
		a.render(w, r, http.StatusUnprocessableEntity, "register.html", "Registrieren", p)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	res, err := a.db.Exec(`INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)`,
		p.Username, p.Email, string(hash), now())
	if isUniqueErr(err) {
		p.Error = "Dieser Benutzername ist bereits vergeben."
		a.render(w, r, http.StatusConflict, "register.html", "Registrieren", p)
		return
	} else if err != nil {
		a.serverError(w, r, err)
		return
	}
	a.limiter.fail(key) // zählt Registrierungen pro IP
	id, _ := res.LastInsertId()
	if err := a.createSession(w, id); err != nil {
		a.serverError(w, r, err)
		return
	}
	a.flash(w, "ok", "Willkommen! Dein Konto wurde angelegt.")
	redirect(w, r, p.Next)
}

// ---------- Konto ----------

type accountPage struct {
	NotifyNew, NotifyFollow, NotifyAssign bool
	IsDev                                 bool
	MailEnabled                           bool
}

func (a *App) handleAccount(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	p := accountPage{IsDev: u.IsAdmin || a.isAnyDeveloper(u.ID), MailEnabled: a.mailer != nil}
	p.NotifyNew, p.NotifyFollow, p.NotifyAssign = a.notifyPrefs(u.ID)
	a.render(w, r, http.StatusOK, "account.html", "Mein Konto", p)
}

func (a *App) handleAccountUpdate(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	switch r.PostFormValue("aktion") {
	case "benachrichtigungen":
		b := func(k string) bool { return r.PostFormValue(k) == "1" }
		if _, err := a.db.Exec(`UPDATE users SET notify_new = ?, notify_follow = ?, notify_assign = ? WHERE id = ?`,
			b("neu"), b("folgen"), b("zugewiesen"), u.ID); err != nil {
			a.serverError(w, r, err)
			return
		}
		a.flash(w, "ok", "Benachrichtigungen gespeichert.")
	case "profil":
		name := cleanLine(r.PostFormValue("anzeigename"), 60)
		email := cleanLine(r.PostFormValue("email"), 200)
		if email != "" && !strings.Contains(email, "@") {
			a.flash(w, "error", "Die E-Mail-Adresse ist ungültig.")
			break
		}
		if u.IsOIDC || u.IsLDAP {
			email = u.Email // wird vom Identity Provider bzw. Verzeichnisdienst verwaltet
		}
		if _, err := a.db.Exec(`UPDATE users SET display_name = ?, email = ? WHERE id = ?`, name, email, u.ID); err != nil {
			a.serverError(w, r, err)
			return
		}
		a.flash(w, "ok", "Profil gespeichert.")
	case "passwort":
		if !u.HasPassword {
			a.flash(w, "error", "Dein Konto hat kein lokales Passwort. Ändere es dort, wo es verwaltet wird (Single Sign-On oder Verzeichnisdienst).")
			break
		}
		var hash string
		if err := a.db.QueryRow(`SELECT password_hash FROM users WHERE id = ?`, u.ID).Scan(&hash); err != nil {
			a.serverError(w, r, err)
			return
		}
		old, pw, pw2 := r.PostFormValue("alt"), r.PostFormValue("neu"), r.PostFormValue("neu2")
		switch {
		case bcrypt.CompareHashAndPassword([]byte(hash), []byte(old)) != nil:
			a.flash(w, "error", "Das aktuelle Passwort ist falsch.")
		case len([]rune(pw)) < minPasswordLen || len(pw) > 72:
			a.flash(w, "error", fmt.Sprintf("Das neue Passwort muss %d bis 72 Zeichen haben.", minPasswordLen))
		case pw != pw2:
			a.flash(w, "error", "Die neuen Passwörter stimmen nicht überein.")
		default:
			nh, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
			if err != nil {
				a.serverError(w, r, err)
				return
			}
			// Passwort setzen und alle anderen Sitzungen beenden
			c, _ := r.Cookie(sessionCookie)
			cur := ""
			if c != nil {
				cur = hashToken(c.Value)
			}
			err = a.tx(func(tx *sql.Tx) error {
				if _, err := tx.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, string(nh), u.ID); err != nil {
					return err
				}
				_, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?`, u.ID, cur)
				return err
			})
			if err != nil {
				a.serverError(w, r, err)
				return
			}
			a.flash(w, "ok", "Passwort geändert. Andere Sitzungen wurden abgemeldet.")
		}
	}
	redirect(w, r, "/konto")
}

// ---------- OpenID Connect ----------

type oidcProvider struct {
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
}

const oidcCookie = "ms_oidc"

func (a *App) getOIDC(ctx context.Context) (*oidcProvider, error) {
	a.oidcMu.Lock()
	defer a.oidcMu.Unlock()
	if a.oidc != nil {
		return a.oidc, nil
	}
	c := a.cfg.OIDC
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(dctx, c.Issuer)
	if err != nil {
		return nil, err
	}
	scopes := c.Scopes
	hasOpenID := false
	for _, s := range scopes {
		hasOpenID = hasOpenID || s == oidc.ScopeOpenID
	}
	if !hasOpenID {
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}
	a.oidc = &oidcProvider{
		verifier: p.Verifier(&oidc.Config{ClientID: c.ClientID}),
		oauth: &oauth2.Config{
			ClientID: c.ClientID, ClientSecret: c.ClientSecret, RedirectURL: c.RedirectURL,
			Endpoint: p.Endpoint(), Scopes: scopes,
		},
	}
	return a.oidc, nil
}

func (a *App) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.OIDC.Enabled() {
		a.notFound(w, r)
		return
	}
	p, err := a.getOIDC(r.Context())
	if err != nil {
		slog.Error("OIDC-Discovery", "err", err)
		a.errorPage(w, r, http.StatusBadGateway, "Der Identity Provider ist gerade nicht erreichbar.")
		return
	}
	state, nonce, verifier := randToken(24), randToken(24), oauth2.GenerateVerifier()
	next := safeNext(r.URL.Query().Get("next"))
	val := base64.RawURLEncoding.EncodeToString([]byte(strings.Join([]string{state, nonce, verifier, next}, "\n")))
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: val, Path: "/auth/oidc/", MaxAge: 600,
		HttpOnly: true, Secure: a.cfg.CookieSecure, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, p.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

var errUserDisabled = errors.New("Benutzer gesperrt")

func (a *App) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.OIDC.Enabled() {
		a.notFound(w, r)
		return
	}
	c, err := r.Cookie(oidcCookie)
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: "", Path: "/auth/oidc/", MaxAge: -1})
	if err != nil {
		a.errorPage(w, r, http.StatusBadRequest, "Die Anmeldesitzung ist abgelaufen. Bitte erneut versuchen.")
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	parts := strings.SplitN(string(raw), "\n", 4)
	if err != nil || len(parts) != 4 {
		a.errorPage(w, r, http.StatusBadRequest, "Ungültige Anmeldesitzung.")
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		a.errorPage(w, r, http.StatusUnauthorized, "Anmeldung beim Identity Provider fehlgeschlagen: "+cleanLine(e+" "+q.Get("error_description"), 200))
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(parts[0])) != 1 {
		a.errorPage(w, r, http.StatusBadRequest, "Ungültiger State-Parameter.")
		return
	}
	p, err := a.getOIDC(r.Context())
	if err != nil {
		a.errorPage(w, r, http.StatusBadGateway, "Der Identity Provider ist gerade nicht erreichbar.")
		return
	}
	tok, err := p.oauth.Exchange(r.Context(), q.Get("code"), oauth2.VerifierOption(parts[2]))
	if err != nil {
		slog.Warn("OIDC-Code-Tausch", "err", err)
		a.errorPage(w, r, http.StatusUnauthorized, "Die Anmeldung konnte nicht abgeschlossen werden.")
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	idt, err := p.verifier.Verify(r.Context(), rawID)
	if err != nil || subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(parts[1])) != 1 {
		slog.Warn("OIDC-ID-Token ungültig", "err", err)
		a.errorPage(w, r, http.StatusUnauthorized, "Das ID-Token ist ungültig.")
		return
	}
	var claims struct {
		Email     string `json:"email"`
		Name      string `json:"name"`
		Preferred string `json:"preferred_username"`
	}
	var all map[string]any
	if err := idt.Claims(&claims); err != nil || idt.Claims(&all) != nil {
		a.errorPage(w, r, http.StatusUnauthorized, "Die Claims des ID-Tokens sind ungültig.")
		return
	}
	var isAdmin *bool
	if g := a.cfg.OIDC.AdminGroup; g != "" {
		b := hasGroup(all[a.cfg.OIDC.GroupsClaim], g)
		isAdmin = &b
	}
	id, err := a.upsertOIDCUser(idt.Issuer, idt.Subject, claims.Preferred, claims.Email, claims.Name, isAdmin)
	if errors.Is(err, errUserDisabled) {
		a.errorPage(w, r, http.StatusForbidden, "Dein Konto ist gesperrt.")
		return
	} else if err != nil {
		a.serverError(w, r, err)
		return
	}
	if err := a.createSession(w, id); err != nil {
		a.serverError(w, r, err)
		return
	}
	redirect(w, r, parts[3])
}

func hasGroup(v any, group string) bool {
	switch g := v.(type) {
	case string:
		return g == group
	case []any:
		for _, x := range g {
			if s, ok := x.(string); ok && s == group {
				return true
			}
		}
	}
	return false
}

func (a *App) upsertOIDCUser(issuer, sub, preferred, email, name string, isAdmin *bool) (int64, error) {
	var id int64
	var disabled bool
	err := a.db.QueryRow(`SELECT id, disabled FROM users WHERE oidc_issuer = ? AND oidc_subject = ?`, issuer, sub).Scan(&id, &disabled)
	if err == nil {
		if disabled {
			return 0, errUserDisabled
		}
		if _, err := a.db.Exec(`UPDATE users SET email = ? WHERE id = ?`, cleanLine(email, 200), id); err != nil {
			return 0, err
		}
		if isAdmin != nil {
			if _, err := a.db.Exec(`UPDATE users SET is_admin = ? WHERE id = ?`, *isAdmin, id); err != nil {
				return 0, err
			}
		}
		return id, nil
	}
	if !notFoundErr(err) {
		return 0, err
	}
	want := preferred
	if want == "" {
		want, _, _ = strings.Cut(email, "@")
	}
	if want == "" {
		want = "benutzer"
	}
	for attempt := 0; attempt < 3; attempt++ {
		username, err := a.uniqueUsername(want)
		if err != nil {
			return 0, err
		}
		admin := isAdmin != nil && *isAdmin
		res, err := a.db.Exec(`INSERT INTO users (username, email, display_name, oidc_issuer, oidc_subject, is_admin, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, username, cleanLine(email, 200), cleanLine(name, 60), issuer, sub, admin, now())
		if isUniqueErr(err) {
			continue
		}
		if err != nil {
			return 0, err
		}
		return res.LastInsertId()
	}
	return 0, errors.New("Benutzer konnte nicht angelegt werden")
}
