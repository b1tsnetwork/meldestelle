package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type App struct {
	cfg       Config
	db        *sql.DB
	pages     map[string]*template.Template
	static    fs.FS
	attachDir string
	limiter   *limiter
	dummyHash []byte

	dir      directory // LDAP, nil wenn nicht konfiguriert
	mailer   mailer    // nil, wenn kein SMTP konfiguriert ist
	mailKick chan struct{}
	scanner  virusScanner // nil ohne ClamAV

	oidcMu sync.Mutex
	oidc   *oidcProvider
}

func newApp(ctx context.Context, cfg Config) (*App, error) {
	attachDir := filepath.Join(cfg.DataDir, "anhaenge")
	if err := os.MkdirAll(attachDir, 0o750); err != nil {
		return nil, err
	}
	db, err := openDB(dbPath(cfg))
	if err != nil {
		return nil, err
	}
	st, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	dummy, _ := bcrypt.GenerateFromPassword([]byte("platzhalter-fuer-konstante-laufzeit"), bcrypt.DefaultCost)
	a := &App{
		cfg:       cfg,
		db:        db,
		static:    st,
		attachDir: attachDir,
		limiter:   newLimiter(10, 15*time.Minute),
		dummyHash: dummy,
	}
	if err := a.loadTemplates(); err != nil {
		return nil, err
	}
	a.mailKick = make(chan struct{}, 1)
	if cfg.SMTP.Enabled() {
		m, err := newSMTPMailer(cfg.SMTP, cfg.BaseURL)
		if err != nil {
			return nil, err
		}
		a.mailer = m
	}
	if cfg.ClamAV.Addr != "" {
		a.scanner = &clamd{cfg: cfg.ClamAV}
	}
	if cfg.LDAP.Enabled() {
		d, err := newLDAPDirectory(cfg.LDAP)
		if err != nil {
			return nil, err
		}
		a.dir = d
	}
	if cfg.OIDC.Enabled() {
		if _, err := a.getOIDC(ctx); err != nil {
			slog.Warn("OIDC-Provider derzeit nicht erreichbar – neuer Versuch bei der nächsten Anmeldung", "err", err)
		}
	}
	return a, nil
}

func (a *App) janitor(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if _, err := a.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, now()); err != nil {
			slog.Warn("Sitzungen aufräumen", "err", err)
		}
		a.limiter.cleanup()
		a.db.Exec(`DELETE FROM outbox WHERE sent_at <> 0 AND created_at < ?`, now()-30*24*3600)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ---------- Routen ----------

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", a.staticHandler()))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := a.db.PingContext(r.Context()); err != nil {
			http.Error(w, "db", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("GET /{$}", a.handleList)
	mux.HandleFunc("GET /s/{slug}", a.handleList)
	mux.HandleFunc("GET /neu", a.requireLogin(a.handleNewForm))
	mux.HandleFunc("POST /neu", a.requireLogin(a.handleCreate))
	mux.HandleFunc("GET /r/{id}", a.handleReport)
	mux.HandleFunc("POST /r/{id}/vote", a.requireLogin(a.handleVote))
	mux.HandleFunc("POST /r/{id}/kommentar", a.requireLogin(a.handleComment))
	mux.HandleFunc("POST /r/{id}/verwalten", a.requireLogin(a.handleManage))
	mux.HandleFunc("POST /r/{id}/loeschen", a.requireLogin(a.handleDelete))
	mux.HandleFunc("GET /anhang/{id}/{name}", a.handleAttachment)
	mux.HandleFunc("POST /anhang/{id}/entfernen", a.requireLogin(a.handleRemoveAttachment))
	mux.HandleFunc("GET /r/{id}/bearbeiten", a.requireLogin(a.handleEditReportForm))
	mux.HandleFunc("POST /r/{id}/bearbeiten", a.requireLogin(a.handleEditReport))
	mux.HandleFunc("POST /r/{id}/folgen", a.requireLogin(a.handleFollow))
	mux.HandleFunc("GET /k/{id}/bearbeiten", a.requireLogin(a.handleEditCommentForm))
	mux.HandleFunc("POST /k/{id}/bearbeiten", a.requireLogin(a.handleEditComment))
	mux.HandleFunc("POST /k/{id}/loeschen", a.requireLogin(a.handleDeleteComment))
	mux.HandleFunc("GET /s/{slug}/einstellungen", a.requireLogin(a.handleSoftwareSettings))
	mux.HandleFunc("POST /s/{slug}/labels", a.requireLogin(a.handleLabelCreate))
	mux.HandleFunc("POST /s/{slug}/labels/{id}", a.requireLogin(a.handleLabelUpdate))
	mux.HandleFunc("POST /s/{slug}/labels/{id}/loeschen", a.requireLogin(a.handleLabelDelete))
	mux.HandleFunc("POST /admin/testmail", a.requireAdmin(a.handleTestMail))
	mux.HandleFunc("GET /api/aehnlich", a.requireLogin(a.handleSimilar))
	mux.HandleFunc("POST /api/vorschau", a.requireLogin(a.handlePreview))

	mux.HandleFunc("GET /login", a.handleLoginForm)
	mux.HandleFunc("POST /login", a.handleLogin)
	mux.HandleFunc("POST /logout", a.handleLogout)
	mux.HandleFunc("GET /registrieren", a.handleRegisterForm)
	mux.HandleFunc("POST /registrieren", a.handleRegister)
	mux.HandleFunc("GET /konto", a.requireLogin(a.handleAccount))
	mux.HandleFunc("POST /konto", a.requireLogin(a.handleAccountUpdate))
	mux.HandleFunc("GET /auth/oidc/login", a.handleOIDCLogin)
	mux.HandleFunc("GET /auth/oidc/callback", a.handleOIDCCallback)

	mux.HandleFunc("GET /admin", a.requireAdmin(a.handleAdmin))
	mux.HandleFunc("POST /admin/software", a.requireAdmin(a.handleSoftwareCreate))
	mux.HandleFunc("POST /admin/software/{id}", a.requireAdmin(a.handleSoftwareUpdate))
	mux.HandleFunc("POST /admin/software/{id}/entwickler", a.requireAdmin(a.handleDevAdd))
	mux.HandleFunc("POST /admin/software/{id}/entwickler/{uid}/entfernen", a.requireAdmin(a.handleDevRemove))
	mux.HandleFunc("POST /admin/benutzer/{id}", a.requireAdmin(a.handleUserUpdate))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { a.notFound(w, r) })

	return a.securityHeaders(a.recoverer(a.withSession(a.csrfProtect(mux))))
}

func (a *App) staticHandler() http.Handler {
	fsrv := http.FileServerFS(a.static)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		fsrv.ServeHTTP(w, r)
	})
}

// ---------- Kontext ----------

type ctxKey int

const (
	ctxUser ctxKey = iota
	ctxCSRF
)

func currentUser(r *http.Request) *User {
	u, _ := r.Context().Value(ctxUser).(*User)
	return u
}

func csrfToken(r *http.Request) string {
	t, _ := r.Context().Value(ctxCSRF).(string)
	return t
}

// ---------- Middleware ----------

const (
	sessionCookie = "ms_session"
	csrfCookie    = "ms_csrf"
	flashCookie   = "ms_flash"
	sessionTTL    = 30 * 24 * time.Hour
)

const defaultCSP = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; " +
	"object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

func (a *App) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy", defaultCSP)
		if a.cfg.CookieSecure {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				slog.Error("Panic", "err", v, "path", r.URL.Path)
				http.Error(w, "Interner Fehler", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (a *App) withSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		ctx := r.Context()
		if u := a.userFromSession(r); u != nil {
			ctx = context.WithValue(ctx, ctxUser, u)
		}
		tok := ""
		if c, err := r.Cookie(csrfCookie); err == nil && len(c.Value) >= 40 {
			tok = c.Value
		} else {
			tok = randToken(32)
			a.setCSRFCookie(w, tok)
		}
		ctx = context.WithValue(ctx, ctxCSRF, tok)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// csrfProtect begrenzt die Anfragegröße, parst Formulare und prüft das Double-Submit-Token
// sowie den Origin-Header für alle schreibenden Anfragen.
func (a *App) csrfProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		limit := a.cfg.MaxUploadBytes*int64(a.cfg.MaxFiles) + 2<<20
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		var err error
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			err = r.ParseMultipartForm(16 << 20)
			if r.MultipartForm != nil {
				defer r.MultipartForm.RemoveAll()
			}
		} else {
			err = r.ParseForm()
		}
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				a.errorPage(w, r, http.StatusRequestEntityTooLarge, "Die Anfrage ist zu groß. Bitte kleinere oder weniger Anhänge verwenden.")
				return
			}
			a.errorPage(w, r, http.StatusBadRequest, "Ungültige Anfrage.")
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !a.originOK(o, r) {
			a.errorPage(w, r, http.StatusForbidden, "Anfrage von fremder Herkunft abgelehnt.")
			return
		}
		sent := r.Header.Get("X-CSRF-Token")
		if sent == "" {
			sent = r.PostFormValue("csrf")
		}
		want := csrfToken(r)
		if want == "" || subtle.ConstantTimeCompare([]byte(sent), []byte(want)) != 1 {
			a.errorPage(w, r, http.StatusForbidden, "Das Sicherheitstoken ist abgelaufen oder ungültig. Bitte lade die Seite neu und versuche es erneut.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) originOK(origin string, r *http.Request) bool {
	o, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if b, err := url.Parse(a.cfg.BaseURL); err == nil && strings.EqualFold(o.Host, b.Host) {
		return true
	}
	return strings.EqualFold(o.Host, r.Host)
}

func (a *App) requireLogin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if currentUser(r) != nil {
			h(w, r)
			return
		}
		if wantsJSON(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Anmeldung erforderlich"})
			return
		}
		next := "/"
		if r.Method == http.MethodGet {
			next = r.URL.RequestURI()
		}
		http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusSeeOther)
	}
}

func (a *App) requireAdmin(h http.HandlerFunc) http.HandlerFunc {
	return a.requireLogin(func(w http.ResponseWriter, r *http.Request) {
		if !currentUser(r).IsAdmin {
			a.errorPage(w, r, http.StatusForbidden, "Dieser Bereich ist Administratoren vorbehalten.")
			return
		}
		h(w, r)
	})
}

// ---------- Sitzungen ----------

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) string {
	s := sha256.Sum256([]byte(t))
	return hex.EncodeToString(s[:])
}

func (a *App) setCSRFCookie(w http.ResponseWriter, tok string) {
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: tok, Path: "/", HttpOnly: true,
		Secure: a.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: int(sessionTTL.Seconds())})
}

func (a *App) createSession(w http.ResponseWriter, userID int64) error {
	tok := randToken(32)
	exp := time.Now().Add(sessionTTL)
	if _, err := a.db.Exec(`INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)`,
		hashToken(tok), userID, exp.Unix(), now()); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", Expires: exp, HttpOnly: true,
		Secure: a.cfg.CookieSecure, SameSite: http.SameSiteLaxMode})
	a.setCSRFCookie(w, randToken(32)) // Token nach Anmeldung rotieren
	return nil
}

func (a *App) userFromSession(r *http.Request) *User {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	u, err := scanUser(a.db.QueryRow(`SELECT `+userCols+` FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > ? AND u.disabled = 0`, hashToken(c.Value), now()))
	if err != nil {
		return nil
	}
	return u
}

func (a *App) destroySession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, hashToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: a.cfg.CookieSecure, SameSite: http.SameSiteLaxMode})
}

func (a *App) clientIP(r *http.Request) string {
	if a.cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
		if xr := r.Header.Get("X-Real-IP"); xr != "" {
			return strings.TrimSpace(xr)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------- Brute-Force-Schutz ----------

type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string]*hitCount
}

type hitCount struct {
	n     int
	until time.Time
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{max: max, window: window, hits: map[string]*hitCount{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	h := l.hits[key]
	return h == nil || time.Now().After(h.until) || h.n < l.max
}

func (l *limiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	h := l.hits[key]
	if h == nil || time.Now().After(h.until) {
		h = &hitCount{until: time.Now().Add(l.window)}
		l.hits[key] = h
	}
	h.n++
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	delete(l.hits, key)
	l.mu.Unlock()
}

func (l *limiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, h := range l.hits {
		if time.Now().After(h.until) {
			delete(l.hits, k)
		}
	}
}

// ---------- Darstellung ----------

type Flash struct{ Kind, Msg string }

type Page struct {
	Title        string
	AppName      string
	User         *User
	IsDeveloper  bool
	CSRF         string
	Flash        *Flash
	OIDC         bool
	OIDCLabel    string
	LocalLogin   bool
	LDAP         bool
	LDAPHint     string
	Registration bool
	Version      string
	Data         any
}

var berlin = func() *time.Location {
	if l, err := time.LoadLocation(getenv("TZ", "Europe/Berlin")); err == nil {
		return l
	}
	return time.Local
}()

var funcs = template.FuncMap{
	"kindLabel":   func(k string) string { return label(kinds, k) },
	"statusLabel": func(s string) string { return label(statuses, s) },
	"date":        func(t int64) string { return time.Unix(t, 0).In(berlin).Format("02.01.2006, 15:04") },
	"iso":         func(t int64) string { return time.Unix(t, 0).UTC().Format(time.RFC3339) },
	"ago":         ago,
	"bytes":       humanBytes,
	"pathesc":     url.PathEscape,
	"join":        strings.Join,
	"isImage":     isInlineImage,
	"sub":         func(a, b int) int { return a - b },
	"md":          renderMarkdown,
	"isInfected":  func(scan string) bool { return strings.HasPrefix(scan, "FOUND:") },
	"signature":   func(scan string) string { return strings.TrimPrefix(scan, "FOUND:") },
	"dict": func(kv ...any) map[string]any {
		m := map[string]any{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	},
	"excerpt": func(s string, n int) string {
		s = plainText(s)
		if r := []rune(s); len(r) > n {
			return string(r[:n]) + " …"
		}
		return s
	},
	"plural": func(n int, one, many string) string {
		if n == 1 {
			return one
		}
		return many
	},
}

func ago(t int64) string {
	d := time.Since(time.Unix(t, 0))
	switch {
	case d < time.Minute:
		return "gerade eben"
	case d < time.Hour:
		return fmt.Sprintf("vor %d Min.", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("vor %d Std.", int(d.Hours()))
	case d < 30*24*time.Hour:
		n := int(d.Hours() / 24)
		if n == 1 {
			return "vor 1 Tag"
		}
		return fmt.Sprintf("vor %d Tagen", n)
	}
	return time.Unix(t, 0).In(berlin).Format("02.01.2006")
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func (a *App) loadTemplates() error {
	pages, err := fs.Glob(assets, "templates/*.html")
	if err != nil {
		return err
	}
	a.pages = map[string]*template.Template{}
	for _, p := range pages {
		name := filepath.Base(p)
		if name == "layout.html" {
			continue
		}
		t, err := template.New(name).Funcs(funcs).ParseFS(assets, "templates/layout.html", p)
		if err != nil {
			return fmt.Errorf("Template %s: %w", name, err)
		}
		a.pages[name] = t
	}
	return nil
}

func (a *App) render(w http.ResponseWriter, r *http.Request, status int, name, title string, data any) {
	t, ok := a.pages[name]
	if !ok {
		http.Error(w, "Template fehlt: "+name, http.StatusInternalServerError)
		return
	}
	u := currentUser(r)
	p := Page{
		Title:        title,
		AppName:      a.cfg.AppName,
		User:         u,
		CSRF:         csrfToken(r),
		Flash:        a.popFlash(w, r),
		OIDC:         a.cfg.OIDC.Enabled(),
		OIDCLabel:    a.cfg.OIDC.ButtonLabel,
		LocalLogin:   a.cfg.AllowLocalLogin,
		LDAP:         a.dir != nil,
		LDAPHint:     a.cfg.LDAP.Hint,
		Registration: a.cfg.AllowRegistration,
		Version:      version,
		Data:         data,
	}
	if u != nil {
		p.IsDeveloper = u.IsAdmin || a.isAnyDeveloper(u.ID)
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", p); err != nil {
		slog.Error("Template", "name", name, "err", err)
		http.Error(w, "Interner Fehler", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	buf.WriteTo(w)
}

func (a *App) errorPage(w http.ResponseWriter, r *http.Request, status int, msg string) {
	if wantsJSON(r) {
		writeJSON(w, status, map[string]string{"error": msg})
		return
	}
	a.render(w, r, status, "error.html", "Fehler", map[string]any{"Status": status, "Message": msg})
}

func (a *App) notFound(w http.ResponseWriter, r *http.Request) {
	a.errorPage(w, r, http.StatusNotFound, "Diese Seite gibt es nicht – oder sie ist für dich nicht sichtbar.")
}

func (a *App) serverError(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("Serverfehler", "path", r.URL.Path, "err", err)
	a.errorPage(w, r, http.StatusInternalServerError, "Es ist ein interner Fehler aufgetreten.")
}

func (a *App) flash(w http.ResponseWriter, kind, msg string) {
	v := base64.RawURLEncoding.EncodeToString([]byte(kind + "\x00" + msg))
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: v, Path: "/", HttpOnly: true,
		Secure: a.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: 60})
}

func (a *App) popFlash(w http.ResponseWriter, r *http.Request) *Flash {
	c, err := r.Cookie(flashCookie)
	if err != nil {
		return nil
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: "", Path: "/", MaxAge: -1})
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	kind, msg, ok := strings.Cut(string(b), "\x00")
	if !ok || (kind != "ok" && kind != "info" && kind != "error") {
		return nil
	}
	return &Flash{Kind: kind, Msg: msg}
}

func redirect(w http.ResponseWriter, r *http.Request, to string) {
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// safeNext lässt nur lokale Pfade als Weiterleitungsziel zu (kein Open Redirect).
func safeNext(s string) string {
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, `/\`) || strings.ContainsAny(s, "\r\n") {
		return "/"
	}
	return s
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func parseID(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 1 {
		return 0
	}
	return n
}
