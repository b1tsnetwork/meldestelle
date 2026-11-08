// Meldestelle – öffentliche Melde-Anwendung für Bugs und Feature-Wünsche
// mit vertraulichen Sicherheitsmeldungen, Upvotes, Anhängen und Entwicklern pro Software.
package main

import (
	"bufio"
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

//go:embed templates/*.html static/*
var assets embed.FS

// version wird beim Build per -ldflags "-X main.version=…" gesetzt.
var version = "dev"

type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	ButtonLabel  string
	AdminGroup   string
	GroupsClaim  string
	Scopes       []string
}

func (o OIDCConfig) Enabled() bool { return o.Issuer != "" && o.ClientID != "" }

type Config struct {
	Listen            string
	DataDir           string
	BaseURL           string
	AppName           string
	CookieSecure      bool
	TrustProxy        bool
	AllowRegistration bool
	AllowLocalLogin   bool
	MaxUploadBytes    int64
	MaxFiles          int
	OIDC              OIDCConfig
	LDAP              LDAPConfig
	SMTP              SMTPConfig
	ClamAV            ClamAVConfig
	Backup            BackupConfig
	Limits            LimitConfig
}

func getenv(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func getbool(k string, def bool) bool {
	switch strings.ToLower(getenv(k, "")) {
	case "1", "true", "yes", "ja", "on":
		return true
	case "0", "false", "no", "nein", "off":
		return false
	}
	return def
}

// getintZero erlaubt auch 0 (z. B. „Begrenzung aus“).
func getintZero(k string, def int) int {
	if n, err := strconv.Atoi(getenv(k, "")); err == nil && n >= 0 {
		return n
	}
	return def
}

func getint(k string, def int) int {
	if n, err := strconv.Atoi(getenv(k, "")); err == nil && n > 0 {
		return n
	}
	return def
}

// secret liest einen Wert aus KEY oder – für Docker-Secrets – aus der Datei in KEY_FILE.
func secret(k string) string {
	if v := getenv(k, ""); v != "" {
		return v
	}
	if p := getenv(k+"_FILE", ""); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

func loadConfig() Config {
	base := strings.TrimRight(getenv("MS_BASE_URL", "http://localhost:8080"), "/")
	c := Config{
		Listen:            getenv("MS_LISTEN", ":8080"),
		DataDir:           getenv("MS_DATA_DIR", "./data"),
		BaseURL:           base,
		AppName:           getenv("MS_APP_NAME", "Meldestelle"),
		CookieSecure:      getbool("MS_COOKIE_SECURE", strings.HasPrefix(base, "https://")),
		TrustProxy:        getbool("MS_TRUST_PROXY", false),
		AllowRegistration: getbool("MS_ALLOW_REGISTRATION", true),
		AllowLocalLogin:   getbool("MS_LOCAL_LOGIN", true),
		MaxUploadBytes:    int64(getint("MS_MAX_UPLOAD_MB", 20)) << 20,
		MaxFiles:          getint("MS_MAX_FILES", 5),
		OIDC: OIDCConfig{
			Issuer:       getenv("MS_OIDC_ISSUER", ""),
			ClientID:     getenv("MS_OIDC_CLIENT_ID", ""),
			ClientSecret: secret("MS_OIDC_CLIENT_SECRET"),
			RedirectURL:  getenv("MS_OIDC_REDIRECT_URL", base+"/auth/oidc/callback"),
			ButtonLabel:  getenv("MS_OIDC_LABEL", "Mit SSO anmelden"),
			AdminGroup:   getenv("MS_OIDC_ADMIN_GROUP", ""),
			GroupsClaim:  getenv("MS_OIDC_GROUPS_CLAIM", "groups"),
			Scopes:       strings.Fields(getenv("MS_OIDC_SCOPES", "openid profile email")),
		},
	}
	c.LDAP = loadLDAPConfig()
	c.SMTP = loadSMTPConfig()
	c.ClamAV = loadClamAVConfig()
	c.Backup = loadBackupConfig()
	c.Limits = LimitConfig{ReportsPerHour: getintZero("MS_LIMIT_REPORTS_PER_HOUR", 10), RepliesPerHour: getintZero("MS_LIMIT_REPLIES_PER_HOUR", 60)}
	if !c.AllowLocalLogin {
		c.AllowRegistration = false
	}
	return c
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	cfg := loadConfig()
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(cfg)
	case "create-admin":
		err = createAdminCmd(cfg, os.Args[2:])
	case "healthcheck":
		err = healthcheck(cfg)
	case "backup":
		err = backupCmd(cfg, os.Args[2:])
	case "restore":
		err = restoreCmd(cfg, os.Args[2:])
	case "ldap-test":
		fs := flag.NewFlagSet("ldap-test", flag.ExitOnError)
		user := fs.String("user", "", "Benutzername")
		_ = fs.Parse(os.Args[2:])
		if *user == "" {
			err = errors.New("-user fehlt")
			break
		}
		err = ldapTestCmd(cfg, *user)
	case "version", "-v", "--version":
		fmt.Println("meldestelle", version)
		return
	case "help", "-h", "--help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "Unbekannter Befehl %q\n\n", cmd)
		printUsage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Fehler:", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Meldestelle – Bugs, Features und vertrauliche Sicherheitsmeldungen

Befehle:
  serve          Webserver starten (Standard)
  create-admin   Lokalen Administrator anlegen oder Passwort zurücksetzen
                 -user NAME [-email MAIL] [-name ANZEIGENAME]
                 Passwort über MS_ADMIN_PASSWORD oder interaktive Eingabe
  healthcheck    Prüft /healthz des laufenden Servers (für Docker)
  backup         Sicherung von Datenbank und Anhängen: [-out datei.tar.gz] (auch im laufenden Betrieb)
  restore        Sicherung einspielen: -in datei.tar.gz [-force] (Server vorher stoppen)
  ldap-test      LDAP-Anbindung prüfen: -user NAME (Passwort über MS_LDAP_TEST_PASSWORD oder Eingabe)
  version        Version anzeigen

Konfiguration erfolgt über Umgebungsvariablen (siehe README.md).`)
}

func serve(cfg Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app, err := newApp(ctx, cfg)
	if err != nil {
		return err
	}
	defer app.db.Close()

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           app.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Minute,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	go app.janitor(ctx)
	if app.mailer != nil {
		go app.mailWorker(ctx)
	}
	if cfg.Backup.Dir != "" {
		go app.backupLoop(ctx)
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("Meldestelle gestartet", "version", version, "listen", cfg.Listen, "url", cfg.BaseURL,
			"oidc", cfg.OIDC.Enabled(), "ldap", cfg.LDAP.Enabled(), "mail", cfg.SMTP.Enabled(), "clamav", cfg.ClamAV.Addr != "", "backup", cfg.Backup.Dir != "", "lokal", cfg.AllowLocalLogin, "registrierung", cfg.AllowRegistration)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	slog.Info("Fahre herunter …")
	shCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shCtx)
}

func healthcheck(cfg Config) error {
	addr := cfg.Listen
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	c := http.Client{Timeout: 3 * time.Second}
	res, err := c.Get("http://" + addr + "/healthz")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Status %d", res.StatusCode)
	}
	return nil
}

func createAdminCmd(cfg Config, args []string) error {
	fs := flag.NewFlagSet("create-admin", flag.ExitOnError)
	user := fs.String("user", "", "Benutzername")
	email := fs.String("email", "", "E-Mail-Adresse")
	name := fs.String("name", "", "Anzeigename")
	_ = fs.Parse(args)
	if !validUsername(*user) {
		return errors.New("-user fehlt oder ist ungültig (3–32 Zeichen: Buchstaben, Ziffern, . _ -)")
	}

	pw := os.Getenv("MS_ADMIN_PASSWORD")
	if pw == "" {
		var err error
		pw, err = readPassword("Passwort für " + *user + ": ")
		if err != nil {
			return err
		}
	}
	if len([]rune(pw)) < minPasswordLen {
		return fmt.Errorf("Passwort muss mindestens %d Zeichen haben", minPasswordLen)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return err
	}
	db, err := openDB(dbPath(cfg))
	if err != nil {
		return err
	}
	defer db.Close()

	res, err := db.Exec(`UPDATE users SET password_hash = ?, is_admin = 1, disabled = 0 WHERE username = ?`, string(hash), *user)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		fmt.Printf("Benutzer %q existierte bereits: Passwort gesetzt und Administratorrechte vergeben.\n", *user)
		return nil
	}
	_, err = db.Exec(`INSERT INTO users (username, email, display_name, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?, 1, ?)`,
		*user, *email, *name, string(hash), now())
	if err != nil {
		return err
	}
	fmt.Printf("Administrator %q angelegt.\n", *user)
	return nil
}

func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
