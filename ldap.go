package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/go-ldap/ldap/v3"
)

// LDAP-Anmeldung (Active Directory, OpenLDAP, FreeIPA …) als Alternative oder Ergänzung zu OIDC.
//
// Ablauf pro Anmeldung: Dienstkonto bindet → Benutzer per Filter suchen (genau ein Treffer) →
// Bind als dieser Benutzer mit dem eingegebenen Passwort → Gruppen prüfen → Konto anlegen/abgleichen.
// Konten werden über eine unveränderliche ID verknüpft (AD: objectGUID, OpenLDAP: entryUUID),
// damit Umbenennungen oder OU-Wechsel kein neues Konto erzeugen.

type LDAPConfig struct {
	URL                string
	StartTLS           bool
	InsecureSkipVerify bool
	CAFile             string
	BindDN             string
	BindPassword       string
	BaseDN             string
	UserFilter         string
	AttrUsername       string
	AttrEmail          string
	AttrName           string
	AttrID             string
	RequiredGroup      string
	AdminGroup         string
	NestedGroups       bool
	Hint               string
	Timeout            time.Duration
}

func (l LDAPConfig) Enabled() bool { return l.URL != "" && l.BaseDN != "" }

func loadLDAPConfig() LDAPConfig {
	return LDAPConfig{
		URL:                getenv("MS_LDAP_URL", ""),
		StartTLS:           getbool("MS_LDAP_STARTTLS", false),
		InsecureSkipVerify: getbool("MS_LDAP_INSECURE_SKIP_VERIFY", false),
		CAFile:             getenv("MS_LDAP_CA_FILE", ""),
		BindDN:             getenv("MS_LDAP_BIND_DN", ""),
		BindPassword:       secret("MS_LDAP_BIND_PASSWORD"),
		BaseDN:             getenv("MS_LDAP_BASE_DN", ""),
		UserFilter:         getenv("MS_LDAP_USER_FILTER", "(&(objectClass=person)(|(sAMAccountName={username})(userPrincipalName={username})(uid={username})))"),
		AttrUsername:       getenv("MS_LDAP_ATTR_USERNAME", "sAMAccountName"),
		AttrEmail:          getenv("MS_LDAP_ATTR_EMAIL", "mail"),
		AttrName:           getenv("MS_LDAP_ATTR_NAME", "displayName"),
		AttrID:             getenv("MS_LDAP_ATTR_ID", ""),
		RequiredGroup:      getenv("MS_LDAP_REQUIRED_GROUP", ""),
		AdminGroup:         getenv("MS_LDAP_ADMIN_GROUP", ""),
		NestedGroups:       getbool("MS_LDAP_NESTED_GROUPS", false),
		Hint:               getenv("MS_LDAP_HINT", "Du kannst dich mit deinem Domänenkonto anmelden."),
		Timeout:            time.Duration(getint("MS_LDAP_TIMEOUT_SECONDS", 10)) * time.Second,
	}
}

type ldapIdentity struct {
	ID       string
	DN       string
	Username string
	Email    string
	Name     string
	IsAdmin  *bool // nil, wenn keine Admin-Gruppe konfiguriert ist
}

var (
	errBadCredentials = errors.New("Benutzername oder Passwort falsch")
	errNotPermitted   = errors.New("nicht für diese Anwendung freigeschaltet")
	errDirectoryDown  = errors.New("Verzeichnisdienst nicht erreichbar")
)

// directory ist die Schnittstelle zum Verzeichnisdienst (in Tests durch eine Attrappe ersetzt).
type directory interface {
	Authenticate(ctx context.Context, username, password string) (*ldapIdentity, error)
}

type ldapDirectory struct {
	cfg  LDAPConfig
	tls  *tls.Config
	host string
}

func newLDAPDirectory(cfg LDAPConfig) (*ldapDirectory, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Hostname() == "" {
		return nil, fmt.Errorf("MS_LDAP_URL muss ldap://host[:port] oder ldaps://host[:port] sein")
	}
	if !strings.Contains(cfg.UserFilter, "{username}") {
		return nil, fmt.Errorf("MS_LDAP_USER_FILTER muss den Platzhalter {username} enthalten")
	}
	if cfg.StartTLS && u.Scheme == "ldaps" {
		return nil, fmt.Errorf("MS_LDAP_STARTTLS ist nur mit ldap:// sinnvoll, nicht mit ldaps://")
	}
	tc := &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureSkipVerify}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("MS_LDAP_CA_FILE: %w", err)
		}
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("MS_LDAP_CA_FILE enthält kein gültiges PEM-Zertifikat")
		}
		tc.RootCAs = pool
	}
	if u.Scheme == "ldap" && !cfg.StartTLS {
		slog.Warn("LDAP ohne Verschlüsselung: Passwörter werden im Klartext übertragen. ldaps:// oder MS_LDAP_STARTTLS=true verwenden.")
	}
	if cfg.InsecureSkipVerify {
		slog.Warn("LDAP-Zertifikatsprüfung ist deaktiviert (MS_LDAP_INSECURE_SKIP_VERIFY) – nur für Tests verwenden.")
	}
	return &ldapDirectory{cfg: cfg, tls: tc, host: u.Host}, nil
}

func (d *ldapDirectory) connect() (*ldap.Conn, error) {
	conn, err := ldap.DialURL(d.cfg.URL,
		ldap.DialWithDialer(&net.Dialer{Timeout: d.cfg.Timeout}),
		ldap.DialWithTLSConfig(d.tls))
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(d.cfg.Timeout)
	if d.cfg.StartTLS {
		if err := conn.StartTLS(d.tls); err != nil {
			conn.Close()
			return nil, fmt.Errorf("StartTLS: %w", err)
		}
	}
	return conn, nil
}

func (d *ldapDirectory) serviceBind(conn *ldap.Conn) error {
	if d.cfg.BindDN == "" {
		return nil // anonyme Suche
	}
	return conn.Bind(d.cfg.BindDN, d.cfg.BindPassword)
}

func validLoginName(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (d *ldapDirectory) Authenticate(ctx context.Context, username, password string) (*ldapIdentity, error) {
	// Ein leeres Passwort würde bei vielen Servern als „unauthenticated bind“ ERFOLGREICH sein.
	if password == "" || len(password) > 1024 || !validLoginName(username) {
		return nil, errBadCredentials
	}
	conn, err := d.connect()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errDirectoryDown, err)
	}
	defer conn.Close()
	go func() { <-ctx.Done(); conn.Close() }()

	if err := d.serviceBind(conn); err != nil {
		return nil, fmt.Errorf("%w: Dienstkonto-Bind: %v", errDirectoryDown, err)
	}

	attrs := []string{"objectGUID", "entryUUID", "ipaUniqueID"}
	for _, a := range []string{d.cfg.AttrUsername, d.cfg.AttrEmail, d.cfg.AttrName, d.cfg.AttrID} {
		if a != "" {
			attrs = append(attrs, a)
		}
	}
	filter := strings.ReplaceAll(d.cfg.UserFilter, "{username}", ldap.EscapeFilter(username))
	res, err := conn.Search(ldap.NewSearchRequest(d.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, int(d.cfg.Timeout.Seconds()), false, filter, attrs, nil))
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return nil, fmt.Errorf("%w: Suche: %v", errDirectoryDown, err)
	}
	if res == nil || len(res.Entries) != 1 {
		if res != nil && len(res.Entries) > 1 {
			slog.Warn("LDAP: Filter liefert mehrere Benutzer – Anmeldung abgelehnt", "benutzer", username)
		}
		return nil, errBadCredentials
	}
	entry := res.Entries[0]

	if err := conn.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, errBadCredentials
		}
		return nil, fmt.Errorf("%w: Benutzer-Bind: %v", errDirectoryDown, err)
	}
	// Für Gruppenabfragen wieder als Dienstkonto arbeiten (sonst mit den Rechten des Benutzers).
	if d.cfg.BindDN != "" {
		if err := d.serviceBind(conn); err != nil {
			return nil, fmt.Errorf("%w: erneuter Dienstkonto-Bind: %v", errDirectoryDown, err)
		}
	}

	id := &ldapIdentity{
		ID:       entryID(entry, d.cfg.AttrID),
		DN:       entry.DN,
		Username: entry.GetAttributeValue(d.cfg.AttrUsername),
		Email:    entry.GetAttributeValue(d.cfg.AttrEmail),
		Name:     entry.GetAttributeValue(d.cfg.AttrName),
	}
	if id.Username == "" {
		id.Username = username
	}
	if d.cfg.RequiredGroup != "" {
		ok, err := d.memberOf(conn, entry.DN, d.cfg.RequiredGroup)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errNotPermitted
		}
	}
	if d.cfg.AdminGroup != "" {
		ok, err := d.memberOf(conn, entry.DN, d.cfg.AdminGroup)
		if err != nil {
			return nil, err
		}
		id.IsAdmin = &ok
	}
	return id, nil
}

// memberOf prüft die Gruppenmitgliedschaft über das memberOf-Attribut des Benutzers.
// Mit MS_LDAP_NESTED_GROUPS nutzt AD die Matching-Rule LDAP_MATCHING_RULE_IN_CHAIN (verschachtelte Gruppen).
func (d *ldapDirectory) memberOf(conn *ldap.Conn, userDN, groupDN string) (bool, error) {
	attr := "memberOf"
	if d.cfg.NestedGroups {
		attr = "memberOf:1.2.840.113556.1.4.1941:"
	}
	res, err := conn.Search(ldap.NewSearchRequest(userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, int(d.cfg.Timeout.Seconds()), false, "("+attr+"="+ldap.EscapeFilter(groupDN)+")", []string{"1.1"}, nil))
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return false, nil
		}
		return false, fmt.Errorf("%w: Gruppenprüfung: %v", errDirectoryDown, err)
	}
	return len(res.Entries) == 1, nil
}

// entryID liefert eine stabile ID: konfiguriertes Attribut, sonst objectGUID (AD), entryUUID (OpenLDAP),
// ipaUniqueID (FreeIPA) und als letzte Möglichkeit der DN.
func entryID(e *ldap.Entry, attr string) string {
	if attr != "" {
		if raw := e.GetRawAttributeValue(attr); len(raw) > 0 {
			if attr == "objectGUID" && len(raw) == 16 {
				return "guid:" + formatGUID(raw)
			}
			if isPrintable(raw) {
				return attr + ":" + string(raw)
			}
			return attr + ":" + hex.EncodeToString(raw)
		}
	}
	if raw := e.GetRawAttributeValue("objectGUID"); len(raw) == 16 {
		return "guid:" + formatGUID(raw)
	}
	if v := e.GetAttributeValue("entryUUID"); v != "" {
		return "uuid:" + strings.ToLower(v)
	}
	if v := e.GetAttributeValue("ipaUniqueID"); v != "" {
		return "ipa:" + strings.ToLower(v)
	}
	return "dn:" + strings.ToLower(e.DN)
}

// formatGUID wandelt die binäre AD-objectGUID in die übliche Schreibweise (Little-Endian-Felder) um.
func formatGUID(b []byte) string {
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// upsertLDAPUser legt beim ersten Login ein Konto an und gleicht danach E-Mail und Admin-Recht ab.
func (a *App) upsertLDAPUser(id *ldapIdentity) (int64, error) {
	var uid int64
	var disabled bool
	var display string
	err := a.db.QueryRow(`SELECT id, disabled, display_name FROM users WHERE ldap_id = ?`, id.ID).Scan(&uid, &disabled, &display)
	if err == nil {
		if disabled {
			return 0, errUserDisabled
		}
		if display == "" {
			display = cleanLine(id.Name, 60)
		}
		if _, err := a.db.Exec(`UPDATE users SET email = ?, display_name = ? WHERE id = ?`, cleanLine(id.Email, 200), display, uid); err != nil {
			return 0, err
		}
		if id.IsAdmin != nil {
			if _, err := a.db.Exec(`UPDATE users SET is_admin = ? WHERE id = ?`, *id.IsAdmin, uid); err != nil {
				return 0, err
			}
		}
		return uid, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	for attempt := 0; attempt < 3; attempt++ {
		username, err := a.uniqueUsername(id.Username)
		if err != nil {
			return 0, err
		}
		admin := id.IsAdmin != nil && *id.IsAdmin
		res, err := a.db.Exec(`INSERT INTO users (username, email, display_name, ldap_id, is_admin, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
			username, cleanLine(id.Email, 200), cleanLine(id.Name, 60), id.ID, admin, now())
		if isUniqueErr(err) {
			continue
		}
		if err != nil {
			return 0, err
		}
		return res.LastInsertId()
	}
	return 0, errors.New("LDAP-Benutzer konnte nicht angelegt werden")
}

// ldapTestCmd prüft die Konfiguration von der Kommandozeile aus: meldestelle ldap-test -user NAME
func ldapTestCmd(cfg Config, user string) error {
	if !cfg.LDAP.Enabled() {
		return errors.New("LDAP ist nicht konfiguriert (MS_LDAP_URL und MS_LDAP_BASE_DN setzen)")
	}
	d, err := newLDAPDirectory(cfg.LDAP)
	if err != nil {
		return err
	}
	pw := os.Getenv("MS_LDAP_TEST_PASSWORD")
	if pw == "" {
		if pw, err = readPassword("Passwort für " + user + ": "); err != nil {
			return err
		}
	}
	id, err := d.Authenticate(context.Background(), user, pw)
	if err != nil {
		return err
	}
	fmt.Printf("Anmeldung erfolgreich\n  DN:           %s\n  ID:           %s\n  Benutzername: %s\n  Name:         %s\n  E-Mail:       %s\n",
		id.DN, id.ID, id.Username, id.Name, id.Email)
	if id.IsAdmin != nil {
		fmt.Printf("  Administrator: %v\n", *id.IsAdmin)
	}
	return nil
}
