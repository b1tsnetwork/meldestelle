package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type fakeUser struct {
	pw    string
	ident ldapIdentity
	deny  bool
}

type fakeDir struct {
	users map[string]fakeUser
	down  bool
	calls int
}

func (f *fakeDir) Authenticate(_ context.Context, user, pw string) (*ldapIdentity, error) {
	f.calls++
	if f.down {
		return nil, errDirectoryDown
	}
	u, ok := f.users[strings.ToLower(user)]
	if !ok || pw == "" || u.pw != pw {
		return nil, errBadCredentials
	}
	if u.deny {
		return nil, errNotPermitted
	}
	id := u.ident
	return &id, nil
}

func boolp(b bool) *bool { return &b }

func TestLDAPAnmeldung(t *testing.T) {
	cfg := loadConfig()
	cfg.DataDir = t.TempDir()
	cfg.BaseURL = "http://example.test"
	app, err := newApp(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	dir := &fakeDir{users: map[string]fakeUser{
		"jdoe":   {pw: "ad-pass", ident: ldapIdentity{ID: "guid:1111", Username: "jdoe", Email: "jdoe@firma.de", Name: "Jana Doe", IsAdmin: boolp(false)}},
		"chef":   {pw: "ad-pass", ident: ldapIdentity{ID: "guid:2222", Username: "chef", Email: "chef@firma.de", Name: "Chefin", IsAdmin: boolp(true)}},
		"extern": {pw: "ad-pass", deny: true},
	}}
	app.dir = dir
	srv := httptest.NewServer(app.routes())
	defer srv.Close()

	// Ein lokal registrierter Fremder belegt den Namen "jdoe", bevor die echte Jana sich anmeldet.
	h, _ := bcrypt.GenerateFromPassword([]byte("lokal-pass"), bcrypt.MinCost)
	app.db.Exec(`INSERT INTO users (username, password_hash, created_at) VALUES ('jdoe', ?, 0)`, string(h))

	login := func(user, pw string) (int, string, *client) {
		c := newClient(t, srv.URL)
		code, loc, body := c.post("/login", url.Values{"benutzer": {user}, "passwort": {pw}})
		_ = loc
		return code, body, c
	}

	// LDAP-Login legt ein eigenes, über die GUID verknüpftes Konto an
	code, body, jana := login("jdoe", "ad-pass")
	if code != http.StatusSeeOther {
		t.Fatalf("LDAP-Login: %d %s", code, body)
	}
	var uname, mail, name, lid string
	app.db.QueryRow(`SELECT username, email, display_name, ldap_id FROM users WHERE ldap_id = 'guid:1111'`).Scan(&uname, &mail, &name, &lid)
	if uname != "jdoe-2" || mail != "jdoe@firma.de" || name != "Jana Doe" {
		t.Errorf("LDAP-Konto falsch angelegt: %q %q %q", uname, mail, name)
	}
	if _, page := jana.get("/konto"); !strings.Contains(page, "Verzeichniskonto") || strings.Contains(page, "Passwort ändern") {
		t.Error("Kontoseite zeigt LDAP-Konto nicht korrekt")
	}

	// Der lokale "jdoe" meldet sich weiterhin mit seinem eigenen Passwort an – und landet NICHT im LDAP-Konto
	before := dir.calls
	if code, _, _ := login("jdoe", "lokal-pass"); code != http.StatusSeeOther {
		t.Errorf("lokaler Login: %d", code)
	}
	if dir.calls != before {
		t.Error("bei erfolgreichem lokalen Login wurde trotzdem LDAP gefragt")
	}

	// Zweiter Login: gleiches Konto, E-Mail wird abgeglichen, kein Duplikat
	u := dir.users["jdoe"]
	u.ident.Email = "jana.doe@firma.de"
	dir.users["jdoe"] = u
	login("jdoe", "ad-pass")
	var n int
	app.db.QueryRow(`SELECT COUNT(*) FROM users WHERE ldap_id = 'guid:1111'`).Scan(&n)
	app.db.QueryRow(`SELECT email FROM users WHERE ldap_id = 'guid:1111'`).Scan(&mail)
	if n != 1 || mail != "jana.doe@firma.de" {
		t.Errorf("Abgleich beim zweiten Login: %d Konten, Mail %q", n, mail)
	}

	// Admin-Gruppe wird bei jeder Anmeldung übernommen – auch der Entzug
	login("chef", "ad-pass")
	var admin bool
	app.db.QueryRow(`SELECT is_admin FROM users WHERE ldap_id = 'guid:2222'`).Scan(&admin)
	if !admin {
		t.Error("Mitglied der Admin-Gruppe ist kein Admin")
	}
	c := dir.users["chef"]
	c.ident.IsAdmin = boolp(false)
	dir.users["chef"] = c
	login("chef", "ad-pass")
	app.db.QueryRow(`SELECT is_admin FROM users WHERE ldap_id = 'guid:2222'`).Scan(&admin)
	if admin {
		t.Error("Admin-Recht nach Austritt aus der Gruppe nicht entzogen")
	}

	// Fehlerfälle mit verständlichen Meldungen
	if code, body, _ := login("jdoe", "falsch"); code != http.StatusUnauthorized || !strings.Contains(body, "falsch") {
		t.Errorf("falsches Passwort: %d", code)
	}
	if code, body, _ := login("extern", "ad-pass"); code != http.StatusForbidden || !strings.Contains(body, "nicht freigeschaltet") {
		t.Errorf("fehlende Pflichtgruppe: %d", code)
	}
	app.db.Exec(`UPDATE users SET disabled = 1 WHERE ldap_id = 'guid:2222'`)
	if code, body, _ := login("chef", "ad-pass"); code != http.StatusForbidden || !strings.Contains(body, "gesperrt") {
		t.Errorf("gesperrtes LDAP-Konto: %d", code)
	}
	dir.down = true
	if code, body, _ := login("jdoe", "ad-pass"); code != http.StatusServiceUnavailable || !strings.Contains(body, "nicht erreichbar") {
		t.Errorf("Verzeichnis nicht erreichbar: %d", code)
	}
	dir.down = false

	// Nur LDAP, lokale Anmeldung abgeschaltet: lokales Passwort zählt nicht mehr
	app.cfg.AllowLocalLogin = false
	if code, _, _ := login("jdoe", "lokal-pass"); code != http.StatusUnauthorized {
		t.Errorf("lokaler Login trotz MS_LOCAL_LOGIN=false: %d", code)
	}
	if code, _, _ := login("jdoe", "ad-pass"); code != http.StatusSeeOther {
		t.Errorf("LDAP-Login bei abgeschalteter lokaler Anmeldung: %d", code)
	}
	if _, page := newClient(t, srv.URL).get("/login"); !strings.Contains(page, "Domänenkonto") {
		t.Error("Login-Formular zeigt LDAP-Hinweis nicht")
	}
}

// Ein leeres Passwort darf nie zum Server gelangen (unauthenticated bind wäre sonst „erfolgreich“).
func TestLDAPLeeresPasswort(t *testing.T) {
	d, err := newLDAPDirectory(LDAPConfig{URL: "ldap://192.0.2.1:389", BaseDN: "dc=x", UserFilter: "(uid={username})", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := d.Authenticate(context.Background(), "jdoe", ""); err != errBadCredentials {
		t.Errorf("leeres Passwort: %v", err)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Error("bei leerem Passwort wurde eine Verbindung aufgebaut")
	}
}

func TestLDAPKonfiguration(t *testing.T) {
	for _, c := range []LDAPConfig{
		{URL: "http://dc01", BaseDN: "dc=x", UserFilter: "(uid={username})"},
		{URL: "ldap://dc01", BaseDN: "dc=x", UserFilter: "(uid=fest)"},
		{URL: "ldaps://dc01", BaseDN: "dc=x", UserFilter: "(uid={username})", StartTLS: true},
	} {
		if _, err := newLDAPDirectory(c); err == nil {
			t.Errorf("ungültige Konfiguration akzeptiert: %+v", c)
		}
	}
	if g := formatGUID([]byte{0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}); g != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Errorf("GUID-Format: %s", g)
	}
}

// Integrationstest gegen einen echten Server, nur wenn MS_TEST_LDAP_URL gesetzt ist, z. B.:
// MS_TEST_LDAP_URL=ldap://localhost:389 MS_TEST_LDAP_BASE_DN=dc=example,dc=org
// MS_TEST_LDAP_BIND_DN=cn=admin,dc=example,dc=org MS_TEST_LDAP_BIND_PASSWORD=… MS_TEST_LDAP_USER=jdoe
// MS_TEST_LDAP_PASSWORD=… [MS_TEST_LDAP_ADMIN_GROUP=… MS_TEST_LDAP_REQUIRED_GROUP=…] go test -run Integration
func TestLDAPIntegration(t *testing.T) {
	url := os.Getenv("MS_TEST_LDAP_URL")
	if url == "" {
		t.Skip("MS_TEST_LDAP_URL nicht gesetzt")
	}
	cfg := LDAPConfig{
		URL: url, BaseDN: os.Getenv("MS_TEST_LDAP_BASE_DN"),
		BindDN: os.Getenv("MS_TEST_LDAP_BIND_DN"), BindPassword: os.Getenv("MS_TEST_LDAP_BIND_PASSWORD"),
		UserFilter:   "(&(objectClass=person)(|(sAMAccountName={username})(uid={username})))",
		AttrUsername: "uid", AttrEmail: "mail", AttrName: "cn",
		AdminGroup: os.Getenv("MS_TEST_LDAP_ADMIN_GROUP"), RequiredGroup: os.Getenv("MS_TEST_LDAP_REQUIRED_GROUP"),
		StartTLS: os.Getenv("MS_TEST_LDAP_STARTTLS") == "1", CAFile: os.Getenv("MS_TEST_LDAP_CA_FILE"),
		Timeout: 5 * time.Second,
	}
	d, err := newLDAPDirectory(cfg)
	if err != nil {
		t.Fatal(err)
	}
	user, pw := os.Getenv("MS_TEST_LDAP_USER"), os.Getenv("MS_TEST_LDAP_PASSWORD")
	id, err := d.Authenticate(context.Background(), user, pw)
	if err != nil {
		t.Fatalf("Anmeldung: %v", err)
	}
	t.Logf("%+v admin=%v", *id, id.IsAdmin != nil && *id.IsAdmin)
	if !strings.HasPrefix(id.ID, "uuid:") && !strings.HasPrefix(id.ID, "guid:") {
		t.Errorf("keine stabile ID: %s", id.ID)
	}
	if _, err := d.Authenticate(context.Background(), user, pw+"x"); err != errBadCredentials {
		t.Errorf("falsches Passwort: %v", err)
	}
	if _, err := d.Authenticate(context.Background(), user+")(uid=*", pw); err != errBadCredentials {
		t.Errorf("Filter-Injection: %v", err)
	}
	if _, err := d.Authenticate(context.Background(), "*", pw); err != errBadCredentials {
		t.Errorf("Platzhalter-Benutzername: %v", err)
	}
	if u2 := os.Getenv("MS_TEST_LDAP_USER2"); u2 != "" {
		_, err := d.Authenticate(context.Background(), u2, os.Getenv("MS_TEST_LDAP_PASSWORD2"))
		if want := os.Getenv("MS_TEST_LDAP_USER2_EXPECT"); want == "forbidden" && err != errNotPermitted {
			t.Errorf("Benutzer außerhalb der Pflichtgruppe: %v", err)
		}
	}
}
