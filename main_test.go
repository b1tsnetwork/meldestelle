package main

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

type client struct {
	t    *testing.T
	base string
	c    *http.Client
}

func newClient(t *testing.T, base string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: base, c: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}}
}

func (c *client) csrf() string {
	u, _ := url.Parse(c.base)
	for _, ck := range c.c.Jar.Cookies(u) {
		if ck.Name == csrfCookie {
			return ck.Value
		}
	}
	c.get("/") // Token holen
	return c.csrf()
}

func (c *client) get(path string) (int, string) {
	res, err := c.c.Get(c.base + path)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func (c *client) post(path string, form url.Values) (int, string, string) {
	if form.Get("csrf") == "" {
		form.Set("csrf", c.csrf())
	}
	res, err := c.c.PostForm(c.base+path, form)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header.Get("Location"), string(b)
}

func (c *client) postMultipart(path string, fields map[string]string, fileName string, data []byte) (int, string) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("csrf", c.csrf())
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	if fileName != "" {
		fw, _ := mw.CreateFormFile("anhaenge", fileName)
		fw.Write(data)
	}
	mw.Close()
	req, _ := http.NewRequest("POST", c.base+path, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	res, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode, res.Header.Get("Location")
}

func (c *client) register(name string) {
	code, _, body := c.post("/registrieren", url.Values{"benutzer": {name}, "passwort": {"geheim-passwort"}, "passwort2": {"geheim-passwort"}})
	if code != http.StatusSeeOther {
		c.t.Fatalf("Registrierung %s: %d %s", name, code, body)
	}
}

var attRe = regexp.MustCompile(`/anhang/(\d+)/`)

func TestSichtbarkeitUndAblauf(t *testing.T) {
	cfg := loadConfig()
	cfg.DataDir = t.TempDir()
	cfg.BaseURL = "http://example.test"
	app, err := newApp(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(app.routes())
	defer srv.Close()

	// Admin direkt anlegen (wie create-admin)
	hash, _ := bcrypt.GenerateFromPassword([]byte("admin-passwort"), bcrypt.MinCost)
	app.db.Exec(`INSERT INTO users (username, password_hash, is_admin, created_at) VALUES ('admin', ?, 1, ?)`, string(hash), now())

	admin, alice, bob, eve, anon := newClient(t, srv.URL), newClient(t, srv.URL), newClient(t, srv.URL), newClient(t, srv.URL), newClient(t, srv.URL)
	if code, _, _ := admin.post("/login", url.Values{"benutzer": {"admin"}, "passwort": {"admin-passwort"}}); code != http.StatusSeeOther {
		t.Fatalf("Admin-Login: %d", code)
	}
	alice.register("alice")
	bob.register("bob")
	eve.register("eve")

	// CSRF-Schutz
	if code, _, _ := alice.post("/admin/software", url.Values{"csrf": {"falsch"}, "name": {"X"}}); code != http.StatusForbidden {
		t.Fatalf("CSRF erwartet 403, bekam %d", code)
	}
	// Nur Admins verwalten
	if code, _, _ := alice.post("/admin/software", url.Values{"name": {"X"}}); code != http.StatusForbidden {
		t.Fatalf("Nicht-Admin legt Software an: %d", code)
	}

	admin.post("/admin/software", url.Values{"name": {"Super Tool"}})
	admin.post("/admin/software", url.Values{"name": {"Anderes Tool"}})
	admin.post("/admin/software/1/entwickler", url.Values{"benutzer": {"bob"}})
	admin.post("/admin/software/2/entwickler", url.Values{"benutzer": {"eve"}}) // eve ist Entwicklerin einer ANDEREN Software

	// Öffentliche Meldung mit Bild-Anhang, vertrauliche mit Exploit-Anhang
	png := []byte("\x89PNG\r\n\x1a\n" + strings.Repeat("x", 100))
	code, loc := alice.postMultipart("/neu", map[string]string{"software": "1", "art": "bug", "titel": "Absturz beim Speichern", "beschreibung": "Reproduzierbar mit leerer Datei."}, "screen.png", png)
	if code != http.StatusSeeOther || loc != "/r/1" {
		t.Fatalf("Bug anlegen: %d %s", code, loc)
	}
	code, loc = alice.postMultipart("/neu", map[string]string{"software": "1", "art": "security", "titel": "RCE über Upload GEHEIM", "beschreibung": "Exploit siehe Anhang."}, "exploit.py", []byte("print('pwn')"))
	if code != http.StatusSeeOther || loc != "/r/2" {
		t.Fatalf("Security anlegen: %d %s", code, loc)
	}

	_, page := alice.get("/r/2")
	m := attRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("Anhang der Sicherheitsmeldung fehlt")
	}
	secAtt := "/anhang/" + m[1] + "/exploit.py"

	// Sichtbarkeit
	for name, c := range map[string]*client{"anon": anon, "eve (fremde Entwicklerin)": eve} {
		if _, body := c.get("/"); strings.Contains(body, "GEHEIM") || !strings.Contains(body, "Absturz") {
			t.Errorf("%s: Liste falsch gefiltert", name)
		}
		if _, body := c.get("/?art=security"); strings.Contains(body, "GEHEIM") {
			t.Errorf("%s: sieht Sicherheitsmeldung im Filter", name)
		}
		if _, body := c.get("/?q=GEHEIM"); strings.Contains(body, "RCE") {
			t.Errorf("%s: findet Sicherheitsmeldung über Suche", name)
		}
		if code, _ := c.get("/r/2"); code != http.StatusNotFound {
			t.Errorf("%s: /r/2 = %d, erwartet 404", name, code)
		}
		if code, body := c.get(secAtt); code != http.StatusNotFound || strings.Contains(body, "pwn") {
			t.Errorf("%s: Exploit-Anhang abrufbar (%d)", name, code)
		}
	}
	for name, c := range map[string]*client{"alice (Autorin)": alice, "bob (Entwickler)": bob, "admin": admin} {
		if code, body := c.get("/r/2"); code != http.StatusOK || !strings.Contains(body, "GEHEIM") {
			t.Errorf("%s: sieht Sicherheitsmeldung nicht (%d)", name, code)
		}
		if code, body := c.get(secAtt); code != http.StatusOK || body != "print('pwn')" {
			t.Errorf("%s: Anhang nicht abrufbar (%d)", name, code)
		}
	}
	if _, body := bob.get("/?art=security"); !strings.Contains(body, "GEHEIM") {
		t.Error("bob: Sicherheitsmeldung fehlt in der Liste")
	}

	// Anhänge werden sicher ausgeliefert
	res, _ := anon.c.Get(srv.URL + secAtt)
	res.Body.Close()
	res, _ = bob.c.Get(srv.URL + secAtt)
	res.Body.Close()
	if ct := res.Header.Get("Content-Type"); ct != "application/octet-stream" || !strings.HasPrefix(res.Header.Get("Content-Disposition"), "attachment") {
		t.Errorf("Exploit-Anhang wird nicht als Download ausgeliefert: %s", ct)
	}

	// Upvotes
	req, _ := http.NewRequest("POST", srv.URL+"/r/1/vote", strings.NewReader(url.Values{"csrf": {eve.csrf()}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, _ = eve.c.Do(req)
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(b), `"score":2`) || !strings.Contains(string(b), `"voted":true`) {
		t.Errorf("Vote: %s", b)
	}
	eve.post("/r/1/vote", url.Values{}) // zurücknehmen
	if _, body := anon.get("/r/1"); !strings.Contains(body, `<span class="n">1</span>`) {
		t.Error("Vote zurücknehmen hat nicht funktioniert")
	}
	if code, _, _ := anon.post("/r/1/vote", url.Values{}); code != http.StatusSeeOther {
		t.Errorf("Anonymer Vote sollte zum Login umleiten, bekam %d", code)
	}
	if code, _, _ := alice.post("/r/2/vote", url.Values{}); code != http.StatusBadRequest {
		t.Errorf("Vote auf vertrauliche Meldung: %d", code)
	}

	// Nur Entwickler der Software verwalten
	if code, _, _ := eve.post("/r/1/verwalten", url.Values{"status": {"fixed"}, "art": {"bug"}}); code != http.StatusForbidden {
		t.Errorf("eve darf fremde Software verwalten: %d", code)
	}
	if code, _, _ := alice.post("/r/2/verwalten", url.Values{"status": {"fixed"}, "art": {"security"}}); code != http.StatusForbidden {
		t.Errorf("Autorin darf verwalten: %d", code)
	}

	// Bug zu Sicherheit umstufen → automatisch vertraulich
	bob.post("/r/1/verwalten", url.Values{"status": {"confirmed"}, "art": {"security"}})
	if code, _ := anon.get("/r/1"); code != http.StatusNotFound {
		t.Errorf("Umgestufte Meldung noch öffentlich: %d", code)
	}

	// Nach dem Fix veröffentlichen
	bob.post("/r/2/verwalten", url.Values{"status": {"fixed"}, "art": {"security"}, "vertraulich": {"0"}})
	if code, body := anon.get("/r/2"); code != http.StatusOK || !strings.Contains(body, "Veröffentlicht") {
		t.Errorf("Veröffentlichte Meldung nicht sichtbar: %d", code)
	}

	// Kommentar mit Anhang
	if code, loc := eve.postMultipart("/r/2/kommentar", map[string]string{"text": "Danke für den Fix!"}, "log.txt", []byte("log")); code != http.StatusSeeOther || !strings.HasPrefix(loc, "/r/2#k") {
		t.Errorf("Kommentar: %d %s", code, loc)
	}

	// Open Redirect verhindert
	if code, loc, _ := newClient(t, srv.URL).post("/login", url.Values{"benutzer": {"alice"}, "passwort": {"geheim-passwort"}, "next": {"//evil.example"}}); code != http.StatusSeeOther || loc != "/" {
		t.Errorf("Open Redirect: %d %s", code, loc)
	}
}

func TestErledigteAmEnde(t *testing.T) {
	cfg := loadConfig()
	cfg.DataDir = t.TempDir()
	app, err := newApp(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	db := app.db
	db.Exec(`INSERT INTO users (id, username, created_at) VALUES (1, 'u', 0)`)
	db.Exec(`INSERT INTO software (id, slug, name, created_at) VALUES (1, 's', 'S', 0)`)
	ins := func(id int, status string, score int) {
		db.Exec(`INSERT INTO reports (id, software_id, author_id, kind, status, title, body, score, created_at, updated_at)
			VALUES (?, 1, 1, 'bug', ?, 't', 'b', ?, ?, ?)`, id, status, score, now()-int64(id), now()-int64(id))
	}
	ins(1, "fixed", 99)
	ins(2, "open", 1)
	ins(3, "wontfix", 50)
	ins(4, "in_progress", 2)
	for _, sort := range []string{"hot", "top", "neu"} {
		list, _, err := app.queryReports(nil, listFilter{Sort: sort}, 1)
		if err != nil {
			t.Fatal(err)
		}
		var order []int64
		for _, r := range list {
			order = append(order, r.ID)
		}
		if len(order) != 4 || list[0].Done() || list[1].Done() || !list[2].Done() || !list[3].Done() || !list[2].FirstDone {
			t.Errorf("%s: Reihenfolge %v", sort, order)
		}
	}
}
