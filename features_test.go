package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// ---------- SMTP-Testserver ----------

type sentMail struct {
	To      string
	Subject string
	Body    string
	Raw     string
}

type fakeSMTP struct {
	ln   net.Listener
	mu   sync.Mutex
	msgs []sentMail
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	w := func(s string) { c.Write([]byte(s + "\r\n")) }
	w("220 test")
	var to string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			w("250-test")
			w("250 8BITMIME")
		case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RSET"), strings.HasPrefix(cmd, "NOOP"):
			w("250 OK")
		case strings.HasPrefix(cmd, "RCPT"):
			to = strings.Trim(strings.TrimSpace(line[strings.Index(line, ":")+1:]), "<>")
			w("250 OK")
		case cmd == "DATA":
			w("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			raw := b.String()
			head, body, _ := strings.Cut(raw, "\r\n\r\n")
			dec, _ := io.ReadAll(quotedprintable.NewReader(strings.NewReader(body)))
			subj := ""
			for _, h := range strings.Split(head, "\r\n") {
				if strings.HasPrefix(h, "Subject: ") {
					subj, _ = new(mimeDecoder).decode(strings.TrimPrefix(h, "Subject: "))
				}
			}
			f.mu.Lock()
			f.msgs = append(f.msgs, sentMail{To: to, Subject: subj, Body: string(dec), Raw: raw})
			f.mu.Unlock()
			w("250 OK")
		case cmd == "QUIT":
			w("221 bye")
			return
		default:
			w("502 unknown")
		}
	}
}

func (f *fakeSMTP) take() []sentMail {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.msgs
	f.msgs = nil
	return m
}

func mailsTo(ms []sentMail, to string) []sentMail {
	var out []sentMail
	for _, m := range ms {
		if m.To == to {
			out = append(out, m)
		}
	}
	return out
}

// ---------- ClamAV-Attrappe (spricht das INSTREAM-Protokoll) ----------

func newFakeClamd(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				cmd, _ := r.ReadString(0)
				if cmd == "zPING\x00" {
					c.Write([]byte("PONG\x00"))
					return
				}
				var data bytes.Buffer
				size := make([]byte, 4)
				for {
					if _, err := io.ReadFull(r, size); err != nil {
						return
					}
					n := binary.BigEndian.Uint32(size)
					if n == 0 {
						break
					}
					io.CopyN(&data, r, int64(n))
				}
				if bytes.Contains(data.Bytes(), []byte("EICAR-STANDARD-ANTIVIRUS-TEST-FILE")) {
					c.Write([]byte("stream: Eicar-Test-Signature FOUND\x00"))
				} else {
					c.Write([]byte("stream: OK\x00"))
				}
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return "tcp://" + ln.Addr().String()
}

// ---------- Aufbau ----------

type world struct {
	app  *App
	srv  *httptest.Server
	smtp *fakeSMTP
	c    map[string]*client
}

func newWorld(t *testing.T, mutate func(*Config)) *world {
	cfg := loadConfig()
	cfg.DataDir = t.TempDir()
	cfg.BaseURL = "http://meldestelle.test"
	cfg.Limits = LimitConfig{ReportsPerHour: 100, RepliesPerHour: 100}
	fs := newFakeSMTP(t)
	cfg.SMTP = SMTPConfig{Host: "127.0.0.1", Port: fs.port(), From: "Meldestelle <meldestelle@example.org>", TLS: "none"}
	if mutate != nil {
		mutate(&cfg)
	}
	app, err := newApp(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(app.routes())
	t.Cleanup(srv.Close)
	w := &world{app: app, srv: srv, smtp: fs, c: map[string]*client{}}

	h, _ := bcrypt.GenerateFromPassword([]byte("admin-passwort"), bcrypt.MinCost)
	app.db.Exec(`INSERT INTO users (username, email, password_hash, is_admin, created_at) VALUES ('admin', 'admin@example.org', ?, 1, 0)`, string(h))
	w.c["admin"] = newClient(t, srv.URL)
	w.c["admin"].post("/login", url.Values{"benutzer": {"admin"}, "passwort": {"admin-passwort"}})
	for _, n := range []string{"alice", "bob", "carol", "dave", "eve"} {
		w.c[n] = newClient(t, srv.URL)
		w.c[n].register(n)
		app.db.Exec(`UPDATE users SET email = ? WHERE username = ?`, n+"@example.org", n)
	}
	a := w.c["admin"]
	a.post("/admin/software", url.Values{"name": {"Portal"}})
	a.post("/admin/software", url.Values{"name": {"Anderes"}})
	a.post("/admin/software/1/entwickler", url.Values{"benutzer": {"bob"}})
	a.post("/admin/software/1/entwickler", url.Values{"benutzer": {"carol"}})
	a.post("/admin/software/2/entwickler", url.Values{"benutzer": {"eve"}})
	return w
}

func (w *world) flush() []sentMail {
	w.app.flushOutbox(context.Background())
	return w.smtp.take()
}

func (w *world) report(t *testing.T, who string, sw int, kind, title, body string) int64 {
	code, loc := w.c[who].postMultipart("/neu", map[string]string{"software": strconv.Itoa(sw), "art": kind, "titel": title, "beschreibung": body}, "", nil)
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/r/") {
		t.Fatalf("Meldung von %s: %d %s", who, code, loc)
	}
	id, _ := strconv.ParseInt(strings.TrimPrefix(loc, "/r/"), 10, 64)
	return id
}

func (w *world) reply(t *testing.T, who string, id int64, text string) int64 {
	code, loc := w.c[who].postMultipart("/r/"+itoa(id)+"/kommentar", map[string]string{"text": text}, "", nil)
	if code != http.StatusSeeOther {
		t.Fatalf("Antwort von %s: %d", who, code)
	}
	_, k, _ := strings.Cut(loc, "#k")
	n, _ := strconv.ParseInt(k, 10, 64)
	return n
}

func manage(c *client, id int64, v url.Values) (int, string) {
	if v.Get("status") == "" {
		v.Set("status", "open")
	}
	if v.Get("art") == "" {
		v.Set("art", "bug")
	}
	code, _, _ := c.post("/r/"+itoa(id)+"/verwalten", v)
	_, page := c.get("/r/" + itoa(id))
	return code, page
}

// ---------- Tests ----------

func TestBenachrichtigungen(t *testing.T) {
	w := newWorld(t, nil)
	w.flush()

	// Neue öffentliche Meldung → Entwickler (bob, carol), nicht der Autor, nicht Entwickler anderer Software
	id := w.report(t, "alice", 1, "bug", "Export nach CSV bricht ab", "Beim **Export** großer Listen kommt ein Fehler.")
	ms := w.flush()
	if len(mailsTo(ms, "bob@example.org")) != 1 || len(mailsTo(ms, "carol@example.org")) != 1 || len(ms) != 2 {
		t.Fatalf("Neue Meldung: %d Mails %+v", len(ms), ms)
	}
	m := ms[0]
	if !strings.Contains(m.Subject, "#1 Export nach CSV bricht ab") || !strings.Contains(m.Body, "Export großer Listen") ||
		!strings.Contains(m.Body, "http://meldestelle.test/r/1") || !strings.Contains(m.Raw, "References: <meldung-1@meldestelle.test>") {
		t.Errorf("Inhalt der Mail: %q / %q", m.Subject, m.Body)
	}

	// Antwort von bob → alice (Autorin folgt automatisch), nicht bob selbst
	w.reply(t, "bob", id, "Kann ich nachstellen, schaue ich mir an.")
	ms = w.flush()
	if len(ms) != 1 || ms[0].To != "alice@example.org" || !strings.Contains(ms[0].Body, "Kann ich nachstellen") {
		t.Fatalf("Antwort: %+v", ms)
	}

	// dave folgt manuell, bob antwortete (folgt automatisch) → alice antwortet: bob + dave
	w.c["dave"].post("/r/1/folgen", url.Values{})
	w.reply(t, "alice", id, "Danke!")
	ms = w.flush()
	if len(ms) != 2 || len(mailsTo(ms, "bob@example.org")) != 1 || len(mailsTo(ms, "dave@example.org")) != 1 {
		t.Fatalf("Folgende: %+v", ms)
	}

	// Entfolgen und abgeschaltete Benachrichtigungen
	w.c["dave"].post("/r/1/folgen", url.Values{})
	w.c["bob"].post("/konto", url.Values{"aktion": {"benachrichtigungen"}, "neu": {"1"}, "zugewiesen": {"1"}})
	w.reply(t, "alice", id, "Noch ein Detail")
	if ms = w.flush(); len(ms) != 0 {
		t.Errorf("Mails trotz Entfolgen/abbestellt: %+v", ms)
	}

	// Zuweisung: carol bekommt eine Zuweisungs-Mail statt der normalen Änderungs-Mail
	manage(w.c["bob"], id, url.Values{"status": {"confirmed"}, "zustaendig": {"4"}}) // carol hat id 4
	ms = w.flush()
	if c := mailsTo(ms, "carol@example.org"); len(c) != 1 || !strings.Contains(c[0].Body, "zugewiesen") {
		t.Errorf("Zuweisung an carol: %+v", ms)
	}
	if a := mailsTo(ms, "alice@example.org"); len(a) != 1 || !strings.Contains(a[0].Body, "Status: Offen → Bestätigt") {
		t.Errorf("Änderungs-Mail an alice: %+v", ms)
	}

	// Vertrauliche Meldung: weder Titel noch Inhalt in der Mail
	w.report(t, "alice", 1, "security", "SQL-Injection GEHEIMTITEL", "Payload GEHEIMINHALT im Suchfeld")
	ms = w.flush()
	for _, m := range ms {
		if strings.Contains(m.Subject+m.Body, "GEHEIM") {
			t.Errorf("vertraulicher Inhalt in Mail an %s: %q %q", m.To, m.Subject, m.Body)
		}
	}
	if len(ms) != 2 || len(mailsTo(ms, "alice@example.org")) != 0 { // bob hat nur „Folgen“ abbestellt
		t.Errorf("Security-Mail an Entwickler: %d Mails", len(ms))
	}

	// Folgender verliert die Sichtbarkeit (Meldung wird vertraulich) → keine Mail mehr an ihn
	pub := w.report(t, "alice", 1, "bug", "Login-Button reagiert nicht", "Nach Klick passiert nichts.")
	w.flush()
	w.c["dave"].post("/r/"+itoa(pub)+"/folgen", url.Values{})
	manage(w.c["carol"], pub, url.Values{"art": {"security"}})
	ms = w.flush()
	if len(mailsTo(ms, "dave@example.org")) != 0 {
		t.Errorf("dave bekam Mail zu jetzt vertraulicher Meldung")
	}
	if len(mailsTo(ms, "alice@example.org")) != 1 {
		t.Errorf("Autorin bekam keine Mail zur Umstufung")
	}

	// Mailserver weg → Wiederholung später, kein Verlust
	w.smtp.ln.Close()
	w.reply(t, "carol", id, "Fix ist unterwegs")
	w.app.flushOutbox(context.Background())
	var attempts int
	var nextTry int64
	w.app.db.QueryRow(`SELECT attempts, next_try FROM outbox WHERE sent_at = 0 ORDER BY id DESC LIMIT 1`).Scan(&attempts, &nextTry)
	if attempts != 1 || nextTry <= now() {
		t.Errorf("Wiederholung nicht geplant: attempts=%d next=%d", attempts, nextTry-now())
	}
}

func TestMarkdownImDetail(t *testing.T) {
	w := newWorld(t, nil)
	id := w.report(t, "alice", 1, "bug", "Fehler mit Stacktrace", "Siehe **Log**:\n\n```\npanic: <nil>\n```\n<script>alert(1)</script>")
	_, page := w.c["dave"].get("/r/" + itoa(id))
	if !strings.Contains(page, "<strong>Log</strong>") || !strings.Contains(page, "<pre><code>panic: &lt;nil&gt;") || strings.Contains(page, "<script>alert") {
		t.Errorf("Markdown nicht korrekt gerendert")
	}
	code, _, body := w.c["dave"].post("/api/vorschau", url.Values{"text": {"**x** <img src=x onerror=1>"}})
	var prev struct{ HTML string }
	json.Unmarshal([]byte(body), &prev)
	if code != 200 || !strings.Contains(prev.HTML, "<strong>x</strong>") || strings.Contains(prev.HTML, "<img") {
		t.Errorf("Vorschau: %d %s", code, prev.HTML)
	}
	if code, _, _ := newClient(t, w.srv.URL).post("/api/vorschau", url.Values{"text": {"x"}}); code != http.StatusSeeOther {
		t.Errorf("Vorschau ohne Anmeldung: %d", code)
	}
}

func TestBearbeitenUndModeration(t *testing.T) {
	w := newWorld(t, nil)
	id := w.report(t, "alice", 1, "bug", "Tippfehler im Titell", "Die Beschreibung ist noch unvollständig.")
	r := "/r/" + itoa(id)

	// Fremde dürfen nicht bearbeiten, Autorin und Entwickler schon
	if code, _, _ := w.c["dave"].post(r+"/bearbeiten", url.Values{"titel": {"Gekapert"}, "beschreibung": {"xxxxxxxxxxxx"}}); code != http.StatusForbidden {
		t.Errorf("Fremder bearbeitet: %d", code)
	}
	if code, _, _ := w.c["eve"].post(r+"/bearbeiten", url.Values{"titel": {"Gekapert"}, "beschreibung": {"xxxxxxxxxxxx"}}); code != http.StatusForbidden {
		t.Errorf("Entwicklerin anderer Software bearbeitet: %d", code)
	}
	code, _ := w.c["alice"].postMultipart(r+"/bearbeiten", map[string]string{"titel": "Tippfehler im Titel", "beschreibung": "Jetzt vollständig beschrieben.", "version": "1.2"}, "log.txt", []byte("log"))
	if code != http.StatusSeeOther {
		t.Fatalf("Autorin bearbeitet: %d", code)
	}
	_, page := w.c["dave"].get(r)
	for _, want := range []string{"Tippfehler im Titel", "Jetzt vollständig beschrieben.", "bearbeitet", "Titel geändert", "Anhang hinzugefügt: log.txt"} {
		if !strings.Contains(page, want) {
			t.Errorf("nach Bearbeitung fehlt %q", want)
		}
	}

	// Antworten: nur eigene bearbeiten; Moderation darf fremde entfernen
	k1 := w.reply(t, "dave", id, "Bei mir auch, **Version 1.1**")
	k := "/k/" + itoa(k1)
	if code, _, _ := w.c["alice"].post(k+"/bearbeiten", url.Values{"text": {"manipuliert"}}); code != http.StatusForbidden {
		t.Errorf("fremde Antwort bearbeitet: %d", code)
	}
	if code, _, _ := w.c["bob"].post(k+"/bearbeiten", url.Values{"text": {"manipuliert"}}); code != http.StatusForbidden {
		t.Errorf("Entwickler bearbeitet fremden Text: %d", code)
	}
	w.c["dave"].post(k+"/bearbeiten", url.Values{"text": {"Bei mir auch, Version 1.1 und 1.2"}})
	_, page = w.c["alice"].get(r)
	if !strings.Contains(page, "1.1 und 1.2") {
		t.Error("eigene Antwort nicht bearbeitet")
	}
	if code, _, _ := w.c["alice"].post(k+"/loeschen", url.Values{}); code != http.StatusForbidden {
		t.Errorf("Autorin löscht fremde Antwort: %d", code)
	}
	k2 := w.reply(t, "eve", id, "Werbung!!!")
	w.c["bob"].post("/k/"+itoa(k2)+"/loeschen", url.Values{})
	_, page = w.c["alice"].get(r)
	if strings.Contains(page, "Werbung!!!") || !strings.Contains(page, "von der Moderation entfernt") {
		t.Error("Moderation hat Antwort nicht entfernt")
	}

	// Antwort mit Anhang löschen → Datei verschwindet
	w.c["dave"].postMultipart(r+"/kommentar", map[string]string{"text": "Screenshot"}, "bild.png", []byte("\x89PNG\r\n\x1a\nxxxx"))
	var aid int64
	var storage string
	w.app.db.QueryRow(`SELECT id, storage_name FROM attachments WHERE filename = 'bild.png'`).Scan(&aid, &storage)
	var cid int64
	w.app.db.QueryRow(`SELECT comment_id FROM attachments WHERE id = ?`, aid).Scan(&cid)
	w.c["dave"].post("/k/"+itoa(cid)+"/loeschen", url.Values{})
	if _, err := os.Stat(filepath.Join(w.app.attachDir, storage)); !os.IsNotExist(err) {
		t.Error("Anhang einer gelöschten Antwort liegt noch auf der Platte")
	}

	// Einzelner Anhang: nur Hochladende oder Entwickler
	w.app.db.QueryRow(`SELECT id, storage_name FROM attachments WHERE filename = 'log.txt'`).Scan(&aid, &storage)
	if code, _, _ := w.c["dave"].post("/anhang/"+itoa(aid)+"/entfernen", url.Values{}); code != http.StatusForbidden {
		t.Errorf("Fremder entfernt Anhang: %d", code)
	}
	w.c["alice"].post("/anhang/"+itoa(aid)+"/entfernen", url.Values{})
	if _, err := os.Stat(filepath.Join(w.app.attachDir, storage)); !os.IsNotExist(err) {
		t.Error("entfernter Anhang liegt noch auf der Platte")
	}

	// Autorin darf zurückziehen, solange niemand sonst beteiligt ist
	solo := w.report(t, "alice", 1, "feature", "Idee, die ich zurückziehe", "Doch keine gute Idee gewesen.")
	if code, _, _ := w.c["alice"].post("/r/"+itoa(solo)+"/loeschen", url.Values{}); code != http.StatusSeeOther {
		t.Errorf("Autorin zieht eigene Meldung zurück: %d", code)
	}
	if code, _, _ := w.c["alice"].post(r+"/loeschen", url.Values{}); code != http.StatusForbidden {
		t.Errorf("Autorin löscht Meldung mit fremden Antworten: %d", code)
	}
}

func TestDuplikate(t *testing.T) {
	w := newWorld(t, nil)
	orig := w.report(t, "alice", 1, "bug", "PDF-Export liefert leere Seiten", "Export erzeugt nur weiße Seiten.")
	dup := w.report(t, "dave", 1, "bug", "Exportiertes PDF ist leer", "Das PDF hat keinen Inhalt.")
	dup2 := w.report(t, "eve", 1, "bug", "Leeres PDF beim Export", "Nur leere Seiten.")
	other := w.report(t, "alice", 2, "bug", "Anderes Programm", "Gehört nicht dazu.")
	w.c["carol"].post("/r/"+itoa(dup)+"/vote", url.Values{})  // carol + dave unterstützen dup
	w.c["alice"].post("/r/"+itoa(dup2)+"/vote", url.Values{}) // alice unterstützt dup2 (hat orig schon)
	w.c["bob"].post("/r/"+itoa(dup2)+"/folgen", url.Values{})

	// Ungültige Ziele
	for ref, want := range map[string]string{"": "Nummer der Original", "#" + itoa(dup): "von sich selbst", "#" + itoa(other): "gehört nicht zu", "#999": "gibt es nicht"} {
		manage(w.c["bob"], dup, url.Values{"status": {"duplicate"}, "duplikat": {ref}})
		_, page := w.c["bob"].get("/")
		_ = page
		var st string
		w.app.db.QueryRow(`SELECT status FROM reports WHERE id = ?`, dup).Scan(&st)
		if st == "duplicate" {
			t.Errorf("Ziel %q akzeptiert (erwartet: %s)", ref, want)
		}
	}

	// dup2 → dup, dann dup → orig: Kette wird auf orig umgehängt
	manage(w.c["bob"], dup2, url.Values{"status": {"duplicate"}, "duplikat": {"#" + itoa(dup)}})
	_, page := manage(w.c["bob"], dup, url.Values{"status": {"duplicate"}, "duplikat": {itoa(orig)}})
	var d1, d2 int64
	w.app.db.QueryRow(`SELECT duplicate_of FROM reports WHERE id = ?`, dup).Scan(&d1)
	w.app.db.QueryRow(`SELECT duplicate_of FROM reports WHERE id = ?`, dup2).Scan(&d2)
	if d1 != orig || d2 != orig {
		t.Errorf("Verknüpfung: dup→%d dup2→%d, erwartet %d", d1, d2, orig)
	}
	if !strings.Contains(page, "Duplikat.") || !strings.Contains(page, "PDF-Export liefert leere Seiten") {
		t.Error("Hinweis auf Original fehlt auf der Duplikat-Seite")
	}

	// Stimmen: orig hatte alice; dazu dave, carol (von dup) und eve (dup2 → dup → orig). Keine Doppelzählung.
	var score int
	w.app.db.QueryRow(`SELECT score FROM reports WHERE id = ?`, orig).Scan(&score)
	if score != 4 {
		t.Errorf("Stimmen im Original: %d, erwartet 4 (alice, dave, carol, eve)", score)
	}
	if !w.app.isFollowing(orig, 2+1) { // bob (id 3) folgte dup2
		t.Error("Folgende wurden nicht übernommen")
	}
	_, page = w.c["dave"].get("/r/" + itoa(orig))
	if !strings.Contains(page, "Zusammengeführte Duplikate") || !strings.Contains(page, "Exportiertes PDF ist leer") || !strings.Contains(page, "als Duplikat hierher zusammengeführt") {
		t.Error("Original zeigt Duplikate nicht")
	}

	// Abstimmen auf Duplikat abgelehnt, Duplikatsfinder schlägt nur das Original vor
	if code, _, _ := w.c["eve"].post("/r/"+itoa(dup)+"/vote", url.Values{}); code != http.StatusBadRequest {
		t.Errorf("Vote auf Duplikat: %d", code)
	}
	hits, _ := w.app.findSimilar(nil, 1, "PDF Export leer", 5, 0)
	for _, h := range hits {
		if h.ID == dup || h.ID == dup2 {
			t.Errorf("Duplikat #%d vorgeschlagen", h.ID)
		}
	}

	// Aufheben
	manage(w.c["bob"], dup, url.Values{"status": {"open"}})
	w.app.db.QueryRow(`SELECT COALESCE(duplicate_of, 0) FROM reports WHERE id = ?`, dup).Scan(&d1)
	if d1 != 0 {
		t.Error("Verknüpfung nicht aufgehoben")
	}
}

func TestLabelsZustaendigkeitBehobenIn(t *testing.T) {
	w := newWorld(t, nil)
	id := w.report(t, "alice", 1, "bug", "Druckansicht abgeschnitten", "Rechter Rand fehlt.")
	other := w.report(t, "alice", 1, "bug", "Etwas anderes", "Ganz anderes Problem.")

	// Labels anlegen: Entwickler ja, Fremde und Entwickler anderer Software nein
	if code, _, _ := w.c["bob"].post("/s/portal/labels", url.Values{"name": {"Oberfläche"}, "farbe": {"6"}}); code != http.StatusSeeOther {
		t.Fatalf("Entwickler legt Label an: %d", code)
	}
	w.c["bob"].post("/s/portal/labels", url.Values{"name": {"Druck"}, "farbe": {"4"}})
	w.c["eve"].post("/s/anderes/labels", url.Values{"name": {"Fremd"}})
	for _, n := range []string{"dave", "eve"} {
		if code, _, _ := w.c[n].post("/s/portal/labels", url.Values{"name": {"Hack"}}); code != http.StatusForbidden {
			t.Errorf("%s legt Label an: %d", n, code)
		}
		if code, _ := w.c[n].get("/s/portal/einstellungen"); code != http.StatusForbidden {
			t.Errorf("%s öffnet Einstellungen: %d", n, code)
		}
	}
	var lOber, lDruck, lFremd int64
	w.app.db.QueryRow(`SELECT id FROM labels WHERE name = 'Oberfläche'`).Scan(&lOber)
	w.app.db.QueryRow(`SELECT id FROM labels WHERE name = 'Druck'`).Scan(&lDruck)
	w.app.db.QueryRow(`SELECT id FROM labels WHERE name = 'Fremd'`).Scan(&lFremd)

	// Vergeben, zuweisen, behoben in. Fremdes Label wird ignoriert, Zuweisung an Nicht-Entwickler abgelehnt.
	_, page := manage(w.c["bob"], id, url.Values{"status": {"fixed"}, "labels": {itoa(lOber), itoa(lDruck), itoa(lFremd)}, "zustaendig": {"4"}, "behoben_in": {"2.4.2"}})
	for _, want := range []string{"Oberfläche", "Druck", "Behoben in", "2.4.2", "Labels hinzugefügt: Druck, Oberfläche"} {
		if !strings.Contains(page, want) {
			t.Errorf("Detailseite: fehlt %q", want)
		}
	}
	if strings.Contains(page, ">Fremd<") {
		t.Error("Label einer anderen Software vergeben")
	}
	var asg int64
	w.app.db.QueryRow(`SELECT assignee_id FROM reports WHERE id = ?`, id).Scan(&asg)
	if asg != 4 {
		t.Errorf("Zuständig: %d", asg)
	}
	manage(w.c["bob"], other, url.Values{"zustaendig": {"5"}}) // dave ist kein Entwickler
	w.app.db.QueryRow(`SELECT COALESCE(assignee_id, 0) FROM reports WHERE id = ?`, other).Scan(&asg)
	if asg != 0 {
		t.Error("Zuweisung an Nicht-Entwickler akzeptiert")
	}

	// Filter
	_, list := w.c["dave"].get("/s/portal?label=" + itoa(lDruck))
	if !strings.Contains(list, "Druckansicht abgeschnitten") || strings.Contains(list, "Etwas anderes") {
		t.Error("Label-Filter")
	}
	_, list = w.c["carol"].get("/?zugewiesen=1")
	if !strings.Contains(list, "Druckansicht abgeschnitten") || strings.Contains(list, "Etwas anderes") {
		t.Error("Filter „Mir zugewiesen“")
	}

	// Label löschen entfernt es von Meldungen
	w.c["carol"].post("/s/portal/labels/"+itoa(lDruck)+"/loeschen", url.Values{})
	var n int
	w.app.db.QueryRow(`SELECT COUNT(*) FROM report_labels WHERE label_id = ?`, lDruck).Scan(&n)
	if n != 0 {
		t.Error("gelöschtes Label hängt noch an Meldungen")
	}
}

func TestBegrenzung(t *testing.T) {
	w := newWorld(t, func(c *Config) { c.Limits = LimitConfig{ReportsPerHour: 2, RepliesPerHour: 3} })
	id := w.report(t, "alice", 1, "bug", "Erste Meldung hier", "Beschreibung eins.")
	w.report(t, "alice", 1, "bug", "Zweite Meldung hier", "Beschreibung zwei.")
	code, _ := w.c["alice"].postMultipart("/neu", map[string]string{"software": "1", "art": "bug", "titel": "Dritte Meldung hier", "beschreibung": "Beschreibung drei."}, "", nil)
	if code != http.StatusUnprocessableEntity {
		t.Errorf("dritte Meldung pro Stunde: %d", code)
	}
	for i := 0; i < 5; i++ { // Entwickler sind ausgenommen
		w.report(t, "bob", 1, "bug", "Entwickler-Meldung "+itoa(int64(i)), "Interne Aufgabe.")
	}
	for i := 0; i < 3; i++ {
		w.reply(t, "dave", id, "Antwort "+itoa(int64(i)))
	}
	w.c["dave"].postMultipart("/r/"+itoa(id)+"/kommentar", map[string]string{"text": "zu viel"}, "", nil)
	var n int
	w.app.db.QueryRow(`SELECT COUNT(*) FROM comments WHERE author_id = 5 AND is_system = 0`).Scan(&n)
	if n != 3 {
		t.Errorf("Antworten trotz Begrenzung: %d", n)
	}
}

func TestVirenscan(t *testing.T) {
	addr := newFakeClamd(t)
	w := newWorld(t, func(c *Config) { c.ClamAV = ClamAVConfig{Addr: addr, Required: true} })
	eicar := []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)

	// Öffentlich: abgelehnt
	code, _ := w.c["alice"].postMultipart("/neu", map[string]string{"software": "1", "art": "bug", "titel": "Mit Virus im Anhang", "beschreibung": "Bitte ansehen."}, "invoice.exe", eicar)
	if code != http.StatusUnprocessableEntity {
		t.Errorf("Schadsoftware in öffentlicher Meldung: %d", code)
	}
	// Sauber: angenommen und als geprüft markiert
	w.c["alice"].postMultipart("/neu", map[string]string{"software": "1", "art": "bug", "titel": "Mit sauberem Anhang", "beschreibung": "Log anbei."}, "log.txt", []byte("alles gut"))
	var scan string
	w.app.db.QueryRow(`SELECT scan FROM attachments WHERE filename = 'log.txt'`).Scan(&scan)
	if scan != "clean" {
		t.Errorf("Scan-Ergebnis sauber: %q", scan)
	}
	// Vertraulich: Exploit angenommen, markiert, nie inline
	code, _ = w.c["alice"].postMultipart("/neu", map[string]string{"software": "1", "art": "security", "titel": "RCE mit Proof of Concept", "beschreibung": "PoC anbei."}, "poc.png", eicar)
	if code != http.StatusSeeOther {
		t.Fatalf("PoC in Sicherheitsmeldung: %d", code)
	}
	var aid, rid int64
	w.app.db.QueryRow(`SELECT id, report_id, scan FROM attachments WHERE filename = 'poc.png'`).Scan(&aid, &rid, &scan)
	if scan != "FOUND:Eicar-Test-Signature" {
		t.Errorf("Markierung: %q", scan)
	}
	res, _ := w.c["bob"].c.Get(w.srv.URL + "/anhang/" + itoa(aid) + "/poc.png")
	res.Body.Close()
	if !strings.HasPrefix(res.Header.Get("Content-Disposition"), "attachment") || res.Header.Get("Content-Type") != "application/octet-stream" {
		t.Errorf("erkannte Datei wird inline ausgeliefert: %s", res.Header.Get("Content-Disposition"))
	}
	_, page := w.c["bob"].get("/r/" + itoa(rid))
	if !strings.Contains(page, "Schadsoftware erkannt") {
		t.Error("Warnhinweis fehlt")
	}
	// Scanner weg + Pflicht → Upload abgelehnt, ohne Anhang aber möglich
	w.app.scanner = &clamd{cfg: ClamAVConfig{Addr: "tcp://127.0.0.1:1"}}
	code, _ = w.c["alice"].postMultipart("/neu", map[string]string{"software": "1", "art": "bug", "titel": "Scanner ist weg", "beschreibung": "Mit Anhang."}, "a.txt", []byte("x"))
	if code != http.StatusUnprocessableEntity {
		t.Errorf("Upload trotz fehlendem Scanner: %d", code)
	}
	w.report(t, "alice", 1, "bug", "Ohne Anhang geht es", "Kein Anhang dabei.")
}

func TestSicherungUndWiederherstellung(t *testing.T) {
	w := newWorld(t, nil)
	w.c["alice"].postMultipart("/neu", map[string]string{"software": "1", "art": "bug", "titel": "Meldung mit Anhang", "beschreibung": "Bitte sichern."}, "daten.txt", []byte("wichtig"))
	w.reply(t, "bob", 1, "Antwort, die erhalten bleiben muss")

	out := filepath.Join(t.TempDir(), "sicherung.tar.gz")
	n, err := writeBackup(context.Background(), w.app.cfg, out)
	if err != nil || n != 1 {
		t.Fatalf("Sicherung: %v (%d Anhänge)", err, n)
	}

	cfg := w.app.cfg
	cfg.DataDir = t.TempDir()
	if err := restoreCmd(cfg, []string{"-in", out}); err != nil {
		t.Fatalf("Wiederherstellung: %v", err)
	}
	if err := restoreCmd(cfg, []string{"-in", out}); err == nil {
		t.Error("Überschreiben ohne -force erlaubt")
	}
	db, err := openDB(dbPath(cfg))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var reports, comments int
	var storage string
	db.QueryRow(`SELECT COUNT(*) FROM reports`).Scan(&reports)
	db.QueryRow(`SELECT COUNT(*) FROM comments WHERE body LIKE '%erhalten bleiben%'`).Scan(&comments)
	db.QueryRow(`SELECT storage_name FROM attachments WHERE filename = 'daten.txt'`).Scan(&storage)
	if reports != 1 || comments != 1 {
		t.Errorf("wiederhergestellt: %d Meldungen, %d Antworten", reports, comments)
	}
	if b, err := os.ReadFile(filepath.Join(cfg.DataDir, "anhaenge", storage)); err != nil || string(b) != "wichtig" {
		t.Errorf("Anhang nicht wiederhergestellt: %v", err)
	}

	// Manipuliertes Archiv mit Pfad-Trick wird abgelehnt
	evil := filepath.Join(t.TempDir(), "boese.tar.gz")
	f, _ := os.Create(evil)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "../../etc/passwd", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
	tw.Write([]byte("x"))
	tw.Close()
	gz.Close()
	f.Close()
	cfg.DataDir = t.TempDir()
	if err := restoreCmd(cfg, []string{"-in", evil}); err == nil || !strings.Contains(err.Error(), "unerwarteter Eintrag") {
		t.Errorf("Pfad-Trick nicht abgelehnt: %v", err)
	}
}

// mimeDecoder dekodiert RFC-2047-Betreffzeilen.
type mimeDecoder struct{}

func (mimeDecoder) decode(s string) (string, error) {
	return new(mime.WordDecoder).DecodeHeader(s)
}

func TestBegrenzungAbschaltbar(t *testing.T) {
	t.Setenv("MS_LIMIT_REPORTS_PER_HOUR", "0")
	t.Setenv("MS_LIMIT_REPLIES_PER_HOUR", "")
	c := loadConfig()
	if c.Limits.ReportsPerHour != 0 || c.Limits.RepliesPerHour != 60 {
		t.Errorf("Begrenzung: %+v", c.Limits)
	}
}
