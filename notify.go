package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Benachrichtigungen per E-Mail.
//
// Ereignisse landen in der Tabelle outbox; ein Hintergrund-Worker versendet sie mit Wiederholungen.
// So blockiert ein langsamer oder ausgefallener Mailserver nie eine Anfrage.
// Inhalte vertraulicher Meldungen (auch der Titel) stehen NIE in einer E-Mail.

type SMTPConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	From     string
	TLS      string // starttls | tls | none
}

func (s SMTPConfig) Enabled() bool { return s.Host != "" && s.From != "" }

func loadSMTPConfig() SMTPConfig {
	c := SMTPConfig{
		Host:     getenv("MS_SMTP_HOST", ""),
		Port:     getint("MS_SMTP_PORT", 587),
		User:     getenv("MS_SMTP_USER", ""),
		Password: secret("MS_SMTP_PASSWORD"),
		From:     getenv("MS_SMTP_FROM", ""),
		TLS:      strings.ToLower(getenv("MS_SMTP_TLS", "starttls")),
	}
	if c.TLS != "tls" && c.TLS != "none" {
		c.TLS = "starttls"
	}
	return c
}

// ---------- Versand ----------

type mailer interface {
	Send(ctx context.Context, to, subject, body, thread string) error
}

type smtpMailer struct {
	cfg  SMTPConfig
	from *mail.Address
	host string // für Message-IDs
}

func newSMTPMailer(cfg SMTPConfig, baseURL string) (*smtpMailer, error) {
	from, err := mail.ParseAddress(cfg.From)
	if err != nil {
		return nil, fmt.Errorf("MS_SMTP_FROM ist keine gültige Adresse: %w", err)
	}
	host := "meldestelle.local"
	if u, err := url.Parse(baseURL); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	if cfg.TLS == "none" && cfg.User != "" {
		slog.Warn("SMTP-Anmeldung ohne TLS: Zugangsdaten werden im Klartext übertragen")
	}
	return &smtpMailer{cfg: cfg, from: from, host: host}, nil
}

func buildMessage(from *mail.Address, to, subject, body, thread, host string) []byte {
	var b bytes.Buffer
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", from.String())
	h("To", to)
	h("Subject", mime.QEncoding.Encode("utf-8", subject))
	h("Date", time.Now().Format(time.RFC1123Z))
	h("Message-ID", "<"+randToken(18)+"@"+host+">")
	if thread != "" {
		ref := "<" + thread + "@" + host + ">"
		h("In-Reply-To", ref)
		h("References", ref)
	}
	h("MIME-Version", "1.0")
	h("Content-Type", "text/plain; charset=utf-8")
	h("Content-Transfer-Encoding", "quoted-printable")
	h("Auto-Submitted", "auto-generated")
	h("X-Auto-Response-Suppress", "All")
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	qp.Write([]byte(strings.ReplaceAll(body, "\n", "\r\n")))
	qp.Close()
	return b.Bytes()
}

func (m *smtpMailer) Send(ctx context.Context, to, subject, body, thread string) error {
	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))
	tlsCfg := &tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12}
	d := &net.Dialer{Timeout: 20 * time.Second}

	var conn net.Conn
	var err error
	if m.cfg.TLS == "tls" {
		conn, err = tls.DialWithDialer(d, "tcp", addr, tlsCfg)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if err := c.Hello(m.host); err != nil {
		return err
	}
	if m.cfg.TLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("Server bietet kein STARTTLS an (MS_SMTP_TLS=none, falls gewollt)")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	if m.cfg.User != "" {
		if err := c.Auth(smtp.PlainAuth("", m.cfg.User, m.cfg.Password, m.cfg.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(m.from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(buildMessage(m.from, to, subject, body, thread, m.host)); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// ---------- Warteschlange ----------

var retryDelays = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 6 * time.Hour, 12 * time.Hour}

func (a *App) enqueueMail(to, subject, body, thread string) {
	if a.mailer == nil {
		return
	}
	addr, err := mail.ParseAddress(to)
	if err != nil || strings.ContainsAny(addr.Address, "\r\n") {
		return
	}
	if _, err := a.db.Exec(`INSERT INTO outbox (recipient, subject, body, thread, next_try, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		addr.Address, cleanLine(subject, 250), body, thread, now(), now()); err != nil {
		slog.Error("E-Mail einreihen", "err", err)
		return
	}
	select {
	case a.mailKick <- struct{}{}:
	default:
	}
}

func (a *App) mailWorker(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		a.flushOutbox(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.mailKick:
		}
	}
}

func (a *App) flushOutbox(ctx context.Context) {
	type job struct {
		id                        int64
		to, subject, body, thread string
		attempts                  int
	}
	rows, err := a.db.QueryContext(ctx, `SELECT id, recipient, subject, body, thread, attempts FROM outbox
		WHERE sent_at = 0 AND next_try <= ? ORDER BY id LIMIT 25`, now())
	if err != nil {
		return
	}
	var jobs []job
	for rows.Next() {
		var j job
		if rows.Scan(&j.id, &j.to, &j.subject, &j.body, &j.thread, &j.attempts) == nil {
			jobs = append(jobs, j)
		}
	}
	rows.Close()
	for _, j := range jobs {
		err := a.mailer.Send(ctx, j.to, j.subject, j.body, j.thread)
		if err == nil {
			a.db.Exec(`UPDATE outbox SET sent_at = ?, last_error = '' WHERE id = ?`, now(), j.id)
			continue
		}
		slog.Warn("E-Mail-Versand fehlgeschlagen", "an", j.to, "versuch", j.attempts+1, "err", err)
		if j.attempts+1 >= len(retryDelays)+1 {
			a.db.Exec(`UPDATE outbox SET attempts = attempts + 1, sent_at = -1, last_error = ? WHERE id = ?`, cleanLine(err.Error(), 500), j.id)
			continue
		}
		a.db.Exec(`UPDATE outbox SET attempts = attempts + 1, next_try = ?, last_error = ? WHERE id = ?`,
			time.Now().Add(retryDelays[j.attempts]).Unix(), cleanLine(err.Error(), 500), j.id)
	}
}

type mailStats struct {
	Enabled         bool
	Pending, Failed int
	LastError       string
}

func (a *App) mailStatus() mailStats {
	st := mailStats{Enabled: a.mailer != nil}
	a.db.QueryRow(`SELECT COUNT(*) FROM outbox WHERE sent_at = 0`).Scan(&st.Pending)
	a.db.QueryRow(`SELECT COUNT(*) FROM outbox WHERE sent_at = -1`).Scan(&st.Failed)
	a.db.QueryRow(`SELECT last_error FROM outbox WHERE last_error <> '' ORDER BY id DESC LIMIT 1`).Scan(&st.LastError)
	return st
}

// ---------- Folgen ----------

func (a *App) follow(reportID, userID int64) {
	a.db.Exec(`INSERT OR IGNORE INTO follows (report_id, user_id, created_at) VALUES (?, ?, ?)`, reportID, userID, now())
}

func (a *App) isFollowing(reportID, userID int64) bool {
	var ok bool
	a.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM follows WHERE report_id = ? AND user_id = ?)`, reportID, userID).Scan(&ok)
	return ok
}

func (a *App) handleFollow(w http.ResponseWriter, r *http.Request) {
	rep, ok := a.loadVisibleReport(w, r)
	if !ok {
		return
	}
	u := currentUser(r)
	following := !a.isFollowing(rep.ID, u.ID)
	if following {
		a.follow(rep.ID, u.ID)
	} else {
		a.db.Exec(`DELETE FROM follows WHERE report_id = ? AND user_id = ?`, rep.ID, u.ID)
	}
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]any{"following": following})
		return
	}
	if following {
		a.flash(w, "ok", "Du folgst dieser Meldung und wirst über Antworten und Änderungen informiert.")
	} else {
		a.flash(w, "info", "Du folgst dieser Meldung nicht mehr.")
	}
	redirect(w, r, "/r/"+itoa(rep.ID))
}

// ---------- Ereignisse ----------

type recipient struct {
	id    int64
	email string
}

func (a *App) recipients(query string, args ...any) []recipient {
	rows, err := a.db.Query(query, args...)
	if err != nil {
		slog.Error("Empfänger ermitteln", "err", err)
		return nil
	}
	defer rows.Close()
	var out []recipient
	for rows.Next() {
		var r recipient
		if rows.Scan(&r.id, &r.email) == nil && r.email != "" {
			out = append(out, r)
		}
	}
	return out
}

func (a *App) reportURL(id int64, anchor string) string {
	u := a.cfg.BaseURL + "/r/" + itoa(id)
	if anchor != "" {
		u += "#" + anchor
	}
	return u
}

func mailSubject(app string, rep *Report) string {
	if rep.Confidential {
		return fmt.Sprintf("[%s] #%d Vertrauliche Meldung zu %s", app, rep.ID, rep.SoftwareName)
	}
	return fmt.Sprintf("[%s] #%d %s", app, rep.ID, rep.Title)
}

func confidentialNote(rep *Report) string {
	return "Die Meldung ist vertraulich. Aus Sicherheitsgründen stehen Titel und Inhalt nicht in dieser E-Mail.\n"
}

func mailFooter(a *App, reason string) string {
	return "\n-- \n" + reason + "\nBenachrichtigungen einstellen: " + a.cfg.BaseURL + "/konto\n"
}

func excerptText(s string, n int) string {
	s = plainText(s)
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + " …"
	}
	return s
}

// notifyNewReport informiert die Entwickler der Software über eine neue Meldung.
func (a *App) notifyNewReport(rep *Report) {
	if a.mailer == nil {
		return
	}
	rcpts := a.recipients(`SELECT u.id, u.email FROM developers d JOIN users u ON u.id = d.user_id
		WHERE d.software_id = ? AND u.notify_new = 1 AND u.disabled = 0 AND u.id <> ?`, rep.SoftwareID, rep.AuthorID)
	var b strings.Builder
	fmt.Fprintf(&b, "Neue Meldung (%s) zu %s von %s:\n\n", label(kinds, rep.Kind), rep.SoftwareName, rep.AuthorName)
	if rep.Confidential {
		b.WriteString(confidentialNote(rep))
	} else {
		fmt.Fprintf(&b, "%s\n\n%s\n", rep.Title, excerptText(rep.Body, 1200))
	}
	fmt.Fprintf(&b, "\nAnsehen: %s\n", a.reportURL(rep.ID, ""))
	body := b.String() + mailFooter(a, "Du erhältst diese E-Mail als Entwickler von "+rep.SoftwareName+".")
	for _, r := range rcpts {
		a.enqueueMail(r.email, mailSubject(a.cfg.AppName, rep), body, "meldung-"+itoa(rep.ID))
	}
}

// notifyFollowers informiert alle Folgenden (außer dem Auslöser und ausgeschlossenen Nutzern).
// Bei vertraulichen Meldungen nur, wer die Meldung auch sehen darf.
func (a *App) notifyFollowers(rep *Report, actor *User, headline, text, anchor string, exclude ...int64) {
	if a.mailer == nil {
		return
	}
	skip := map[int64]bool{actor.ID: true}
	for _, id := range exclude {
		skip[id] = true
	}
	rcpts := a.recipients(`SELECT u.id, u.email FROM follows f JOIN users u ON u.id = f.user_id
		WHERE f.report_id = ? AND u.notify_follow = 1 AND u.disabled = 0`, rep.ID)
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", headline)
	if rep.Confidential {
		b.WriteString(confidentialNote(rep))
	} else if text != "" {
		fmt.Fprintf(&b, "%s\n", excerptText(text, 2000))
	}
	fmt.Fprintf(&b, "\nAnsehen: %s\n", a.reportURL(rep.ID, anchor))
	body := b.String() + mailFooter(a, "Du erhältst diese E-Mail, weil du Meldung #"+itoa(rep.ID)+" folgst. Auf der Meldung kannst du „Nicht mehr folgen“ wählen.")
	for _, r := range rcpts {
		if skip[r.id] {
			continue
		}
		if rep.Confidential {
			u, err := a.userByID(r.id)
			if err != nil || !a.canView(u, rep) {
				continue
			}
		}
		a.enqueueMail(r.email, mailSubject(a.cfg.AppName, rep), body, "meldung-"+itoa(rep.ID))
	}
}

func (a *App) notifyAssigned(rep *Report, assignee int64, actor *User) {
	if a.mailer == nil || assignee == actor.ID {
		return
	}
	rcpts := a.recipients(`SELECT id, email FROM users WHERE id = ? AND notify_assign = 1 AND disabled = 0`, assignee)
	body := fmt.Sprintf("%s hat dir Meldung #%d zu %s zugewiesen.\n\n", actor.Name(), rep.ID, rep.SoftwareName)
	if rep.Confidential {
		body += confidentialNote(rep)
	} else {
		body += rep.Title + "\n"
	}
	body += "\nAnsehen: " + a.reportURL(rep.ID, "") + "\n" + mailFooter(a, "Du erhältst diese E-Mail, weil dir eine Meldung zugewiesen wurde.")
	for _, r := range rcpts {
		a.enqueueMail(r.email, mailSubject(a.cfg.AppName, rep), body, "meldung-"+itoa(rep.ID))
	}
}

// ---------- Konto-Einstellungen & Testmail ----------

func (a *App) notifyPrefs(userID int64) (newR, follow, assign bool) {
	a.db.QueryRow(`SELECT notify_new, notify_follow, notify_assign FROM users WHERE id = ?`, userID).Scan(&newR, &follow, &assign)
	return
}

func (a *App) handleTestMail(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if a.mailer == nil {
		a.flash(w, "error", "E-Mail-Versand ist nicht konfiguriert (MS_SMTP_HOST und MS_SMTP_FROM).")
	} else if u.Email == "" {
		a.flash(w, "error", "In deinem Konto ist keine E-Mail-Adresse hinterlegt.")
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		err := a.mailer.Send(ctx, u.Email, "["+a.cfg.AppName+"] Testnachricht",
			"Der E-Mail-Versand der "+a.cfg.AppName+" funktioniert.\n\n"+a.cfg.BaseURL+"\n", "")
		if err != nil {
			a.flash(w, "error", "Testmail fehlgeschlagen: "+cleanLine(err.Error(), 300))
		} else {
			a.flash(w, "ok", "Testmail an "+u.Email+" verschickt.")
		}
	}
	redirect(w, r, "/admin#betrieb")
}
