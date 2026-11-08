package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// ---------- Liste ----------

type link struct {
	Label  string
	URL    string
	Active bool
}

type listPage struct {
	Software    *Software
	SoftwareID  int64
	Developers  []string
	Softwares   []Software
	Reports     []Report
	Filter      listFilter
	BasePath    string
	Self        string
	KindLinks   []link
	SortLinks   []link
	Statuses    []option
	Page        int
	PrevURL     string
	NextURL     string
	Labels      []Label // Labels der gewählten Software (Filter)
	ActiveLabel *Label
	IsDev       bool // Entwickler dieser Software bzw. irgendeiner Software
	CanSettings bool
}

func (f listFilter) values(page int) url.Values {
	v := url.Values{}
	if f.Kind != "" {
		v.Set("art", f.Kind)
	}
	if f.Status != "" {
		v.Set("status", f.Status)
	}
	if f.Query != "" {
		v.Set("q", f.Query)
	}
	if f.Sort != "" && f.Sort != "hot" {
		v.Set("sort", f.Sort)
	}
	if f.Mine {
		v.Set("meine", "1")
	}
	if f.Assigned {
		v.Set("zugewiesen", "1")
	}
	if f.Label != 0 {
		v.Set("label", strconv.FormatInt(f.Label, 10))
	}
	if page > 1 {
		v.Set("seite", strconv.Itoa(page))
	}
	return v
}

func buildURL(base string, v url.Values) string {
	if q := v.Encode(); q != "" {
		return base + "?" + q
	}
	return base
}

func (a *App) handleList(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	q := r.URL.Query()
	p := listPage{BasePath: "/", Statuses: statuses}

	if slug := r.PathValue("slug"); slug != "" {
		sw, err := a.softwareBy("slug", slug)
		if notFoundErr(err) {
			a.notFound(w, r)
			return
		} else if err != nil {
			a.serverError(w, r, err)
			return
		}
		p.Software, p.SoftwareID, p.BasePath = sw, sw.ID, "/s/"+sw.Slug
		devs, err := a.developersOf(sw.ID)
		if err != nil {
			a.serverError(w, r, err)
			return
		}
		for _, d := range devs {
			p.Developers = append(p.Developers, d.Name)
		}
	}

	f := listFilter{SoftwareID: p.SoftwareID, Query: cleanLine(q.Get("q"), 100), Sort: q.Get("sort"), Mine: q.Get("meine") == "1" && u != nil}
	if valid(kinds, q.Get("art")) {
		f.Kind = q.Get("art")
	}
	if valid(statuses, q.Get("status")) {
		f.Status = q.Get("status")
	}
	f.Assigned = q.Get("zugewiesen") == "1" && u != nil
	if id := parseID(q.Get("label")); id != 0 {
		var l Label
		if a.db.QueryRow(`SELECT id, software_id, name, color FROM labels WHERE id = ?`, id).Scan(&l.ID, &l.SoftwareID, &l.Name, &l.Color) == nil {
			f.Label, p.ActiveLabel = l.ID, &l
		}
	}
	if p.Software != nil {
		p.Labels, _ = a.labelsFor(p.Software.ID)
		p.CanSettings = a.canManageSoftware(u, p.Software.ID)
		p.IsDev = p.CanSettings
	} else {
		p.IsDev = u != nil && (u.IsAdmin || a.isAnyDeveloper(u.ID))
	}
	if f.Sort != "top" && f.Sort != "neu" {
		f.Sort = "hot"
	}
	page, _ := strconv.Atoi(q.Get("seite"))
	if page < 1 || page > 10000 {
		page = 1
	}
	p.Filter, p.Page = f, page

	reports, more, err := a.queryReports(u, f, page)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	p.Reports = reports
	if err := a.attachLabels(p.Reports); err != nil {
		a.serverError(w, r, err)
		return
	}
	if p.Softwares, err = a.listSoftware(false); err != nil {
		a.serverError(w, r, err)
		return
	}

	p.Self = buildURL(p.BasePath, f.values(page))
	if page > 1 {
		p.PrevURL = buildURL(p.BasePath, f.values(page-1))
	}
	if more {
		p.NextURL = buildURL(p.BasePath, f.values(page+1))
	}

	showSecurity := u != nil && (u.IsAdmin || a.isAnyDeveloper(u.ID))
	kf := f
	kf.Kind = ""
	p.KindLinks = append(p.KindLinks, link{"Alle", buildURL(p.BasePath, kf.values(1)), f.Kind == ""})
	for _, k := range kinds {
		if k.Value == "security" && !showSecurity && f.Kind != "security" {
			continue
		}
		kf.Kind = k.Value
		p.KindLinks = append(p.KindLinks, link{k.Label, buildURL(p.BasePath, kf.values(1)), f.Kind == k.Value})
	}
	for _, s := range []option{{"hot", "Beliebt"}, {"top", "Meiste Stimmen"}, {"neu", "Neueste"}} {
		sf := f
		sf.Sort = s.Value
		p.SortLinks = append(p.SortLinks, link{s.Label, buildURL(p.BasePath, sf.values(1)), f.Sort == s.Value})
	}

	title := "Meldungen"
	if p.Software != nil {
		title = p.Software.Name
	}
	a.render(w, r, http.StatusOK, "list.html", title, p)
}

// ---------- Neue Meldung ----------

type newPage struct {
	Softwares []Software
	Values    map[string]string
	Errors    []string
	MaxFiles  int
	MaxBytes  int64
}

func (a *App) handleNewForm(w http.ResponseWriter, r *http.Request) {
	list, err := a.listSoftware(false)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	vals := map[string]string{"art": "bug"}
	if slug := r.URL.Query().Get("software"); slug != "" {
		for _, s := range list {
			if s.Slug == slug {
				vals["software"] = itoa(s.ID)
			}
		}
	}
	if valid(kinds, r.URL.Query().Get("art")) {
		vals["art"] = r.URL.Query().Get("art")
	}
	a.render(w, r, http.StatusOK, "new.html", "Neue Meldung", newPage{Softwares: list, Values: vals, MaxFiles: a.cfg.MaxFiles, MaxBytes: a.cfg.MaxUploadBytes})
}

func (a *App) handleCreate(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	vals := map[string]string{
		"software":     r.PostFormValue("software"),
		"art":          r.PostFormValue("art"),
		"titel":        cleanLine(r.PostFormValue("titel"), 200),
		"version":      cleanLine(r.PostFormValue("version"), 60),
		"beschreibung": strings.TrimSpace(r.PostFormValue("beschreibung")),
	}
	var errs []string
	if over, max := a.overLimit(u, "report"); over {
		errs = append(errs, fmt.Sprintf("Du hast in der letzten Stunde bereits %d Meldungen erstellt. Bitte warte etwas, bevor du die nächste abschickst.", max))
	}
	sw, err := a.softwareBy("id", parseID(vals["software"]))
	if err != nil {
		errs = append(errs, "Bitte wähle eine Software aus.")
	}
	if !valid(kinds, vals["art"]) {
		errs = append(errs, "Bitte wähle die Art der Meldung.")
	}
	if len([]rune(vals["titel"])) < 5 {
		errs = append(errs, "Der Titel braucht mindestens 5 Zeichen.")
	}
	if n := len([]rune(vals["beschreibung"])); n < 10 || n > 50000 {
		errs = append(errs, "Die Beschreibung braucht 10 bis 50.000 Zeichen.")
	}
	files := uploadedFiles(r)
	if msg := a.validateFiles(files); msg != "" {
		errs = append(errs, msg)
	}
	confidential := vals["art"] == "security"
	var scans []string
	if len(errs) == 0 {
		var msg string
		if scans, msg = a.scanUploads(r.Context(), files, confidential); msg != "" {
			errs = append(errs, msg)
		}
	}
	if len(errs) > 0 {
		list, _ := a.listSoftware(false)
		a.render(w, r, http.StatusUnprocessableEntity, "new.html", "Neue Meldung",
			newPage{Softwares: list, Values: vals, Errors: errs, MaxFiles: a.cfg.MaxFiles, MaxBytes: a.cfg.MaxUploadBytes})
		return
	}

	score := 1
	if confidential {
		score = 0
	}
	ts := now()
	var saved []string
	var id int64
	err = a.tx(func(tx *sql.Tx) error {
		res, err := tx.Exec(`INSERT INTO reports (software_id, author_id, kind, status, title, body, version, confidential, score, created_at, updated_at)
			VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?)`,
			sw.ID, u.ID, vals["art"], vals["titel"], vals["beschreibung"], vals["version"], confidential, score, ts, ts)
		if err != nil {
			return err
		}
		id, _ = res.LastInsertId()
		if !confidential {
			if _, err := tx.Exec(`INSERT INTO votes (report_id, user_id, created_at) VALUES (?, ?, ?)`, id, u.ID, ts); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`INSERT INTO follows (report_id, user_id, created_at) VALUES (?, ?, ?)`, id, u.ID, ts); err != nil {
			return err
		}
		saved, err = a.storeFiles(tx, id, nil, u.ID, files, scans)
		return err
	})
	if err != nil {
		a.removeFiles(saved)
		a.serverError(w, r, err)
		return
	}
	if rep, err := a.getReport(id, u); err == nil {
		a.notifyNewReport(rep)
	}
	if confidential {
		a.flash(w, "ok", "Danke! Deine Sicherheitsmeldung ist nur für dich und die Entwickler sichtbar.")
	} else {
		a.flash(w, "ok", "Danke für deine Meldung! Du wirst über Antworten und Änderungen informiert.")
	}
	redirect(w, r, "/r/"+itoa(id))
}

// ---------- Detailansicht ----------

type reportPage struct {
	Report      *Report
	Attachments []Attachment
	Replies     []Comment // Nachrichten von Entwicklern und Nutzern
	Events      []Comment // Änderungsverlauf (Audit)
	Developers  []UserRef
	CanManage   bool
	CanEdit     bool
	CanDelete   bool
	Following   bool
	Original    *Report // bei Duplikaten: das Original (nil, falls nicht sichtbar)
	Duplicates  []Report
	SoftLabels  []Label // alle Labels der Software (für Entwickler)
	LabelSet    map[int64]bool
	Statuses    []option
	Kinds       []option
	MaxFiles    int
	MaxBytes    int64
}

// loadVisibleReport liefert 404 für nicht existierende UND nicht sichtbare Meldungen,
// damit sich die Existenz vertraulicher Meldungen nicht erraten lässt.
func (a *App) loadVisibleReport(w http.ResponseWriter, r *http.Request) (*Report, bool) {
	return a.loadVisibleReportID(w, r, parseID(r.PathValue("id")))
}

func (a *App) loadVisibleReportID(w http.ResponseWriter, r *http.Request, id int64) (*Report, bool) {
	u := currentUser(r)
	rep, err := a.getReport(id, u)
	if notFoundErr(err) || (err == nil && !a.canView(u, rep)) {
		a.notFound(w, r)
		return nil, false
	}
	if err != nil {
		a.serverError(w, r, err)
		return nil, false
	}
	return rep, true
}

// canAuthorDelete: Autoren dürfen ihre Meldung zurückziehen, solange sich niemand sonst beteiligt hat.
func (a *App) canAuthorDelete(u *User, rep *Report) bool {
	if u == nil || u.ID != rep.AuthorID {
		return false
	}
	var others int
	a.db.QueryRow(`SELECT COUNT(*) FROM comments WHERE report_id = ? AND is_system = 0 AND deleted_at = 0 AND author_id <> ?`, rep.ID, u.ID).Scan(&others)
	var votes int
	a.db.QueryRow(`SELECT COUNT(*) FROM votes WHERE report_id = ? AND user_id <> ?`, rep.ID, u.ID).Scan(&votes)
	var dups int
	a.db.QueryRow(`SELECT COUNT(*) FROM reports WHERE duplicate_of = ?`, rep.ID).Scan(&dups)
	return others == 0 && votes == 0 && dups == 0
}

func (a *App) handleReport(w http.ResponseWriter, r *http.Request) {
	rep, ok := a.loadVisibleReport(w, r)
	if !ok {
		return
	}
	u := currentUser(r)
	manage := a.canManage(u, rep)
	atts, err := a.attachmentsForReport(rep.ID)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	comments, err := a.commentsForReport(rep.ID)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	devs, err := a.developersOf(rep.SoftwareID)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	devSet := map[int64]bool{}
	for _, d := range devs {
		devSet[d.ID] = true
	}
	byComment := map[int64][]Attachment{}
	var top []Attachment
	for _, at := range atts {
		at.CanRemove = u != nil && (manage || at.UploaderID == u.ID)
		if at.CommentID.Valid {
			byComment[at.CommentID.Int64] = append(byComment[at.CommentID.Int64], at)
		} else {
			top = append(top, at)
		}
	}
	var replies, events []Comment
	for _, c := range comments {
		c.Attachments = byComment[c.ID]
		c.AuthorIsDev = devSet[c.AuthorID]
		if c.IsSystem {
			events = append(events, c)
			continue
		}
		if !c.Deleted() && u != nil {
			c.CanEdit = c.AuthorID == u.ID
			c.CanDelete = c.AuthorID == u.ID || manage
		}
		replies = append(replies, c)
	}
	p := reportPage{
		Report: rep, Attachments: top, Replies: replies, Events: events, Developers: devs,
		CanManage: manage, CanEdit: u != nil && (manage || u.ID == rep.AuthorID),
		CanDelete: manage || a.canAuthorDelete(u, rep),
		Statuses:  statuses, Kinds: kinds, MaxFiles: a.cfg.MaxFiles, MaxBytes: a.cfg.MaxUploadBytes,
	}
	if u != nil {
		p.Following = a.isFollowing(rep.ID, u.ID)
	}
	rep.Labels, _ = a.reportLabels(rep.ID)
	if rep.DuplicateOf != 0 {
		if orig, err := a.getReport(rep.DuplicateOf, u); err == nil && a.canView(u, orig) {
			p.Original = orig
		}
	}
	p.Duplicates, _ = a.visibleDuplicates(u, rep.ID)
	if manage {
		p.SoftLabels, _ = a.labelsFor(rep.SoftwareID)
		p.LabelSet = map[int64]bool{}
		for _, l := range rep.Labels {
			p.LabelSet[l.ID] = true
		}
	}
	a.render(w, r, http.StatusOK, "report.html", rep.Title, p)
}

func (a *App) visibleDuplicates(u *User, id int64) ([]Report, error) {
	args := append([]any{uid(u)}, visibilityArgs(u)...)
	args = append(args, id)
	rows, err := a.db.Query(reportSelect("''")+` WHERE `+visibilitySQL+` AND r.duplicate_of = ? ORDER BY r.created_at`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Report
	for rows.Next() {
		rep, err := scanReport(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rep)
	}
	return out, rows.Err()
}

// ---------- Upvote ----------

func (a *App) handleVote(w http.ResponseWriter, r *http.Request) {
	rep, ok := a.loadVisibleReport(w, r)
	if !ok {
		return
	}
	if rep.Confidential {
		a.errorPage(w, r, http.StatusBadRequest, "Vertrauliche Meldungen können nicht bewertet werden.")
		return
	}
	if rep.DuplicateOf != 0 {
		a.errorPage(w, r, http.StatusBadRequest, fmt.Sprintf("Diese Meldung ist ein Duplikat. Bitte unterstütze stattdessen die Original-Meldung #%d.", rep.DuplicateOf))
		return
	}
	u := currentUser(r)
	var score int
	var voted bool
	err := a.tx(func(tx *sql.Tx) error {
		res, err := tx.Exec(`DELETE FROM votes WHERE report_id = ? AND user_id = ?`, rep.ID, u.ID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			if _, err := tx.Exec(`INSERT INTO votes (report_id, user_id, created_at) VALUES (?, ?, ?)`, rep.ID, u.ID, now()); err != nil {
				return err
			}
			voted = true
		}
		if _, err := tx.Exec(`UPDATE reports SET score = (SELECT COUNT(*) FROM votes WHERE report_id = ?) WHERE id = ?`, rep.ID, rep.ID); err != nil {
			return err
		}
		return tx.QueryRow(`SELECT score FROM reports WHERE id = ?`, rep.ID).Scan(&score)
	})
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]any{"score": score, "voted": voted})
		return
	}
	back := safeNext(r.PostFormValue("zurueck"))
	if back == "/" && r.PostFormValue("zurueck") == "" {
		back = "/r/" + itoa(rep.ID)
	}
	redirect(w, r, back)
}

// ---------- Antworten ----------

func (a *App) handleComment(w http.ResponseWriter, r *http.Request) {
	rep, ok := a.loadVisibleReport(w, r)
	if !ok {
		return
	}
	u := currentUser(r)
	back := "/r/" + itoa(rep.ID) + "#antworten"
	body := strings.TrimSpace(r.PostFormValue("text"))
	files := uploadedFiles(r)
	if body == "" && len(files) == 0 {
		a.flash(w, "error", "Die Antwort ist leer.")
		redirect(w, r, back)
		return
	}
	if len([]rune(body)) > 20000 {
		a.flash(w, "error", "Die Antwort ist zu lang (max. 20.000 Zeichen).")
		redirect(w, r, back)
		return
	}
	if over, max := a.overLimit(u, "reply"); over {
		a.flash(w, "error", fmt.Sprintf("Du hast in der letzten Stunde bereits %d Antworten geschrieben. Bitte warte etwas.", max))
		redirect(w, r, back)
		return
	}
	if msg := a.validateFiles(files); msg != "" {
		a.flash(w, "error", msg)
		redirect(w, r, back)
		return
	}
	scans, msg := a.scanUploads(r.Context(), files, rep.Confidential)
	if msg != "" {
		a.flash(w, "error", msg)
		redirect(w, r, back)
		return
	}
	var saved []string
	var cid int64
	err := a.tx(func(tx *sql.Tx) error {
		ts := now()
		res, err := tx.Exec(`INSERT INTO comments (report_id, author_id, body, created_at) VALUES (?, ?, ?, ?)`, rep.ID, u.ID, body, ts)
		if err != nil {
			return err
		}
		cid, _ = res.LastInsertId()
		if _, err := tx.Exec(`UPDATE reports SET updated_at = ? WHERE id = ?`, ts, rep.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO follows (report_id, user_id, created_at) VALUES (?, ?, ?)`, rep.ID, u.ID, ts); err != nil {
			return err
		}
		saved, err = a.storeFiles(tx, rep.ID, &cid, u.ID, files, scans)
		return err
	})
	if err != nil {
		a.removeFiles(saved)
		a.serverError(w, r, err)
		return
	}
	text := body
	if text == "" {
		text = fmt.Sprintf("(%d %s)", len(files), map[bool]string{true: "Anhang", false: "Anhänge"}[len(files) == 1])
	}
	a.notifyFollowers(rep, u, fmt.Sprintf("%s hat auf Meldung #%d geantwortet:", u.Name(), rep.ID), text, "k"+itoa(cid))
	redirect(w, r, fmt.Sprintf("/r/%d#k%d", rep.ID, cid))
}

// ---------- Bearbeiten durch Entwickler (Triage) ----------

// resolveOriginal folgt Duplikat-Ketten bis zur Original-Meldung.
func (a *App) resolveOriginal(id int64) (int64, error) {
	for i := 0; i < 20; i++ {
		var next sql.NullInt64
		if err := a.db.QueryRow(`SELECT duplicate_of FROM reports WHERE id = ?`, id).Scan(&next); err != nil {
			return 0, err
		}
		if !next.Valid {
			return id, nil
		}
		id = next.Int64
	}
	return 0, errors.New("Duplikat-Kette zu lang")
}

func (a *App) handleManage(w http.ResponseWriter, r *http.Request) {
	rep, ok := a.loadVisibleReport(w, r)
	if !ok {
		return
	}
	u := currentUser(r)
	back := "/r/" + itoa(rep.ID)
	if !a.canManage(u, rep) {
		a.errorPage(w, r, http.StatusForbidden, "Nur Entwickler dieser Software dürfen Meldungen bearbeiten.")
		return
	}
	fail := func(msg string) {
		a.flash(w, "error", msg)
		redirect(w, r, back+"#bearbeiten")
	}
	status, kind := r.PostFormValue("status"), r.PostFormValue("art")
	if !valid(statuses, status) || !valid(kinds, kind) {
		fail("Ungültiger Status oder ungültige Art.")
		return
	}
	confidential := r.PostFormValue("vertraulich") == "1"
	if kind == "security" && rep.Kind != "security" {
		confidential = true // Umklassifizierung zu Sicherheit macht immer vertraulich
	}
	fixedIn := cleanLine(r.PostFormValue("behoben_in"), 60)

	// Zuständigkeit: nur Entwickler dieser Software
	assignee := parseID(r.PostFormValue("zustaendig"))
	devs, _ := a.developersOf(rep.SoftwareID)
	devName := map[int64]string{}
	for _, d := range devs {
		devName[d.ID] = d.Name
	}
	if assignee != 0 && devName[assignee] == "" {
		fail("Zuständig kann nur ein Entwickler dieser Software sein.")
		return
	}

	// Labels: nur Labels dieser Software
	softLabels, _ := a.labelsFor(rep.SoftwareID)
	labelByID := map[int64]Label{}
	for _, l := range softLabels {
		labelByID[l.ID] = l
	}
	want := map[int64]bool{}
	for _, v := range r.PostForm["labels"] {
		if id := parseID(v); labelByID[id].ID != 0 {
			want[id] = true
		}
	}
	current, _ := a.reportLabels(rep.ID)
	have := map[int64]bool{}
	for _, l := range current {
		have[l.ID] = true
	}

	// Duplikat
	var original *Report
	if status == "duplicate" {
		ref := parseID(strings.TrimPrefix(strings.TrimSpace(r.PostFormValue("duplikat")), "#"))
		if ref == 0 {
			fail("Bitte die Nummer der Original-Meldung angeben, z. B. #12.")
			return
		}
		root, err := a.resolveOriginal(ref)
		if err != nil {
			fail(fmt.Sprintf("Meldung #%d gibt es nicht.", ref))
			return
		}
		if root == rep.ID {
			fail("Eine Meldung kann kein Duplikat von sich selbst sein.")
			return
		}
		original, err = a.getReport(root, u)
		if err != nil || original.SoftwareID != rep.SoftwareID {
			fail(fmt.Sprintf("Meldung #%d gehört nicht zu %s.", ref, rep.SoftwareName))
			return
		}
	}

	var changes []string
	if status != rep.Status {
		changes = append(changes, fmt.Sprintf("Status: %s → %s", label(statuses, rep.Status), label(statuses, status)))
	}
	if kind != rep.Kind {
		changes = append(changes, fmt.Sprintf("Art: %s → %s", label(kinds, rep.Kind), label(kinds, kind)))
	}
	if confidential != rep.Confidential {
		if confidential {
			changes = append(changes, "Als vertraulich markiert – nur noch für Entwickler und Autor sichtbar.")
		} else {
			changes = append(changes, "Veröffentlicht – die Meldung ist jetzt für alle sichtbar.")
		}
	}
	if assignee != rep.AssigneeID {
		switch {
		case assignee == 0:
			changes = append(changes, "Zuständigkeit aufgehoben (bisher "+rep.AssigneeName+")")
		case rep.AssigneeID == 0:
			changes = append(changes, "Zuständig: "+devName[assignee])
		default:
			changes = append(changes, "Zuständig: "+rep.AssigneeName+" → "+devName[assignee])
		}
	}
	if fixedIn != rep.FixedIn {
		if fixedIn == "" {
			changes = append(changes, "„Behoben in“ entfernt")
		} else {
			changes = append(changes, "Behoben in Version "+fixedIn)
		}
	}
	var added, removed []string
	for id := range want {
		if !have[id] {
			added = append(added, labelByID[id].Name)
		}
	}
	for id := range have {
		if !want[id] {
			removed = append(removed, labelByID[id].Name)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	if len(added) > 0 {
		changes = append(changes, "Labels hinzugefügt: "+strings.Join(added, ", "))
	}
	if len(removed) > 0 {
		changes = append(changes, "Labels entfernt: "+strings.Join(removed, ", "))
	}
	newDup := int64(0)
	if original != nil {
		newDup = original.ID
	}
	var moved int64
	if newDup != rep.DuplicateOf {
		switch {
		case newDup == 0:
			changes = append(changes, fmt.Sprintf("Duplikat-Verknüpfung zu #%d aufgehoben", rep.DuplicateOf))
		case original.Confidential && !confidential:
			changes = append(changes, "Als Duplikat einer vertraulichen Meldung markiert")
		default:
			changes = append(changes, fmt.Sprintf("Als Duplikat von #%d markiert: %s", original.ID, original.Title))
		}
	}
	if len(changes) == 0 {
		a.flash(w, "info", "Keine Änderungen.")
		redirect(w, r, back)
		return
	}

	err := a.tx(func(tx *sql.Tx) error {
		ts := now()
		var asg, dup any
		if assignee != 0 {
			asg = assignee
		}
		if newDup != 0 {
			dup = newDup
		}
		if _, err := tx.Exec(`UPDATE reports SET status = ?, kind = ?, confidential = ?, assignee_id = ?, fixed_in = ?, duplicate_of = ?, updated_at = ? WHERE id = ?`,
			status, kind, confidential, asg, fixedIn, dup, ts, rep.ID); err != nil {
			return err
		}
		for id := range want {
			if !have[id] {
				if _, err := tx.Exec(`INSERT OR IGNORE INTO report_labels (report_id, label_id) VALUES (?, ?)`, rep.ID, id); err != nil {
					return err
				}
			}
		}
		for id := range have {
			if !want[id] {
				if _, err := tx.Exec(`DELETE FROM report_labels WHERE report_id = ? AND label_id = ?`, rep.ID, id); err != nil {
					return err
				}
			}
		}
		if newDup != 0 && newDup != rep.DuplicateOf {
			// Duplikate dieser Meldung zeigen künftig direkt auf das Original
			if _, err := tx.Exec(`UPDATE reports SET duplicate_of = ? WHERE duplicate_of = ?`, newDup, rep.ID); err != nil {
				return err
			}
			// Stimmen übertragen (nur in öffentliche Originale) und Folgende übernehmen
			if !original.Confidential {
				res, err := tx.Exec(`INSERT OR IGNORE INTO votes (report_id, user_id, created_at) SELECT ?, user_id, created_at FROM votes WHERE report_id = ?`, newDup, rep.ID)
				if err != nil {
					return err
				}
				moved, _ = res.RowsAffected()
				if _, err := tx.Exec(`UPDATE reports SET score = (SELECT COUNT(*) FROM votes WHERE report_id = ?) WHERE id = ?`, newDup, newDup); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(`INSERT OR IGNORE INTO follows (report_id, user_id, created_at) SELECT ?, user_id, ? FROM follows WHERE report_id = ?`, newDup, ts, rep.ID); err != nil {
				return err
			}
			note := fmt.Sprintf("#%d wurde als Duplikat hierher zusammengeführt", rep.ID)
			if !confidential || original.Confidential {
				note += ": " + rep.Title
			}
			if moved > 0 {
				note += fmt.Sprintf(" (%d %s übernommen)", moved, map[bool]string{true: "Stimme", false: "Stimmen"}[moved == 1])
			}
			if _, err := tx.Exec(`INSERT INTO comments (report_id, author_id, body, is_system, created_at) VALUES (?, ?, ?, 1, ?)`, newDup, u.ID, note, ts); err != nil {
				return err
			}
		}
		_, err := tx.Exec(`INSERT INTO comments (report_id, author_id, body, is_system, created_at) VALUES (?, ?, ?, 1, ?)`,
			rep.ID, u.ID, strings.Join(changes, "\n"), ts)
		return err
	})
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	updated, err := a.getReport(rep.ID, u)
	if err == nil {
		var exclude []int64
		if assignee != 0 && assignee != rep.AssigneeID {
			a.notifyAssigned(updated, assignee, u)
			exclude = append(exclude, assignee)
		}
		a.notifyFollowers(updated, u, fmt.Sprintf("%s hat Meldung #%d geändert:", u.Name(), rep.ID), strings.Join(changes, "\n"), "", exclude...)
	}
	a.flash(w, "ok", "Meldung aktualisiert.")
	redirect(w, r, back)
}

func (a *App) handleDelete(w http.ResponseWriter, r *http.Request) {
	rep, ok := a.loadVisibleReport(w, r)
	if !ok {
		return
	}
	u := currentUser(r)
	if !a.canManage(u, rep) && !a.canAuthorDelete(u, rep) {
		a.errorPage(w, r, http.StatusForbidden, "Diese Meldung kann nicht mehr gelöscht werden, weil sich bereits andere beteiligt haben. Bitte einen Entwickler, sie zu schließen.")
		return
	}
	atts, err := a.attachmentsForReport(rep.ID)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	if _, err := a.db.Exec(`DELETE FROM reports WHERE id = ?`, rep.ID); err != nil {
		a.serverError(w, r, err)
		return
	}
	var names []string
	for _, at := range atts {
		names = append(names, at.StorageName)
	}
	a.removeFiles(names)
	a.flash(w, "ok", fmt.Sprintf("Meldung #%d wurde gelöscht.", rep.ID))
	redirect(w, r, "/s/"+rep.SoftwareSlug)
}

// ---------- Anhänge ----------

func uploadedFiles(r *http.Request) []*multipart.FileHeader {
	if r.MultipartForm == nil {
		return nil
	}
	var out []*multipart.FileHeader
	for _, fh := range r.MultipartForm.File["anhaenge"] {
		if fh.Filename != "" {
			out = append(out, fh)
		}
	}
	return out
}

func (a *App) validateFiles(files []*multipart.FileHeader) string {
	if len(files) > a.cfg.MaxFiles {
		return fmt.Sprintf("Maximal %d Anhänge pro Beitrag.", a.cfg.MaxFiles)
	}
	for _, fh := range files {
		if fh.Size > a.cfg.MaxUploadBytes {
			return fmt.Sprintf("%q ist größer als %s.", sanitizeFilename(fh.Filename), humanBytes(a.cfg.MaxUploadBytes))
		}
	}
	return ""
}

func sanitizeFilename(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, `\`, "/"))
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || strings.ContainsRune(`/\:*?"<>|`, r) {
			return '_'
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		name = "datei"
	}
	if r := []rune(name); len(r) > 150 {
		ext := filepath.Ext(name)
		if len([]rune(ext)) > 20 {
			ext = ""
		}
		name = string(r[:150-len([]rune(ext))]) + ext
	}
	return name
}

// storeFiles schreibt die Dateien unter Zufallsnamen ins Datenverzeichnis und legt die DB-Einträge an.
// Bei Fehlern gibt es die bereits geschriebenen Dateinamen zurück, damit der Aufrufer aufräumen kann.
func (a *App) storeFiles(tx *sql.Tx, reportID int64, commentID *int64, uploader int64, files []*multipart.FileHeader, scans []string) ([]string, error) {
	var saved []string
	for i, fh := range files {
		scan := ""
		if i < len(scans) {
			scan = scans[i]
		}
		rnd := make([]byte, 16)
		if _, err := rand.Read(rnd); err != nil {
			return saved, err
		}
		storage := hex.EncodeToString(rnd)
		src, err := fh.Open()
		if err != nil {
			return saved, err
		}
		dst, err := os.OpenFile(filepath.Join(a.attachDir, storage), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
		if err != nil {
			src.Close()
			return saved, err
		}
		saved = append(saved, storage)
		h := sha256.New()
		head := make([]byte, 512)
		n, _ := io.ReadFull(src, head)
		head = head[:n]
		size, err := io.Copy(io.MultiWriter(dst, h), io.LimitReader(io.MultiReader(bytes.NewReader(head), src), a.cfg.MaxUploadBytes+1))
		src.Close()
		if cerr := dst.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return saved, err
		}
		if size > a.cfg.MaxUploadBytes {
			return saved, fmt.Errorf("Datei zu groß")
		}
		ctype := http.DetectContentType(head)
		var cid any
		if commentID != nil {
			cid = *commentID
		}
		if _, err := tx.Exec(`INSERT INTO attachments (report_id, comment_id, uploader_id, filename, content_type, size, sha256, storage_name, scan, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			reportID, cid, uploader, sanitizeFilename(fh.Filename), ctype, size, hex.EncodeToString(h.Sum(nil)), storage, scan, now()); err != nil {
			return saved, err
		}
	}
	return saved, nil
}

func (a *App) removeFiles(names []string) {
	for _, n := range names {
		os.Remove(filepath.Join(a.attachDir, n))
	}
}

var inlineImages = map[string]bool{"image/png": true, "image/jpeg": true, "image/gif": true, "image/webp": true}

func isInlineImage(ctype string) bool { return inlineImages[ctype] }

func (a *App) handleAttachment(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	at, err := a.attachmentByID(parseID(r.PathValue("id")))
	if err != nil {
		a.notFound(w, r)
		return
	}
	rep, err := a.getReport(at.ReportID, u)
	if err != nil || !a.canView(u, rep) {
		a.notFound(w, r)
		return
	}
	f, err := os.Open(filepath.Join(a.attachDir, at.StorageName))
	if err != nil {
		a.notFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	h := w.Header()
	// Hochgeladene Inhalte niemals als aktive Inhalte im Kontext der Anwendung ausführen.
	h.Set("Content-Security-Policy", "default-src 'none'; img-src 'self'; sandbox")
	h.Set("X-Content-Type-Options", "nosniff")
	if rep.Confidential {
		h.Set("Cache-Control", "private, no-store")
	} else {
		h.Set("Cache-Control", "private, max-age=300")
	}
	disp := "attachment"
	ctype := "application/octet-stream"
	if isInlineImage(at.ContentType) && !strings.HasPrefix(at.Scan, "FOUND:") {
		disp, ctype = "inline", at.ContentType
	}
	h.Set("Content-Type", ctype)
	h.Set("Content-Disposition", mime.FormatMediaType(disp, map[string]string{"filename": at.Filename}))
	http.ServeContent(w, r, "", st.ModTime(), f)
}

// ---------- Hilfen ----------

func (a *App) tx(fn func(*sql.Tx) error) error {
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}
