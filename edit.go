package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
)

// ---------- Meldung bearbeiten (Autor, Entwickler, Admins) ----------

type editReportPage struct {
	Report      *Report
	Values      map[string]string
	Errors      []string
	Attachments []Attachment
	MaxFiles    int
	MaxBytes    int64
}

func (a *App) loadEditableReport(w http.ResponseWriter, r *http.Request) (*Report, bool) {
	rep, ok := a.loadVisibleReport(w, r)
	if !ok {
		return nil, false
	}
	u := currentUser(r)
	if u.ID != rep.AuthorID && !a.canManage(u, rep) {
		a.errorPage(w, r, http.StatusForbidden, "Nur die meldende Person und die Entwickler dürfen diese Meldung bearbeiten.")
		return nil, false
	}
	return rep, true
}

func (a *App) editPage(w http.ResponseWriter, r *http.Request, status int, rep *Report, vals map[string]string, errs []string) {
	u := currentUser(r)
	atts, _ := a.attachmentsForReport(rep.ID)
	var top []Attachment
	for _, at := range atts {
		if !at.CommentID.Valid {
			at.CanRemove = a.canManage(u, rep) || at.UploaderID == u.ID
			top = append(top, at)
		}
	}
	a.render(w, r, status, "edit.html", "Meldung bearbeiten", editReportPage{
		Report: rep, Values: vals, Errors: errs, Attachments: top, MaxFiles: a.cfg.MaxFiles, MaxBytes: a.cfg.MaxUploadBytes,
	})
}

func (a *App) handleEditReportForm(w http.ResponseWriter, r *http.Request) {
	rep, ok := a.loadEditableReport(w, r)
	if !ok {
		return
	}
	a.editPage(w, r, http.StatusOK, rep, map[string]string{"titel": rep.Title, "beschreibung": rep.Body, "version": rep.Version}, nil)
}

func (a *App) handleEditReport(w http.ResponseWriter, r *http.Request) {
	rep, ok := a.loadEditableReport(w, r)
	if !ok {
		return
	}
	u := currentUser(r)
	vals := map[string]string{
		"titel":        cleanLine(r.PostFormValue("titel"), 200),
		"beschreibung": strings.TrimSpace(r.PostFormValue("beschreibung")),
		"version":      cleanLine(r.PostFormValue("version"), 60),
	}
	var errs []string
	if len([]rune(vals["titel"])) < 5 {
		errs = append(errs, "Der Titel braucht mindestens 5 Zeichen.")
	}
	if n := len([]rune(vals["beschreibung"])); n < 10 || n > 50000 {
		errs = append(errs, "Die Beschreibung braucht 10 bis 50.000 Zeichen.")
	}
	files := uploadedFiles(r)
	existing, _ := a.attachmentsForReport(rep.ID)
	if len(files) > 0 {
		if msg := a.validateFiles(files); msg != "" {
			errs = append(errs, msg)
		}
		top := 0
		for _, at := range existing {
			if !at.CommentID.Valid {
				top++
			}
		}
		if top+len(files) > a.cfg.MaxFiles*2 {
			errs = append(errs, fmt.Sprintf("Eine Meldung kann höchstens %d Anhänge haben. Entferne zuerst ältere Anhänge.", a.cfg.MaxFiles*2))
		}
	}
	var scans []string
	if len(errs) == 0 {
		var msg string
		if scans, msg = a.scanUploads(r.Context(), files, rep.Confidential); msg != "" {
			errs = append(errs, msg)
		}
	}
	if len(errs) > 0 {
		a.editPage(w, r, http.StatusUnprocessableEntity, rep, vals, errs)
		return
	}

	var changes []string
	if vals["titel"] != rep.Title {
		changes = append(changes, "Titel geändert: „"+rep.Title+"“ → „"+vals["titel"]+"“")
	}
	if vals["beschreibung"] != rep.Body {
		changes = append(changes, "Beschreibung bearbeitet")
	}
	if vals["version"] != rep.Version {
		changes = append(changes, "Betroffene Version: "+orDash(rep.Version)+" → "+orDash(vals["version"]))
	}
	for _, fh := range files {
		changes = append(changes, "Anhang hinzugefügt: "+sanitizeFilename(fh.Filename))
	}
	if len(changes) == 0 {
		a.flash(w, "info", "Keine Änderungen.")
		redirect(w, r, "/r/"+itoa(rep.ID))
		return
	}
	var saved []string
	err := a.tx(func(tx *sql.Tx) error {
		ts := now()
		textChanged := vals["titel"] != rep.Title || vals["beschreibung"] != rep.Body
		editedAt := rep.EditedAt
		if textChanged {
			editedAt = ts
		}
		if _, err := tx.Exec(`UPDATE reports SET title = ?, body = ?, version = ?, edited_at = ?, updated_at = ? WHERE id = ?`,
			vals["titel"], vals["beschreibung"], vals["version"], editedAt, ts, rep.ID); err != nil {
			return err
		}
		var err error
		if saved, err = a.storeFiles(tx, rep.ID, nil, u.ID, files, scans); err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO comments (report_id, author_id, body, is_system, created_at) VALUES (?, ?, ?, 1, ?)`,
			rep.ID, u.ID, strings.Join(changes, "\n"), ts)
		return err
	})
	if err != nil {
		a.removeFiles(saved)
		a.serverError(w, r, err)
		return
	}
	a.flash(w, "ok", "Änderungen gespeichert.")
	redirect(w, r, "/r/"+itoa(rep.ID))
}

func orDash(s string) string {
	if s == "" {
		return "–"
	}
	return s
}

// ---------- Antworten bearbeiten und löschen ----------

type commentRef struct {
	ID, ReportID, AuthorID int64
	Body                   string
	IsSystem               bool
	DeletedAt              int64
}

// loadComment lädt eine Antwort samt Meldung und prüft die Sichtbarkeit.
func (a *App) loadComment(w http.ResponseWriter, r *http.Request) (*commentRef, *Report, bool) {
	var c commentRef
	err := a.db.QueryRow(`SELECT id, report_id, author_id, body, is_system, deleted_at FROM comments WHERE id = ?`, parseID(r.PathValue("id"))).
		Scan(&c.ID, &c.ReportID, &c.AuthorID, &c.Body, &c.IsSystem, &c.DeletedAt)
	if err != nil || c.IsSystem {
		a.notFound(w, r)
		return nil, nil, false
	}
	rep, ok := a.loadVisibleReportID(w, r, c.ReportID)
	if !ok {
		return nil, nil, false
	}
	return &c, rep, true
}

type editCommentPage struct {
	Report  *Report
	Comment *commentRef
	Text    string
	Error   string
}

func (a *App) handleEditCommentForm(w http.ResponseWriter, r *http.Request) {
	c, rep, ok := a.loadComment(w, r)
	if !ok {
		return
	}
	if c.AuthorID != currentUser(r).ID || c.DeletedAt != 0 {
		a.errorPage(w, r, http.StatusForbidden, "Du kannst nur deine eigenen Antworten bearbeiten.")
		return
	}
	a.render(w, r, http.StatusOK, "comment-edit.html", "Antwort bearbeiten", editCommentPage{Report: rep, Comment: c, Text: c.Body})
}

func (a *App) handleEditComment(w http.ResponseWriter, r *http.Request) {
	c, rep, ok := a.loadComment(w, r)
	if !ok {
		return
	}
	if c.AuthorID != currentUser(r).ID || c.DeletedAt != 0 {
		a.errorPage(w, r, http.StatusForbidden, "Du kannst nur deine eigenen Antworten bearbeiten.")
		return
	}
	text := strings.TrimSpace(r.PostFormValue("text"))
	var hasFiles bool
	a.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM attachments WHERE comment_id = ?)`, c.ID).Scan(&hasFiles)
	if (text == "" && !hasFiles) || len([]rune(text)) > 20000 {
		a.render(w, r, http.StatusUnprocessableEntity, "comment-edit.html", "Antwort bearbeiten",
			editCommentPage{Report: rep, Comment: c, Text: text, Error: "Die Antwort darf nicht leer und höchstens 20.000 Zeichen lang sein."})
		return
	}
	if text != c.Body {
		if _, err := a.db.Exec(`UPDATE comments SET body = ?, edited_at = ? WHERE id = ?`, text, now(), c.ID); err != nil {
			a.serverError(w, r, err)
			return
		}
	}
	redirect(w, r, fmt.Sprintf("/r/%d#k%d", rep.ID, c.ID))
}

func (a *App) handleDeleteComment(w http.ResponseWriter, r *http.Request) {
	c, rep, ok := a.loadComment(w, r)
	if !ok {
		return
	}
	u := currentUser(r)
	own := c.AuthorID == u.ID
	if !own && !a.canManage(u, rep) {
		a.errorPage(w, r, http.StatusForbidden, "Du kannst nur deine eigenen Antworten löschen.")
		return
	}
	if c.DeletedAt != 0 {
		redirect(w, r, "/r/"+itoa(rep.ID))
		return
	}
	atts, _ := a.attachmentsForReport(rep.ID)
	var names []string
	err := a.tx(func(tx *sql.Tx) error {
		ts := now()
		if _, err := tx.Exec(`UPDATE comments SET body = '', deleted_at = ?, deleted_by = ? WHERE id = ?`, ts, u.ID, c.ID); err != nil {
			return err
		}
		for _, at := range atts {
			if at.CommentID.Valid && at.CommentID.Int64 == c.ID {
				names = append(names, at.StorageName)
			}
		}
		if _, err := tx.Exec(`DELETE FROM attachments WHERE comment_id = ?`, c.ID); err != nil {
			return err
		}
		if !own {
			_, err := tx.Exec(`INSERT INTO comments (report_id, author_id, body, is_system, created_at) VALUES (?, ?, ?, 1, ?)`,
				rep.ID, u.ID, "Eine Antwort wurde von der Moderation entfernt.", ts)
			return err
		}
		return nil
	})
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	a.removeFiles(names)
	a.flash(w, "ok", "Antwort gelöscht.")
	redirect(w, r, fmt.Sprintf("/r/%d#k%d", rep.ID, c.ID))
}

// ---------- Einzelne Anhänge entfernen ----------

func (a *App) handleRemoveAttachment(w http.ResponseWriter, r *http.Request) {
	at, err := a.attachmentByID(parseID(r.PathValue("id")))
	if err != nil {
		a.notFound(w, r)
		return
	}
	rep, ok := a.loadVisibleReportID(w, r, at.ReportID)
	if !ok {
		return
	}
	u := currentUser(r)
	if at.UploaderID != u.ID && !a.canManage(u, rep) {
		a.errorPage(w, r, http.StatusForbidden, "Du kannst nur selbst hochgeladene Anhänge entfernen.")
		return
	}
	err = a.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM attachments WHERE id = ?`, at.ID); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO comments (report_id, author_id, body, is_system, created_at) VALUES (?, ?, ?, 1, ?)`,
			rep.ID, u.ID, "Anhang entfernt: "+at.Filename, now())
		return err
	})
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	a.removeFiles([]string{at.StorageName})
	a.flash(w, "ok", "Anhang „"+at.Filename+"“ entfernt.")
	back := safeNext(r.PostFormValue("zurueck"))
	if back == "/" {
		back = "/r/" + itoa(rep.ID)
	}
	redirect(w, r, back)
}
