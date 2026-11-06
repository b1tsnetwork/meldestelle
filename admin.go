package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
)

type adminPage struct {
	Softwares []Software
	Users     []User
	Query     string
}

func (a *App) handleAdmin(w http.ResponseWriter, r *http.Request) {
	sw, err := a.listSoftware(true)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	q := cleanLine(r.URL.Query().Get("q"), 100)
	users, err := a.listUsers(q)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	a.render(w, r, http.StatusOK, "admin.html", "Verwaltung", adminPage{Softwares: sw, Users: users, Query: q})
}

func (a *App) handleSoftwareCreate(w http.ResponseWriter, r *http.Request) {
	name := cleanLine(r.PostFormValue("name"), 80)
	slug := slugify(r.PostFormValue("slug"))
	if slug == "" {
		slug = slugify(name)
	}
	desc := strings.TrimSpace(r.PostFormValue("beschreibung"))
	if name == "" || slug == "" {
		a.flash(w, "error", "Bitte einen Namen angeben.")
		redirect(w, r, "/admin")
		return
	}
	if len([]rune(desc)) > 2000 {
		desc = string([]rune(desc)[:2000])
	}
	_, err := a.db.Exec(`INSERT INTO software (slug, name, description, created_at) VALUES (?, ?, ?, ?)`, slug, name, desc, now())
	if isUniqueErr(err) {
		a.flash(w, "error", fmt.Sprintf("Die Kurzbezeichnung %q ist bereits vergeben.", slug))
	} else if err != nil {
		a.serverError(w, r, err)
		return
	} else {
		a.flash(w, "ok", fmt.Sprintf("Software %q angelegt.", name))
	}
	redirect(w, r, "/admin")
}

func (a *App) handleSoftwareUpdate(w http.ResponseWriter, r *http.Request) {
	id := parseID(r.PathValue("id"))
	name := cleanLine(r.PostFormValue("name"), 80)
	desc := strings.TrimSpace(r.PostFormValue("beschreibung"))
	if len([]rune(desc)) > 2000 {
		desc = string([]rune(desc)[:2000])
	}
	if name == "" {
		a.flash(w, "error", "Der Name darf nicht leer sein.")
		redirect(w, r, "/admin")
		return
	}
	if _, err := a.db.Exec(`UPDATE software SET name = ?, description = ? WHERE id = ?`, name, desc, id); err != nil {
		a.serverError(w, r, err)
		return
	}
	a.flash(w, "ok", "Software gespeichert.")
	redirect(w, r, fmt.Sprintf("/admin#sw%d", id))
}

func (a *App) handleDevAdd(w http.ResponseWriter, r *http.Request) {
	sid := parseID(r.PathValue("id"))
	sw, err := a.softwareBy("id", sid)
	if err != nil {
		a.notFound(w, r)
		return
	}
	user, err := a.userByName(strings.TrimSpace(r.PostFormValue("benutzer")))
	if notFoundErr(err) {
		a.flash(w, "error", "Diesen Benutzer gibt es nicht. Er muss sich zuerst einmal anmelden oder registrieren.")
		redirect(w, r, fmt.Sprintf("/admin#sw%d", sid))
		return
	} else if err != nil {
		a.serverError(w, r, err)
		return
	}
	if _, err := a.db.Exec(`INSERT OR IGNORE INTO developers (software_id, user_id) VALUES (?, ?)`, sw.ID, user.ID); err != nil {
		a.serverError(w, r, err)
		return
	}
	a.flash(w, "ok", fmt.Sprintf("%s ist jetzt Entwickler von %s und sieht deren Sicherheitsmeldungen.", user.Username, sw.Name))
	redirect(w, r, fmt.Sprintf("/admin#sw%d", sid))
}

func (a *App) handleDevRemove(w http.ResponseWriter, r *http.Request) {
	sid, uid := parseID(r.PathValue("id")), parseID(r.PathValue("uid"))
	if _, err := a.db.Exec(`DELETE FROM developers WHERE software_id = ? AND user_id = ?`, sid, uid); err != nil {
		a.serverError(w, r, err)
		return
	}
	a.flash(w, "ok", "Entwickler entfernt.")
	redirect(w, r, fmt.Sprintf("/admin#sw%d", sid))
}

func (a *App) handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	id := parseID(r.PathValue("id"))
	target, err := a.userByID(id)
	if err != nil {
		a.notFound(w, r)
		return
	}
	action := r.PostFormValue("aktion")
	if id == me.ID && (action == "admin_aus" || action == "sperren") {
		a.flash(w, "error", "Du kannst dir nicht selbst die Rechte entziehen oder dich sperren.")
		redirect(w, r, "/admin#benutzer")
		return
	}
	var msg string
	err = a.tx(func(tx *sql.Tx) error {
		var err error
		switch action {
		case "admin_an":
			_, err = tx.Exec(`UPDATE users SET is_admin = 1 WHERE id = ?`, id)
			msg = target.Username + " ist jetzt Administrator."
		case "admin_aus":
			_, err = tx.Exec(`UPDATE users SET is_admin = 0 WHERE id = ?`, id)
			msg = target.Username + " ist kein Administrator mehr."
		case "sperren":
			if _, err = tx.Exec(`UPDATE users SET disabled = 1 WHERE id = ?`, id); err == nil {
				_, err = tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, id)
			}
			msg = target.Username + " wurde gesperrt und abgemeldet."
		case "entsperren":
			_, err = tx.Exec(`UPDATE users SET disabled = 0 WHERE id = ?`, id)
			msg = target.Username + " wurde entsperrt."
		default:
			msg = "Unbekannte Aktion."
		}
		return err
	})
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	a.flash(w, "ok", msg)
	redirect(w, r, "/admin#benutzer")
}
