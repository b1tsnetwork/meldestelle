package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func (a *App) labelsFor(softwareID int64) ([]Label, error) {
	rows, err := a.db.Query(`SELECT l.id, l.software_id, l.name, l.color,
			(SELECT COUNT(*) FROM report_labels rl WHERE rl.label_id = l.id)
		FROM labels l WHERE l.software_id = ? ORDER BY l.name COLLATE NOCASE`, softwareID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Label
	for rows.Next() {
		var l Label
		if err := rows.Scan(&l.ID, &l.SoftwareID, &l.Name, &l.Color, &l.Uses); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (a *App) reportLabels(reportID int64) ([]Label, error) {
	rows, err := a.db.Query(`SELECT l.id, l.software_id, l.name, l.color FROM report_labels rl
		JOIN labels l ON l.id = rl.label_id WHERE rl.report_id = ? ORDER BY l.name COLLATE NOCASE`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Label
	for rows.Next() {
		var l Label
		if err := rows.Scan(&l.ID, &l.SoftwareID, &l.Name, &l.Color); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// attachLabels lädt die Labels für eine ganze Liste mit einer Abfrage.
func (a *App) attachLabels(reports []Report) error {
	if len(reports) == 0 {
		return nil
	}
	idx := map[int64]int{}
	ph := make([]string, len(reports))
	args := make([]any, len(reports))
	for i, r := range reports {
		idx[r.ID] = i
		ph[i] = "?"
		args[i] = r.ID
	}
	rows, err := a.db.Query(`SELECT rl.report_id, l.id, l.software_id, l.name, l.color FROM report_labels rl
		JOIN labels l ON l.id = rl.label_id WHERE rl.report_id IN (`+strings.Join(ph, ",")+`) ORDER BY l.name COLLATE NOCASE`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var rid int64
		var l Label
		if err := rows.Scan(&rid, &l.ID, &l.SoftwareID, &l.Name, &l.Color); err != nil {
			return err
		}
		if i, ok := idx[rid]; ok {
			reports[i].Labels = append(reports[i].Labels, l)
		}
	}
	return rows.Err()
}

func (a *App) canManageSoftware(u *User, softwareID int64) bool {
	return u != nil && (u.IsAdmin || a.isDeveloper(softwareID, u.ID))
}

// ---------- Einstellungsseite pro Software ----------

type softwareSettingsPage struct {
	Software   *Software
	Labels     []Label
	Developers []UserRef
	Colors     []option
}

func (a *App) loadManagedSoftware(w http.ResponseWriter, r *http.Request) (*Software, bool) {
	sw, err := a.softwareBy("slug", r.PathValue("slug"))
	if err != nil {
		a.notFound(w, r)
		return nil, false
	}
	if !a.canManageSoftware(currentUser(r), sw.ID) {
		a.errorPage(w, r, http.StatusForbidden, "Die Einstellungen einer Software können nur ihre Entwickler und Administratoren ändern.")
		return nil, false
	}
	return sw, true
}

func (a *App) handleSoftwareSettings(w http.ResponseWriter, r *http.Request) {
	sw, ok := a.loadManagedSoftware(w, r)
	if !ok {
		return
	}
	labels, err := a.labelsFor(sw.ID)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	devs, _ := a.developersOf(sw.ID)
	a.render(w, r, http.StatusOK, "software.html", sw.Name+" – Einstellungen",
		softwareSettingsPage{Software: sw, Labels: labels, Developers: devs, Colors: labelColors})
}

func labelInput(r *http.Request) (string, int, string) {
	name := cleanLine(r.PostFormValue("name"), 40)
	color, _ := strconv.Atoi(r.PostFormValue("farbe"))
	if color < 1 || color > len(labelColors) {
		color = 1
	}
	if name == "" {
		return "", 0, "Bitte einen Namen für das Label angeben."
	}
	return name, color, ""
}

func (a *App) handleLabelCreate(w http.ResponseWriter, r *http.Request) {
	sw, ok := a.loadManagedSoftware(w, r)
	if !ok {
		return
	}
	back := "/s/" + sw.Slug + "/einstellungen"
	name, color, msg := labelInput(r)
	if msg != "" {
		a.flash(w, "error", msg)
		redirect(w, r, back)
		return
	}
	_, err := a.db.Exec(`INSERT INTO labels (software_id, name, color) VALUES (?, ?, ?)`, sw.ID, name, color)
	switch {
	case isUniqueErr(err):
		a.flash(w, "error", fmt.Sprintf("Das Label „%s“ gibt es bereits.", name))
	case err != nil:
		a.serverError(w, r, err)
		return
	default:
		a.flash(w, "ok", fmt.Sprintf("Label „%s“ angelegt.", name))
	}
	redirect(w, r, back)
}

func (a *App) handleLabelUpdate(w http.ResponseWriter, r *http.Request) {
	sw, ok := a.loadManagedSoftware(w, r)
	if !ok {
		return
	}
	back := "/s/" + sw.Slug + "/einstellungen"
	name, color, msg := labelInput(r)
	if msg != "" {
		a.flash(w, "error", msg)
		redirect(w, r, back)
		return
	}
	_, err := a.db.Exec(`UPDATE labels SET name = ?, color = ? WHERE id = ? AND software_id = ?`, name, color, parseID(r.PathValue("id")), sw.ID)
	switch {
	case isUniqueErr(err):
		a.flash(w, "error", fmt.Sprintf("Das Label „%s“ gibt es bereits.", name))
	case err != nil:
		a.serverError(w, r, err)
		return
	default:
		a.flash(w, "ok", "Label gespeichert.")
	}
	redirect(w, r, back)
}

func (a *App) handleLabelDelete(w http.ResponseWriter, r *http.Request) {
	sw, ok := a.loadManagedSoftware(w, r)
	if !ok {
		return
	}
	if _, err := a.db.Exec(`DELETE FROM labels WHERE id = ? AND software_id = ?`, parseID(r.PathValue("id")), sw.ID); err != nil {
		a.serverError(w, r, err)
		return
	}
	a.flash(w, "ok", "Label gelöscht.")
	redirect(w, r, "/s/"+sw.Slug+"/einstellungen")
}
