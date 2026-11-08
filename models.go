package main

import (
	"database/sql"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// ---------- Typen ----------

type User struct {
	ID          int64
	Username    string
	Email       string
	DisplayName string
	HasPassword bool
	IsOIDC      bool
	IsLDAP      bool
	IsAdmin     bool
	Disabled    bool
	CreatedAt   int64
}

func (u *User) Name() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Username
}

type Software struct {
	ID          int64
	Slug        string
	Name        string
	Description string
	CreatedAt   int64
	Developers  []UserRef
}

type UserRef struct {
	ID   int64
	Name string
}

type Report struct {
	ID           int64
	SoftwareID   int64
	SoftwareSlug string
	SoftwareName string
	AuthorID     int64
	AuthorName   string
	Kind         string
	Status       string
	Title        string
	Body         string
	Version      string
	Confidential bool
	Score        int
	CreatedAt    int64
	UpdatedAt    int64
	Comments     int
	Voted        bool
	DuplicateOf  int64
	AssigneeID   int64
	AssigneeName string
	FixedIn      string
	EditedAt     int64
	Labels       []Label
	FirstDone    bool // erste erledigte Meldung in einer Liste (für den Trenner)
}

type Label struct {
	ID         int64
	SoftwareID int64
	Name       string
	Color      int
	Uses       int
}

// labelColors sind feste Farbtöne (CSS-Klassen lc-1 … lc-8), damit Kontrast in hell und dunkel stimmt.
var labelColors = []option{
	{"1", "Blau"}, {"2", "Grün"}, {"3", "Gelb"}, {"4", "Orange"},
	{"5", "Rot"}, {"6", "Violett"}, {"7", "Türkis"}, {"8", "Grau"},
}

// doneStatuses gelten als erledigt: kompakt, gedimmt und in Listen ans Ende sortiert.
var doneStatuses = map[string]bool{"fixed": true, "duplicate": true, "wontfix": true, "closed": true}

func (r Report) Done() bool { return doneStatuses[r.Status] }

const doneSQL = `CASE WHEN r.status IN ('fixed', 'duplicate', 'wontfix', 'closed') THEN 1 ELSE 0 END`

type Comment struct {
	ID          int64
	AuthorID    int64
	AuthorName  string
	Body        string
	IsSystem    bool
	CreatedAt   int64
	EditedAt    int64
	DeletedAt   int64
	DeletedBy   int64
	AuthorIsDev bool
	CanEdit     bool
	CanDelete   bool
	Attachments []Attachment
}

func (c Comment) Deleted() bool { return c.DeletedAt != 0 }

type Attachment struct {
	ID          int64
	ReportID    int64
	CommentID   sql.NullInt64
	UploaderID  int64
	Scan        string // '' = nicht geprüft, "clean" oder "FOUND:<Signatur>"
	CanRemove   bool
	Filename    string
	ContentType string
	Size        int64
	StorageName string
	CreatedAt   int64
}

// ---------- Stammdaten ----------

type option struct{ Value, Label string }

var kinds = []option{
	{"bug", "Bug"},
	{"feature", "Feature"},
	{"security", "Sicherheit"},
}

var statuses = []option{
	{"open", "Offen"},
	{"confirmed", "Bestätigt"},
	{"planned", "Geplant"},
	{"in_progress", "In Arbeit"},
	{"fixed", "Behoben"},
	{"duplicate", "Duplikat"},
	{"wontfix", "Wird nicht umgesetzt"},
	{"closed", "Geschlossen"},
}

func label(opts []option, v string) string {
	for _, o := range opts {
		if o.Value == v {
			return o.Label
		}
	}
	return v
}

func valid(opts []option, v string) bool {
	for _, o := range opts {
		if o.Value == v {
			return true
		}
	}
	return false
}

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{3,32}$`)

func validUsername(s string) bool { return usernameRe.MatchString(s) }

const minPasswordLen = 10

var errNotFound = errors.New("nicht gefunden")

func notFoundErr(err error) bool { return errors.Is(err, sql.ErrNoRows) || errors.Is(err, errNotFound) }

func isUniqueErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint")
}

func slugify(s string) string {
	repl := strings.NewReplacer("ä", "ae", "ö", "oe", "ü", "ue", "ß", "ss", "Ä", "ae", "Ö", "oe", "Ü", "ue")
	s = strings.ToLower(repl.Replace(s))
	var b strings.Builder
	dash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 48 {
		out = strings.Trim(out[:48], "-")
	}
	return out
}

func cleanLine(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}

// ---------- Benutzer ----------

const userCols = `u.id, u.username, u.email, u.display_name, u.password_hash <> '', u.oidc_subject <> '', u.ldap_id <> '', u.is_admin, u.disabled, u.created_at`

type scanner interface{ Scan(...any) error }

func scanUser(s scanner) (*User, error) {
	u := &User{}
	if err := s.Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.HasPassword, &u.IsOIDC, &u.IsLDAP, &u.IsAdmin, &u.Disabled, &u.CreatedAt); err != nil {
		return nil, err
	}
	return u, nil
}

func (a *App) userByID(id int64) (*User, error) {
	return scanUser(a.db.QueryRow(`SELECT `+userCols+` FROM users u WHERE u.id = ?`, id))
}

func (a *App) userByName(name string) (*User, error) {
	return scanUser(a.db.QueryRow(`SELECT `+userCols+` FROM users u WHERE u.username = ?`, name))
}

func (a *App) listUsers(q string) ([]User, error) {
	pat := "%" + likeEscape(q) + "%"
	rows, err := a.db.Query(`SELECT `+userCols+` FROM users u
		WHERE u.username LIKE ? ESCAPE '\' OR u.email LIKE ? ESCAPE '\' OR u.display_name LIKE ? ESCAPE '\'
		ORDER BY u.username LIMIT 300`, pat, pat, pat)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// uniqueUsername leitet aus einem Wunschnamen einen freien, gültigen Benutzernamen ab.
func (a *App) uniqueUsername(want string) (string, error) {
	var b strings.Builder
	for _, r := range want {
		if r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-') {
			b.WriteRune(r)
		}
	}
	base := b.String()
	if len(base) > 28 {
		base = base[:28]
	}
	for len(base) < 3 {
		base += "_"
	}
	for i := 1; i < 1000; i++ {
		cand := base
		if i > 1 {
			cand = base + "-" + itoa(int64(i))
		}
		var exists bool
		if err := a.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM users WHERE username = ?)`, cand).Scan(&exists); err != nil {
			return "", err
		}
		if !exists {
			return cand, nil
		}
	}
	return "", errors.New("kein freier Benutzername gefunden")
}

// ---------- Software & Entwickler ----------

func (a *App) listSoftware(withDevs bool) ([]Software, error) {
	rows, err := a.db.Query(`SELECT id, slug, name, description, created_at FROM software ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	var list []Software
	idx := map[int64]int{}
	for rows.Next() {
		var s Software
		if err := rows.Scan(&s.ID, &s.Slug, &s.Name, &s.Description, &s.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		idx[s.ID] = len(list)
		list = append(list, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil || !withDevs {
		return list, err
	}
	drows, err := a.db.Query(`SELECT d.software_id, u.id, COALESCE(NULLIF(u.display_name, ''), u.username)
		FROM developers d JOIN users u ON u.id = d.user_id ORDER BY u.username COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer drows.Close()
	for drows.Next() {
		var sid int64
		var ref UserRef
		if err := drows.Scan(&sid, &ref.ID, &ref.Name); err != nil {
			return nil, err
		}
		if i, ok := idx[sid]; ok {
			list[i].Developers = append(list[i].Developers, ref)
		}
	}
	return list, drows.Err()
}

func (a *App) softwareBy(col string, v any) (*Software, error) {
	s := &Software{}
	err := a.db.QueryRow(`SELECT id, slug, name, description, created_at FROM software WHERE `+col+` = ?`, v).
		Scan(&s.ID, &s.Slug, &s.Name, &s.Description, &s.CreatedAt)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (a *App) developersOf(softwareID int64) ([]UserRef, error) {
	rows, err := a.db.Query(`SELECT u.id, COALESCE(NULLIF(u.display_name, ''), u.username)
		FROM developers d JOIN users u ON u.id = d.user_id
		WHERE d.software_id = ? ORDER BY u.username COLLATE NOCASE`, softwareID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserRef
	for rows.Next() {
		var r UserRef
		if err := rows.Scan(&r.ID, &r.Name); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (a *App) isDeveloper(softwareID, userID int64) bool {
	var ok bool
	_ = a.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM developers WHERE software_id = ? AND user_id = ?)`, softwareID, userID).Scan(&ok)
	return ok
}

func (a *App) isAnyDeveloper(userID int64) bool {
	var ok bool
	_ = a.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM developers WHERE user_id = ?)`, userID).Scan(&ok)
	return ok
}

// ---------- Berechtigungen ----------

// canView ist die zentrale Sichtbarkeitsregel: Öffentliche Meldungen sieht jeder,
// vertrauliche (Sicherheitslücken/Exploits) nur Autor, Entwickler der Software und Admins.
func (a *App) canView(u *User, r *Report) bool {
	if !r.Confidential {
		return true
	}
	if u == nil {
		return false
	}
	return u.IsAdmin || u.ID == r.AuthorID || a.isDeveloper(r.SoftwareID, u.ID)
}

func (a *App) canManage(u *User, r *Report) bool {
	return u != nil && (u.IsAdmin || a.isDeveloper(r.SoftwareID, u.ID))
}

// visibilitySQL ist das SQL-Gegenstück zu canView für Listenabfragen.
const visibilitySQL = `(r.confidential = 0 OR ? = 1 OR r.author_id = ?
	OR EXISTS (SELECT 1 FROM developers d WHERE d.software_id = r.software_id AND d.user_id = ?))`

func visibilityArgs(u *User) []any {
	if u == nil {
		return []any{0, 0, 0}
	}
	admin := 0
	if u.IsAdmin {
		admin = 1
	}
	return []any{admin, u.ID, u.ID}
}

// ---------- Meldungen ----------

func reportSelect(bodyExpr string) string {
	return `SELECT r.id, r.software_id, s.slug, s.name, r.author_id,
		COALESCE(NULLIF(u.display_name, ''), u.username),
		r.kind, r.status, r.title, ` + bodyExpr + `, r.version, r.confidential, r.score, r.created_at, r.updated_at,
		(SELECT COUNT(*) FROM comments c WHERE c.report_id = r.id AND c.is_system = 0 AND c.deleted_at = 0),
		EXISTS (SELECT 1 FROM votes v WHERE v.report_id = r.id AND v.user_id = ?),
		COALESCE(r.duplicate_of, 0), COALESCE(r.assignee_id, 0),
		COALESCE(NULLIF(asg.display_name, ''), asg.username, ''), r.fixed_in, r.edited_at
	FROM reports r
	JOIN software s ON s.id = r.software_id
	JOIN users u ON u.id = r.author_id
	LEFT JOIN users asg ON asg.id = r.assignee_id`
}

func scanReport(s scanner) (*Report, error) {
	r := &Report{}
	err := s.Scan(&r.ID, &r.SoftwareID, &r.SoftwareSlug, &r.SoftwareName, &r.AuthorID, &r.AuthorName,
		&r.Kind, &r.Status, &r.Title, &r.Body, &r.Version, &r.Confidential, &r.Score, &r.CreatedAt, &r.UpdatedAt,
		&r.Comments, &r.Voted, &r.DuplicateOf, &r.AssigneeID, &r.AssigneeName, &r.FixedIn, &r.EditedAt)
	return r, err
}

func uid(u *User) int64 {
	if u == nil {
		return 0
	}
	return u.ID
}

// getReport lädt eine Meldung OHNE Sichtbarkeitsprüfung – Aufrufer müssen canView prüfen.
func (a *App) getReport(id int64, u *User) (*Report, error) {
	return scanReport(a.db.QueryRow(reportSelect("r.body")+` WHERE r.id = ?`, uid(u), id))
}

type listFilter struct {
	Kind, Status, Query, Sort string
	Mine, Assigned            bool
	SoftwareID, Label         int64
}

const pageSize = 25

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func (a *App) queryReports(u *User, f listFilter, page int) ([]Report, bool, error) {
	args := []any{uid(u)}
	where := []string{visibilitySQL}
	args = append(args, visibilityArgs(u)...)
	if f.SoftwareID != 0 {
		where = append(where, `r.software_id = ?`)
		args = append(args, f.SoftwareID)
	}
	if f.Kind != "" {
		where = append(where, `r.kind = ?`)
		args = append(args, f.Kind)
	}
	if f.Status != "" {
		where = append(where, `r.status = ?`)
		args = append(args, f.Status)
	}
	if f.Query != "" {
		pat := "%" + likeEscape(f.Query) + "%"
		where = append(where, `(r.title LIKE ? ESCAPE '\' OR r.body LIKE ? ESCAPE '\')`)
		args = append(args, pat, pat)
	}
	if f.Mine && u != nil {
		where = append(where, `r.author_id = ?`)
		args = append(args, u.ID)
	}
	if f.Assigned && u != nil {
		where = append(where, `r.assignee_id = ?`)
		args = append(args, u.ID)
	}
	if f.Label != 0 {
		where = append(where, `EXISTS (SELECT 1 FROM report_labels rl WHERE rl.report_id = r.id AND rl.label_id = ?)`)
		args = append(args, f.Label)
	}
	var order string
	switch f.Sort {
	case "top":
		order = doneSQL + `, r.score DESC, r.created_at DESC`
	case "neu":
		order = doneSQL + `, r.created_at DESC`
	default: // "hot": Stimmen relativ zum Alter, ähnlich Reddit
		order = doneSQL + `, (CAST(r.score AS REAL) + 1.0) / (((? - r.created_at) / 3600.0) + 2.0) DESC, r.created_at DESC`
		args = append(args, now())
	}
	// Erledigte Meldungen stehen immer am Ende, die zuletzt erledigten zuerst.
	order = strings.Replace(order, doneSQL+`, `, doneSQL+`, CASE WHEN `+doneSQL+` = 1 THEN -r.updated_at ELSE 0 END, `, 1)
	args = append(args, pageSize+1, (page-1)*pageSize)

	rows, err := a.db.Query(reportSelect("substr(r.body, 1, 400)")+` WHERE `+strings.Join(where, " AND ")+
		` ORDER BY `+order+` LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []Report
	for rows.Next() {
		r, err := scanReport(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, *r)
	}
	more := len(out) > pageSize
	if more {
		out = out[:pageSize]
	}
	for i := range out {
		if out[i].Done() && (i == 0 || !out[i-1].Done()) {
			out[i].FirstDone = i > 0 || page > 1 || f.Status == ""
			break
		}
	}
	return out, more, rows.Err()
}

func (a *App) attachmentsForReport(reportID int64) ([]Attachment, error) {
	rows, err := a.db.Query(`SELECT id, report_id, comment_id, uploader_id, scan, filename, content_type, size, storage_name, created_at
		FROM attachments WHERE report_id = ? ORDER BY id`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Attachment
	for rows.Next() {
		var at Attachment
		if err := rows.Scan(&at.ID, &at.ReportID, &at.CommentID, &at.UploaderID, &at.Scan, &at.Filename, &at.ContentType, &at.Size, &at.StorageName, &at.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, at)
	}
	return out, rows.Err()
}

func (a *App) attachmentByID(id int64) (*Attachment, error) {
	at := &Attachment{}
	err := a.db.QueryRow(`SELECT id, report_id, comment_id, uploader_id, scan, filename, content_type, size, storage_name, created_at
		FROM attachments WHERE id = ?`, id).
		Scan(&at.ID, &at.ReportID, &at.CommentID, &at.UploaderID, &at.Scan, &at.Filename, &at.ContentType, &at.Size, &at.StorageName, &at.CreatedAt)
	return at, err
}

func (a *App) commentsForReport(reportID int64) ([]Comment, error) {
	rows, err := a.db.Query(`SELECT c.id, c.author_id, COALESCE(NULLIF(u.display_name, ''), u.username), c.body, c.is_system, c.created_at,
			c.edited_at, c.deleted_at, COALESCE(c.deleted_by, 0)
		FROM comments c JOIN users u ON u.id = c.author_id
		WHERE c.report_id = ? ORDER BY c.created_at, c.id`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Comment
	for rows.Next() {
		var c Comment
		if err := rows.Scan(&c.ID, &c.AuthorID, &c.AuthorName, &c.Body, &c.IsSystem, &c.CreatedAt, &c.EditedAt, &c.DeletedAt, &c.DeletedBy); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
