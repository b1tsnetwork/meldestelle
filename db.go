package main

import (
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

func now() int64 { return time.Now().Unix() }

func dbPath(cfg Config) string { return filepath.Join(cfg.DataDir, "meldestelle.db") }

func openDB(path string) (*sql.DB, error) {
	q := url.Values{}
	for _, p := range []string{"foreign_keys(1)", "journal_mode(WAL)", "busy_timeout(10000)", "synchronous(NORMAL)"} {
		q.Add("_pragma", p)
	}
	q.Set("_txlock", "immediate")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("Migration: %w", err)
	}
	return db, nil
}

var migrations = []string{
	`
CREATE TABLE users (
	id            INTEGER PRIMARY KEY,
	username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
	email         TEXT    NOT NULL DEFAULT '',
	display_name  TEXT    NOT NULL DEFAULT '',
	password_hash TEXT    NOT NULL DEFAULT '',
	oidc_issuer   TEXT    NOT NULL DEFAULT '',
	oidc_subject  TEXT    NOT NULL DEFAULT '',
	is_admin      INTEGER NOT NULL DEFAULT 0,
	disabled      INTEGER NOT NULL DEFAULT 0,
	created_at    INTEGER NOT NULL
);
CREATE UNIQUE INDEX users_oidc ON users (oidc_issuer, oidc_subject) WHERE oidc_subject <> '';

CREATE TABLE sessions (
	token_hash TEXT    PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	expires_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions (user_id);

CREATE TABLE software (
	id          INTEGER PRIMARY KEY,
	slug        TEXT    NOT NULL UNIQUE,
	name        TEXT    NOT NULL,
	description TEXT    NOT NULL DEFAULT '',
	created_at  INTEGER NOT NULL
);

CREATE TABLE developers (
	software_id INTEGER NOT NULL REFERENCES software (id) ON DELETE CASCADE,
	user_id     INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	PRIMARY KEY (software_id, user_id)
);
CREATE INDEX developers_user ON developers (user_id);

CREATE TABLE reports (
	id           INTEGER PRIMARY KEY,
	software_id  INTEGER NOT NULL REFERENCES software (id) ON DELETE CASCADE,
	author_id    INTEGER NOT NULL REFERENCES users (id),
	kind         TEXT    NOT NULL CHECK (kind IN ('bug', 'feature', 'security')),
	status       TEXT    NOT NULL DEFAULT 'open',
	title        TEXT    NOT NULL,
	body         TEXT    NOT NULL,
	version      TEXT    NOT NULL DEFAULT '',
	confidential INTEGER NOT NULL DEFAULT 0,
	score        INTEGER NOT NULL DEFAULT 0,
	created_at   INTEGER NOT NULL,
	updated_at   INTEGER NOT NULL
);
CREATE INDEX reports_software ON reports (software_id, created_at);
CREATE INDEX reports_author ON reports (author_id);

CREATE TABLE votes (
	report_id  INTEGER NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
	user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	created_at INTEGER NOT NULL,
	PRIMARY KEY (report_id, user_id)
);

CREATE TABLE comments (
	id         INTEGER PRIMARY KEY,
	report_id  INTEGER NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
	author_id  INTEGER NOT NULL REFERENCES users (id),
	body       TEXT    NOT NULL,
	is_system  INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL
);
CREATE INDEX comments_report ON comments (report_id, created_at);

CREATE TABLE attachments (
	id           INTEGER PRIMARY KEY,
	report_id    INTEGER NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
	comment_id   INTEGER REFERENCES comments (id) ON DELETE CASCADE,
	uploader_id  INTEGER NOT NULL REFERENCES users (id),
	filename     TEXT    NOT NULL,
	content_type TEXT    NOT NULL,
	size         INTEGER NOT NULL,
	sha256       TEXT    NOT NULL,
	storage_name TEXT    NOT NULL UNIQUE,
	created_at   INTEGER NOT NULL
);
CREATE INDEX attachments_report ON attachments (report_id);
`,
	// 2: LDAP-Konten, verknüpft über eine unveränderliche Verzeichnis-ID
	`
ALTER TABLE users ADD COLUMN ldap_id TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX users_ldap ON users (ldap_id) WHERE ldap_id <> '';
`,
	// 3: Benachrichtigungen, Folgen, Labels, Zuständigkeit, Duplikate, Bearbeiten/Moderation, Virenscan
	`
ALTER TABLE reports ADD COLUMN duplicate_of INTEGER REFERENCES reports (id) ON DELETE SET NULL;
ALTER TABLE reports ADD COLUMN assignee_id INTEGER REFERENCES users (id) ON DELETE SET NULL;
ALTER TABLE reports ADD COLUMN fixed_in TEXT NOT NULL DEFAULT '';
ALTER TABLE reports ADD COLUMN edited_at INTEGER NOT NULL DEFAULT 0;
CREATE INDEX reports_duplicate ON reports (duplicate_of) WHERE duplicate_of IS NOT NULL;
CREATE INDEX reports_assignee ON reports (assignee_id) WHERE assignee_id IS NOT NULL;

ALTER TABLE comments ADD COLUMN edited_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE comments ADD COLUMN deleted_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE comments ADD COLUMN deleted_by INTEGER REFERENCES users (id) ON DELETE SET NULL;

ALTER TABLE attachments ADD COLUMN scan TEXT NOT NULL DEFAULT '';

ALTER TABLE users ADD COLUMN notify_new INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN notify_follow INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN notify_assign INTEGER NOT NULL DEFAULT 1;

CREATE TABLE labels (
	id          INTEGER PRIMARY KEY,
	software_id INTEGER NOT NULL REFERENCES software (id) ON DELETE CASCADE,
	name        TEXT    NOT NULL,
	color       INTEGER NOT NULL DEFAULT 1,
	UNIQUE (software_id, name COLLATE NOCASE)
);

CREATE TABLE report_labels (
	report_id INTEGER NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
	label_id  INTEGER NOT NULL REFERENCES labels (id) ON DELETE CASCADE,
	PRIMARY KEY (report_id, label_id)
);
CREATE INDEX report_labels_label ON report_labels (label_id);

CREATE TABLE follows (
	report_id  INTEGER NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
	user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	created_at INTEGER NOT NULL,
	PRIMARY KEY (report_id, user_id)
);
CREATE INDEX follows_user ON follows (user_id);

-- Bestehende Meldungen: Autoren und Antwortende folgen automatisch
INSERT OR IGNORE INTO follows (report_id, user_id, created_at) SELECT id, author_id, created_at FROM reports;
INSERT OR IGNORE INTO follows (report_id, user_id, created_at)
	SELECT report_id, author_id, MIN(created_at) FROM comments WHERE is_system = 0 GROUP BY report_id, author_id;

CREATE TABLE outbox (
	id         INTEGER PRIMARY KEY,
	recipient  TEXT    NOT NULL,
	subject    TEXT    NOT NULL,
	body       TEXT    NOT NULL,
	thread     TEXT    NOT NULL DEFAULT '',
	attempts   INTEGER NOT NULL DEFAULT 0,
	next_try   INTEGER NOT NULL,
	last_error TEXT    NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	sent_at    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX outbox_pending ON outbox (sent_at, next_try);
`,
}

func migrate(db *sql.DB) error {
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	for i := v; i < len(migrations); i++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("Schritt %d: %w", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
