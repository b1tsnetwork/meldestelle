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
