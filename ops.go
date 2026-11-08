package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ======================= Virenscan (ClamAV / clamd) =======================

type ClamAVConfig struct {
	Addr     string // tcp://host:3310, host:3310 oder unix:///run/clamav/clamd.ctl
	Required bool   // true: Upload ablehnen, wenn clamd nicht erreichbar ist
}

func loadClamAVConfig() ClamAVConfig {
	return ClamAVConfig{Addr: getenv("MS_CLAMAV_ADDR", ""), Required: getbool("MS_CLAMAV_REQUIRED", true)}
}

type virusScanner interface {
	Scan(ctx context.Context, r io.Reader) (signature string, err error)
	Ping(ctx context.Context) error
}

type clamd struct{ cfg ClamAVConfig }

func (c *clamd) dial(ctx context.Context) (net.Conn, error) {
	network, addr := "tcp", c.cfg.Addr
	switch {
	case strings.HasPrefix(addr, "unix://"):
		network, addr = "unix", strings.TrimPrefix(addr, "unix://")
	case strings.HasPrefix(addr, "tcp://"):
		addr = strings.TrimPrefix(addr, "tcp://")
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(2 * time.Minute))
	return conn, nil
}

func (c *clamd) Ping(ctx context.Context) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("zPING\x00")); err != nil {
		return err
	}
	reply, _ := io.ReadAll(io.LimitReader(conn, 64))
	if !bytes.HasPrefix(reply, []byte("PONG")) {
		return fmt.Errorf("unerwartete Antwort: %q", reply)
	}
	return nil
}

// Scan streamt die Datei per INSTREAM an clamd. Rückgabe: "" = sauber, sonst der Signaturname.
func (c *clamd) Scan(ctx context.Context, r io.Reader) (string, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return "", err
	}
	buf := make([]byte, 64<<10)
	size := make([]byte, 4)
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(size, uint32(n))
			if _, err := conn.Write(size); err != nil {
				return "", err
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return "", err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", rerr
		}
	}
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return "", err
	}
	reply, err := io.ReadAll(io.LimitReader(conn, 1024))
	if err != nil {
		return "", err
	}
	res := strings.TrimRight(string(reply), "\x00\r\n ")
	res = strings.TrimPrefix(res, "stream: ")
	switch {
	case res == "OK":
		return "", nil
	case strings.HasSuffix(res, " FOUND"):
		return strings.TrimSuffix(res, " FOUND"), nil
	}
	return "", fmt.Errorf("clamd: %s", res)
}

// scanUploads prüft alle Dateien vor dem Speichern. Bei öffentlichen Meldungen wird Schadsoftware
// abgelehnt. In vertraulichen Sicherheitsmeldungen sind Exploits und Proof-of-Concepts legitim:
// Sie werden angenommen, aber markiert und nie inline angezeigt.
// Rückgabe: Scan-Ergebnis je Datei sowie eine Fehlermeldung für den Nutzer.
func (a *App) scanUploads(ctx context.Context, files []*multipart.FileHeader, confidential bool) ([]string, string) {
	results := make([]string, len(files))
	if a.scanner == nil {
		return results, ""
	}
	for i, fh := range files {
		f, err := fh.Open()
		if err != nil {
			return nil, "Datei konnte nicht gelesen werden."
		}
		sig, err := a.scanner.Scan(ctx, f)
		f.Close()
		switch {
		case err != nil:
			slog.Error("Virenscan", "datei", fh.Filename, "err", err)
			if a.cfg.ClamAV.Required {
				return nil, "Der Virenscanner ist gerade nicht erreichbar. Anhänge können deshalb nicht angenommen werden, bitte später erneut versuchen."
			}
		case sig != "":
			if !confidential {
				return nil, fmt.Sprintf("%q wurde vom Virenscanner als Schadsoftware erkannt (%s) und nicht angenommen. Exploits und Proof-of-Concepts bitte als Sicherheitsmeldung einreichen.",
					sanitizeFilename(fh.Filename), cleanLine(sig, 120))
			}
			results[i] = "FOUND:" + cleanLine(sig, 200)
		default:
			results[i] = "clean"
		}
	}
	return results, ""
}

// ======================= Begrenzungen =======================

type LimitConfig struct {
	ReportsPerHour int
	RepliesPerHour int
}

// overLimit prüft, ob ein Nutzer in der letzten Stunde zu viele Beiträge verfasst hat.
// Entwickler und Administratoren sind ausgenommen.
func (a *App) overLimit(u *User, what string) (bool, int) {
	if u.IsAdmin || a.isAnyDeveloper(u.ID) {
		return false, 0
	}
	since := now() - 3600
	var n, max int
	switch what {
	case "report":
		max = a.cfg.Limits.ReportsPerHour
		a.db.QueryRow(`SELECT COUNT(*) FROM reports WHERE author_id = ? AND created_at > ?`, u.ID, since).Scan(&n)
	default:
		max = a.cfg.Limits.RepliesPerHour
		a.db.QueryRow(`SELECT COUNT(*) FROM comments WHERE author_id = ? AND is_system = 0 AND created_at > ?`, u.ID, since).Scan(&n)
	}
	return max > 0 && n >= max, max
}

// ======================= Sicherung & Wiederherstellung =======================

type BackupConfig struct {
	Dir      string
	Interval time.Duration
	Keep     int
}

func loadBackupConfig() BackupConfig {
	return BackupConfig{
		Dir:      getenv("MS_BACKUP_DIR", ""),
		Interval: time.Duration(getint("MS_BACKUP_INTERVAL_HOURS", 24)) * time.Hour,
		Keep:     getint("MS_BACKUP_KEEP", 14),
	}
}

var storageNameRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// writeBackup erzeugt ein tar.gz mit einem konsistenten Datenbank-Abzug (VACUUM INTO, auch im
// laufenden Betrieb) und allen Anhängen.
func writeBackup(ctx context.Context, cfg Config, out string) (int, error) {
	tmpDB := out + ".db.tmp"
	os.Remove(tmpDB)
	defer os.Remove(tmpDB)

	db, err := openDB(dbPath(cfg))
	if err != nil {
		return 0, err
	}
	_, err = db.ExecContext(ctx, `VACUUM INTO ?`, tmpDB)
	db.Close()
	if err != nil {
		return 0, fmt.Errorf("Datenbank-Abzug: %w", err)
	}

	f, err := os.OpenFile(out+".part", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	add := func(src, name string) error {
		st, err := os.Stat(src)
		if err != nil {
			return err
		}
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: st.Size(), ModTime: st.ModTime(), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err = io.Copy(tw, in)
		return err
	}
	files := 0
	err = add(tmpDB, "meldestelle.db")
	if err == nil {
		entries, _ := os.ReadDir(filepath.Join(cfg.DataDir, "anhaenge"))
		for _, e := range entries {
			if !e.Type().IsRegular() || !storageNameRe.MatchString(e.Name()) {
				continue
			}
			if err = add(filepath.Join(cfg.DataDir, "anhaenge", e.Name()), "anhaenge/"+e.Name()); err != nil {
				if errors.Is(err, os.ErrNotExist) { // zwischenzeitlich gelöscht
					err = nil
					continue
				}
				break
			}
			files++
		}
	}
	if err == nil {
		err = tw.Close()
	}
	if err == nil {
		err = gz.Close()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(out + ".part")
		return 0, err
	}
	return files, os.Rename(out+".part", out)
}

func backupCmd(cfg Config, args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	out := fs.String("out", "meldestelle-"+time.Now().Format("20060102-150405")+".tar.gz", "Zieldatei")
	_ = fs.Parse(args)
	n, err := writeBackup(context.Background(), cfg, *out)
	if err != nil {
		return err
	}
	fmt.Printf("Sicherung geschrieben: %s (Datenbank und %d Anhänge)\n", *out, n)
	return nil
}

func restoreCmd(cfg Config, args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	in := fs.String("in", "", "Sicherungsdatei (.tar.gz)")
	force := fs.Bool("force", false, "vorhandene Daten überschreiben")
	_ = fs.Parse(args)
	if *in == "" {
		return errors.New("-in fehlt")
	}
	if _, err := os.Stat(dbPath(cfg)); err == nil && !*force {
		return fmt.Errorf("in %s existiert bereits eine Datenbank. Server stoppen und mit -force überschreiben", cfg.DataDir)
	}
	f, err := os.Open(*in)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)

	stage := filepath.Join(cfg.DataDir, ".restore")
	os.RemoveAll(stage)
	if err := os.MkdirAll(filepath.Join(stage, "anhaenge"), 0o750); err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	hasDB, files := false, 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// Nur bekannte Namen annehmen – schützt vor Pfad-Tricks im Archiv.
		var target string
		switch {
		case h.Name == "meldestelle.db":
			target, hasDB = filepath.Join(stage, "meldestelle.db"), true
		case strings.HasPrefix(h.Name, "anhaenge/") && storageNameRe.MatchString(strings.TrimPrefix(h.Name, "anhaenge/")):
			target = filepath.Join(stage, "anhaenge", strings.TrimPrefix(h.Name, "anhaenge/"))
			files++
		default:
			return fmt.Errorf("unerwarteter Eintrag im Archiv: %q", h.Name)
		}
		if h.Typeflag != tar.TypeReg {
			return fmt.Errorf("unerwarteter Eintragstyp: %q", h.Name)
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, tr)
		out.Close()
		if err != nil {
			return err
		}
	}
	if !hasDB {
		return errors.New("das Archiv enthält keine Datenbank")
	}
	// Prüfen, ob die Datenbank lesbar ist, bevor etwas ersetzt wird.
	db, err := openDB(filepath.Join(stage, "meldestelle.db"))
	if err != nil {
		return fmt.Errorf("Datenbank im Archiv ist beschädigt: %w", err)
	}
	var ok string
	db.QueryRow(`PRAGMA integrity_check`).Scan(&ok)
	db.Close()
	if ok != "ok" {
		return fmt.Errorf("Integritätsprüfung fehlgeschlagen: %s", ok)
	}
	os.Remove(filepath.Join(stage, "meldestelle.db-wal"))
	os.Remove(filepath.Join(stage, "meldestelle.db-shm"))

	for _, suffix := range []string{"", "-wal", "-shm"} {
		os.Remove(dbPath(cfg) + suffix)
	}
	if err := os.Rename(filepath.Join(stage, "meldestelle.db"), dbPath(cfg)); err != nil {
		return err
	}
	attach := filepath.Join(cfg.DataDir, "anhaenge")
	os.RemoveAll(attach)
	if err := os.Rename(filepath.Join(stage, "anhaenge"), attach); err != nil {
		return err
	}
	fmt.Printf("Wiederhergestellt: Datenbank und %d Anhänge nach %s\n", files, cfg.DataDir)
	return nil
}

func (a *App) backupLoop(ctx context.Context) {
	if err := os.MkdirAll(a.cfg.Backup.Dir, 0o750); err != nil {
		slog.Error("Sicherungsverzeichnis", "err", err)
		return
	}
	run := func() {
		out := filepath.Join(a.cfg.Backup.Dir, "meldestelle-"+time.Now().Format("20060102-150405")+".tar.gz")
		n, err := writeBackup(ctx, a.cfg, out)
		if err != nil {
			slog.Error("Automatische Sicherung fehlgeschlagen", "err", err)
			return
		}
		slog.Info("Sicherung erstellt", "datei", out, "anhaenge", n)
		pruneBackups(a.cfg.Backup.Dir, a.cfg.Backup.Keep)
	}
	// Erste Sicherung erst, wenn die letzte älter als das Intervall ist.
	wait := time.Duration(0)
	if last := lastBackup(a.cfg.Backup.Dir); !last.IsZero() {
		wait = time.Until(last.Add(a.cfg.Backup.Interval))
	}
	timer := time.NewTimer(max(wait, time.Minute))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			run()
			timer.Reset(a.cfg.Backup.Interval)
		}
	}
}

func backupFiles(dir string) []string {
	m, _ := filepath.Glob(filepath.Join(dir, "meldestelle-*.tar.gz"))
	sort.Strings(m)
	return m
}

func lastBackup(dir string) time.Time {
	files := backupFiles(dir)
	if len(files) == 0 {
		return time.Time{}
	}
	st, err := os.Stat(files[len(files)-1])
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}

func pruneBackups(dir string, keep int) {
	files := backupFiles(dir)
	for i := 0; keep > 0 && i < len(files)-keep; i++ {
		os.Remove(files[i])
	}
}
