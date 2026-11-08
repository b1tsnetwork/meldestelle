package main

import (
	"context"
	"testing"
)

func TestDuplikatsfinder(t *testing.T) {
	cfg := loadConfig()
	cfg.DataDir = t.TempDir()
	app, err := newApp(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	db := app.db
	db.Exec(`INSERT INTO users (id, username, created_at) VALUES (1, 'u', 0)`)
	db.Exec(`INSERT INTO software (id, slug, name, created_at) VALUES (1, 'sg', 'SessionGuard', 0), (2, 'tb', 'Telefonbuch', 0)`)
	add := func(id, sw int, title, body string, conf bool, status string) {
		_, err := db.Exec(`INSERT INTO reports (id, software_id, author_id, kind, status, title, body, confidential, created_at, updated_at)
			VALUES (?, ?, 1, 'bug', ?, ?, ?, ?, 0, 0)`, id, sw, status, title, body, conf)
		if err != nil {
			t.Fatal(err)
		}
	}
	add(1, 1, "Session bricht nach 10 Minuten Inaktivität ab", "Die RDP-Sitzung wird getrennt, obwohl das Timeout auf 60 Minuten steht.", false, "open")
	add(2, 1, "Dunkles Theme für die Guacamole-Oberfläche", "Oberfläche soll sich dem System-Theme anpassen.", false, "open")
	add(3, 1, "Zwischenablage funktioniert nicht unter Firefox", "Copy & Paste zwischen Client und Server geht nicht.", false, "fixed")
	add(4, 1, "Anmeldung über manipulierten Session-Header umgehen", "Exploit im Anhang.", true, "open")
	add(5, 2, "Telefonbuchsuche findet keine Durchwahlen mit Bindestrich", "02103-123 liefert keinen Treffer.", false, "open")
	add(6, 2, "Session läuft nach Inaktivität ab", "Im Telefonbuch muss man sich ständig neu anmelden.", false, "open")

	cases := []struct {
		sw    int64
		query string
		want  int64 // 0 = kein Treffer erwartet
	}{
		{1, "Sitzung wird nach Inaktivität getrennt", 1},             // Treffer über Text und Titel
		{1, "Verbindung bricht ab nach paar Minuten inaktivitat", 1}, // Tippfehler ohne Umlaut
		{1, "Dark Mode / dunkles Design", 2},
		{1, "Theme dunkel", 2},
		{1, "Copy Paste geht nicht", 3}, // erledigt, aber trotzdem vorgeschlagen
		{1, "Zwischenablage kaputt", 3},
		{2, "Suche nach Durchwahl mit Bindestrich", 5}, // Kompositum Telefonbuchsuche
		{2, "Durchwahlen werden nicht gefunden", 5},
		{1, "Drucker druckt nicht", 0},        // keine sinnvolle Übereinstimmung
		{1, "Session-Header manipulieren", 0}, // nur vertraulich vorhanden: darf nie auftauchen
		{1, "die und das", 0},                 // nur Stoppwörter
	}
	for _, c := range cases {
		hits, err := app.findSimilar(nil, c.sw, c.query, 5, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range hits {
			if h.ID == 4 {
				t.Errorf("%q: vertrauliche Meldung vorgeschlagen", c.query)
			}
			if c.sw == 1 && (h.ID == 5 || h.ID == 6) {
				t.Errorf("%q: Meldung einer anderen Software vorgeschlagen", c.query)
			}
		}
		switch {
		case c.want == 0 && len(hits) > 0:
			t.Errorf("%q: kein Treffer erwartet, bekam #%d (%.2f)", c.query, hits[0].ID, hits[0].Match)
		case c.want != 0 && (len(hits) == 0 || hits[0].ID != c.want):
			got := "nichts"
			if len(hits) > 0 {
				got = "#" + itoa(hits[0].ID)
			}
			t.Errorf("%q: erwartet #%d, bekam %s %v", c.query, c.want, got, hits)
		}
	}
}
