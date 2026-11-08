package main

import (
	"math"
	"net/http"
	"sort"
	"strings"
	"unicode"
)

// Duplikatsfinder: schlägt beim Erfassen einer Meldung bereits vorhandene, öffentliche Meldungen
// derselben Software vor. Die Bewertung kombiniert
//   - Normalisierung (Kleinschreibung, Umlaute, Stoppwörter, einfaches Stemming für Deutsch/Englisch),
//   - IDF-Gewichtung (seltene Begriffe zählen mehr als häufige),
//   - Teilwort-Treffer für zusammengesetzte Wörter („Telefonbuchsuche“ ↔ „Suche“),
//   - Trigramm-Ähnlichkeit für Tippfehler („Inaktivitat“ ↔ „Inaktivität“).
// Vertrauliche Meldungen werden nie vorgeschlagen.

type similarHit struct {
	ID      int64   `json:"id"`
	Title   string  `json:"title"`
	Kind    string  `json:"kind"`
	KindL   string  `json:"kindLabel"`
	Status  string  `json:"status"`
	StatusL string  `json:"statusLabel"`
	Score   int     `json:"score"`
	Voted   bool    `json:"voted"`
	Done    bool    `json:"done"`
	Answers int     `json:"answers"`
	Excerpt string  `json:"excerpt"`
	Match   float64 `json:"match"`
}

var stopwords = func() map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(`
		der die das den dem des ein eine einer eines einem einen und oder aber nicht kein keine keinen
		ist sind war waren wird werden wurde wurden bei beim mit ohne von vom zu zum zur im in ins an am auf aus
		für fuer über ueber unter nach vor wenn dann als auch noch nur schon sehr mehr man es er sie wir ich du ihr
		sich mich mir dich dir uns euch dass da wo wie was wer warum weil damit kann koennen können muss soll sollte
		hat haben hatte gibt geht gehen mal bitte immer wieder neue neuer neues neu
		the a an and or not no is are was were be been to of in on at for with without by from as it this that
		when if then can cannot doesnt dont does do into after before new please`) {
		m[foldWord(w)] = true
	}
	return m
}()

var umlauts = strings.NewReplacer("ä", "ae", "ö", "oe", "ü", "ue", "ß", "ss")

func foldWord(w string) string { return umlauts.Replace(strings.ToLower(w)) }

// synonyms fasst gleichbedeutende Begriffe (Deutsch/Englisch, Umgangssprache) zu einem Stamm zusammen.
var synonyms = func() map[string]string {
	groups := [][]string{
		{"dunkel", "dark", "darkmode", "nachtmodus", "schwarz"},
		{"theme", "design", "farbschema", "mode", "modus", "skin"},
		{"zwischenablage", "clipboard", "copy", "paste", "kopieren", "einfuegen", "kopiert", "eingefuegt"},
		{"anmeldung", "login", "logon", "einloggen", "signin", "anmelden", "angemeldet"},
		{"abmeldung", "logout", "ausloggen", "abmelden", "abgemeldet"},
		{"absturz", "crash", "abstuerzen", "abgestuerzt", "stuerzt", "crasht", "haengt", "freeze", "einfrieren"},
		{"langsam", "slow", "performance", "laggt", "lag", "traege", "dauert"},
		{"fehlermeldung", "error", "exception", "fehler"},
		{"passwort", "kennwort", "password", "pw"},
		{"drucker", "printer", "drucken", "druck", "print"},
		{"suche", "search", "suchen", "finden", "gefunden", "findet"},
		{"sitzung", "session"},
		{"verbindung", "connection", "connect", "verbinden", "getrennt", "disconnect", "trennt"},
		{"hochladen", "upload", "uploaden", "hochgeladen"},
		{"herunterladen", "download", "downloaden", "heruntergeladen"},
		{"benachrichtigung", "notification", "mail", "email"},
		{"einstellung", "settings", "option", "konfiguration", "config"},
		{"zertifikat", "certificate", "cert", "tls", "ssl"},
	}
	m := map[string]string{}
	for _, g := range groups {
		head := stem(foldWord(g[0]))
		for _, w := range g {
			m[stem(foldWord(w))] = head
		}
	}
	return m
}()

var suffixes = []string{"ungen", "ung", "heiten", "heit", "keiten", "keit", "lich", "isch", "ing", "ern", "en", "er", "es", "em", "ed", "e", "n", "s"}

func stem(w string) string {
	for _, s := range suffixes {
		if strings.HasSuffix(w, s) && len(w)-len(s) >= 4 {
			return w[:len(w)-len(s)]
		}
	}
	return w
}

func tokenize(s string) []string {
	s = foldWord(s)
	parts := strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	seen := map[string]bool{}
	var out []string
	for _, p := range parts {
		if len(p) < 2 || stopwords[p] {
			continue
		}
		t := stem(p)
		if c, ok := synonyms[t]; ok {
			t = c
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

func trigrams(w string) map[string]bool {
	w = " " + w + " "
	g := map[string]bool{}
	r := []rune(w)
	for i := 0; i+3 <= len(r); i++ {
		g[string(r[i:i+3])] = true
	}
	return g
}

func jaccard(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter := 0
	for k := range a {
		if b[k] {
			inter++
		}
	}
	return float64(inter) / float64(len(a)+len(b)-inter)
}

type simDoc struct {
	hit   similarHit
	title map[string]bool
	body  map[string]bool
	when  int64
}

// tokenMatch bewertet, wie gut ein Suchbegriff in einer Token-Menge vorkommt (0..1).
func tokenMatch(q string, qgrams map[string]bool, toks map[string]bool, gramCache map[string]map[string]bool) float64 {
	if toks[q] {
		return 1
	}
	best := 0.0
	for t := range toks {
		// Teilwort in Komposita, z. B. "telefonbuchsuch" enthält "such"
		if len(q) >= 4 && len(t) >= 4 && (strings.Contains(t, q) || strings.Contains(q, t)) {
			short := math.Min(float64(len(q)), float64(len(t)))
			long := math.Max(float64(len(q)), float64(len(t)))
			if v := 0.55 + 0.35*short/long; v > best {
				best = v
			}
			continue
		}
		if len(q) >= 4 && len(t) >= 4 {
			g, ok := gramCache[t]
			if !ok {
				g = trigrams(t)
				gramCache[t] = g
			}
			if j := jaccard(qgrams, g); j >= 0.45 && j*0.9 > best {
				best = j * 0.9
			}
		}
	}
	return best
}

func (a *App) findSimilar(u *User, softwareID int64, query string, limit int, exclude int64) ([]similarHit, error) {
	qtoks := tokenize(query)
	if len(qtoks) == 0 {
		return nil, nil
	}
	rows, err := a.db.Query(`SELECT r.id, r.title, substr(r.body, 1, 1500), r.kind, r.status, r.score, r.updated_at,
			(SELECT COUNT(*) FROM comments c WHERE c.report_id = r.id AND c.is_system = 0),
			EXISTS (SELECT 1 FROM votes v WHERE v.report_id = r.id AND v.user_id = ?)
		FROM reports r
		WHERE r.software_id = ? AND r.confidential = 0 AND r.duplicate_of IS NULL AND r.id <> ?
		ORDER BY r.updated_at DESC LIMIT 5000`, uid(u), softwareID, exclude)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var docs []simDoc
	df := map[string]int{}
	for rows.Next() {
		var d simDoc
		var body string
		h := &d.hit
		if err := rows.Scan(&h.ID, &h.Title, &body, &h.Kind, &h.Status, &h.Score, &d.when, &h.Answers, &h.Voted); err != nil {
			return nil, err
		}
		d.title, d.body = map[string]bool{}, map[string]bool{}
		for _, t := range tokenize(h.Title) {
			d.title[t] = true
		}
		for _, t := range tokenize(body) {
			d.body[t] = true
		}
		for _, q := range qtoks {
			if d.title[q] || d.body[q] {
				df[q]++
			}
		}
		h.Excerpt = body
		docs = append(docs, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	n := float64(len(docs))
	idf := make([]float64, len(qtoks))
	qgrams := make([]map[string]bool, len(qtoks))
	total := 0.0
	for i, q := range qtoks {
		idf[i] = math.Log(1 + (n+1)/(1+float64(df[q])))
		qgrams[i] = trigrams(q)
		total += idf[i]
	}

	cache := map[string]map[string]bool{}
	var hits []similarHit
	for _, d := range docs {
		sum, titleHits := 0.0, 0
		for i, q := range qtoks {
			m := tokenMatch(q, qgrams[i], d.title, cache)
			if m > 0.5 {
				titleHits++
			}
			if b := 0.45 * tokenMatch(q, qgrams[i], d.body, cache); b > m {
				m = b
			}
			sum += idf[i] * m
		}
		score := sum / total
		if titleHits == 0 {
			score *= 0.7 // nur im Text gefunden: schwächeres Signal
		}
		h := d.hit
		h.Done = doneStatuses[h.Status]
		if h.Done {
			score *= 0.9
		}
		if score < 0.34 {
			continue
		}
		h.Match = math.Round(score*100) / 100
		h.KindL, h.StatusL = label(kinds, h.Kind), label(statuses, h.Status)
		h.Excerpt = funcs["excerpt"].(func(string, int) string)(h.Excerpt, 140)
		hits = append(hits, h)
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].Match != hits[j].Match {
			return hits[i].Match > hits[j].Match
		}
		return hits[i].Score > hits[j].Score
	})
	if len(hits) > limit {
		hits = hits[:limit]
	}
	return hits, nil
}

func (a *App) handleSimilar(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	title := cleanLine(q.Get("q"), 200)
	sid := parseID(q.Get("software"))
	if sid == 0 || len([]rune(title)) < 3 {
		writeJSON(w, http.StatusOK, []similarHit{})
		return
	}
	hits, err := a.findSimilar(currentUser(r), sid, title, 5, parseID(q.Get("ohne")))
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	if hits == nil {
		hits = []similarHit{}
	}
	writeJSON(w, http.StatusOK, hits)
}
