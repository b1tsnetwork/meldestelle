# Meldestelle

[![CI](https://github.com/b1tk1ll3r/meldestelle/actions/workflows/ci.yml/badge.svg)](https://github.com/b1tk1ll3r/meldestelle/actions/workflows/ci.yml)
[![Release](https://github.com/b1tk1ll3r/meldestelle/actions/workflows/release.yml/badge.svg)](https://github.com/b1tk1ll3r/meldestelle/actions/workflows/release.yml)

Webbasierte Melde-Anwendung in Go für **Bugs** und **Feature-Wünsche** – öffentlich sichtbar und per Upvote bewertbar (ähnlich Reddit).
**Sicherheitslücken und Exploits** sind vertraulich und nur für die zuständigen Entwickler sichtbar.

## Funktionen

- Meldungen pro Software: Bug, Feature, Sicherheitslücke/Exploit, optionale Versionsangabe
- Upvotes (eine Stimme pro Benutzer, umschaltbar), Sortierung *Beliebt* / *Meiste Stimmen* / *Neueste*
- Filter nach Software, Art, Status, Volltextsuche, „Nur meine“
- Kommentare mit Anhängen, automatische Verlaufseinträge bei Status-/Art-Änderungen
- **Entwickler pro Software**: dürfen Status/Art ändern, Meldungen vertraulich machen oder veröffentlichen, löschen
- Anmeldung über **lokale Konten** und/oder **OpenID Connect** (PKCE, Nonce; Admin-Rechte optional über eine IdP-Gruppe)
- Verwaltung: Software anlegen, Entwickler zuordnen, Benutzer zu Admins machen oder sperren
- Eigenständige Oberfläche mit selbst gehosteten Schriften (Barlow, SIL OFL), Hell- und Dunkelmodus, mobiltauglich
- SQLite (reines Go, kein CGO), einzelnes Binary mit eingebetteten Templates, Docker-Image auf distroless-Basis

## Sichtbarkeitsregeln

| Meldung | Sichtbar für |
|---|---|
| Bug / Feature | alle, auch ohne Anmeldung |
| Sicherheit / vertraulich | Autor, Entwickler **dieser** Software, Administratoren |

- Vertrauliche Meldungen erscheinen weder in Listen, Suche noch Filtern und liefern für Unbefugte **404** (ihre Existenz ist nicht erkennbar).
- Anhänge erben die Sichtbarkeit ihrer Meldung.
- Wird eine Meldung zu „Sicherheit“ umgestuft, wird sie automatisch vertraulich. Nach dem Fix kann ein Entwickler sie bewusst veröffentlichen.
- Vertrauliche Meldungen können nicht bewertet werden.

Die Regel steckt zentral in `canView` und `visibilitySQL` (`models.go`); `main_test.go` prüft sie Ende-zu-Ende.

## Schnellstart

```bash
go build -o meldestelle .
MS_ADMIN_PASSWORD='ein-langes-passwort' ./meldestelle create-admin -user admin
./meldestelle serve          # http://localhost:8080
```

Danach unter **Verwaltung** Software anlegen und Entwickler zuordnen (Benutzer müssen sich vorher einmal registriert oder per SSO angemeldet haben).

### Docker

Fertige Images für `linux/amd64` und `linux/arm64` liegen in der GitHub Container Registry:

```bash
docker pull ghcr.io/b1tk1ll3r/meldestelle:latest   # letztes Release
docker pull ghcr.io/b1tk1ll3r/meldestelle:edge     # aktueller Stand von main
```

Oder selbst bauen:

```bash
cp .env.example .env         # anpassen
docker compose up -d --build
docker compose exec meldestelle /meldestelle create-admin -user admin
```

Daten (SQLite-Datenbank und Anhänge) liegen im Volume `meldestelle-data` unter `/data`.

### Hinter Caddy

```caddyfile
meldungen.example.de {
	request_body {
		max_size 110MB
	}
	reverse_proxy 127.0.0.1:8080
}
```

`MS_TRUST_PROXY=true` setzen, damit der Brute-Force-Schutz die echte Client-IP nutzt.

## Konfiguration

| Variable | Standard | Bedeutung |
|---|---|---|
| `MS_BASE_URL` | `http://localhost:8080` | Öffentliche URL; `https://` aktiviert Secure-Cookies + HSTS |
| `MS_LISTEN` | `:8080` | Listen-Adresse |
| `MS_DATA_DIR` | `./data` | Datenbank und Anhänge |
| `MS_APP_NAME` | `Meldestelle` | Name in der Oberfläche |
| `MS_TRUST_PROXY` | `false` | `X-Forwarded-For` auswerten |
| `MS_LOCAL_LOGIN` | `true` | Lokale Anmeldung erlauben |
| `MS_ALLOW_REGISTRATION` | `true` | Selbstregistrierung erlauben |
| `MS_MAX_UPLOAD_MB` | `20` | Maximale Größe pro Anhang |
| `MS_MAX_FILES` | `5` | Maximale Anhänge pro Beitrag |
| `MS_OIDC_ISSUER` | – | Issuer-URL (aktiviert OIDC zusammen mit Client-ID) |
| `MS_OIDC_CLIENT_ID` | – | Client-ID |
| `MS_OIDC_CLIENT_SECRET` / `_FILE` | – | Client-Secret (oder Pfad zu Docker-Secret) |
| `MS_OIDC_REDIRECT_URL` | `<BASE_URL>/auth/oidc/callback` | Redirect-URI, im IdP eintragen |
| `MS_OIDC_LABEL` | `Mit SSO anmelden` | Beschriftung des Buttons |
| `MS_OIDC_ADMIN_GROUP` | – | Mitglieder werden Admins (wird bei jeder Anmeldung synchronisiert) |
| `MS_OIDC_GROUPS_CLAIM` | `groups` | Claim im ID-Token mit den Gruppen |
| `MS_OIDC_SCOPES` | `openid profile email` | Angeforderte Scopes |

Wenn nur SSO gewünscht ist: `MS_LOCAL_LOGIN=false`. Admins kommen dann über `MS_OIDC_ADMIN_GROUP`.

## Sicherheit

- Sitzungs-Cookies `HttpOnly`, `SameSite=Lax`, nur gehashte Tokens in der Datenbank
- CSRF-Schutz (Double-Submit-Token + Origin-Prüfung) für alle schreibenden Anfragen
- bcrypt-Passwörter, Brute-Force-Begrenzung pro IP und Benutzer, konstante Laufzeit bei unbekannten Benutzern
- Strikte CSP ohne Inline-Skripte; Anhänge werden mit Zufallsnamen gespeichert und mit `sandbox`-CSP, `nosniff` und – außer bei PNG/JPEG/GIF/WebP – als Download ausgeliefert
- Keine offenen Weiterleitungen

## Entwicklung

```bash
go test ./...
./meldestelle version
```

## CI und Releases

| Workflow | Auslöser | Was passiert |
|---|---|---|
| `ci.yml` | Push auf `main`, Pull Requests | gofmt, `go mod tidy`, `go vet`, Tests mit Race-Detector, govulncheck; bei PRs zusätzlich ein Docker-Testbuild |
| `release.yml` | Push auf `main` | Tests, dann Image `ghcr.io/b1tk1ll3r/meldestelle:edge` und `:sha-<commit>` |
| `release.yml` | Tag `v*` | Tests, Image `:1.2.3`, `:1.2`, `:1` und `:latest`, GitHub-Release mit Binaries für Linux, Windows und macOS samt `SHA256SUMS` |

Ein Release erstellen:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Tags mit Bindestrich (z. B. `v0.2.0-rc1`) werden als Vorabversion veröffentlicht und setzen `latest` nicht. Bei `v0.x` entfällt das reine Major-Tag `:0`.

Images und Binaries erhalten signierte Herkunftsnachweise (SLSA Build Provenance) und Images zusätzlich eine SBOM. Prüfen lässt sich das mit:

```bash
gh attestation verify oci://ghcr.io/b1tk1ll3r/meldestelle:latest --repo b1tk1ll3r/meldestelle
gh attestation verify meldestelle_0.1.0_linux_amd64.tar.gz --repo b1tk1ll3r/meldestelle
```

Dependabot hält Go-Module, Actions und Basis-Images wöchentlich aktuell.

Nach dem ersten Image-Push ist das Paket in GHCR privat. Unter *Packages → meldestelle → Package settings* kann es auf öffentlich gestellt werden.

## Ideen für später

- E-Mail-Benachrichtigungen an Entwickler bei neuen Sicherheitsmeldungen
- Markdown-Rendering, Duplikat-Verknüpfung, Labels
- Entwickler dürfen weitere Entwickler ihrer Software ernennen
