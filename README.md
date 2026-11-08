# Meldestelle

[![CI](https://github.com/b1tk1ll3r/meldestelle/actions/workflows/ci.yml/badge.svg)](https://github.com/b1tk1ll3r/meldestelle/actions/workflows/ci.yml)
[![Release](https://github.com/b1tk1ll3r/meldestelle/actions/workflows/release.yml/badge.svg)](https://github.com/b1tk1ll3r/meldestelle/actions/workflows/release.yml)

Webbasierte Melde-Anwendung in Go für **Bugs** und **Feature-Wünsche** – öffentlich sichtbar und per Upvote bewertbar (ähnlich Reddit).
**Sicherheitslücken und Exploits** sind vertraulich und nur für die zuständigen Entwickler sichtbar.

## Funktionen

- Meldungen pro Software: Bug, Feature, Sicherheitslücke/Exploit, optionale Versionsangabe
- Upvotes (eine Stimme pro Benutzer, umschaltbar), Sortierung *Beliebt* / *Meiste Stimmen* / *Neueste*
- Filter nach Software, Art, Status, Label, Volltextsuche, „Nur meine“, „Mir zugewiesen“
- **Markdown** in Meldungen und Antworten (Codeblöcke für Logs und Stacktraces, Listen, Tabellen) mit Vorschau
- Antworten mit Anhängen; Änderungen landen im eingeklappten Änderungsverlauf
- **Meldung folgen** und **E-Mail-Benachrichtigungen** (neue Meldungen, Antworten, Änderungen, Zuweisungen)
- **Bearbeiten und Löschen** eigener Meldungen und Antworten, Moderation durch Entwickler, einzelne Anhänge entfernen
- **Duplikate verknüpfen**: Stimmen und Folgende wandern zum Original, beide Seiten verweisen aufeinander
- **Labels** pro Software, **Zuständigkeit** und **„Behoben in Version“**
- Duplikatsfinder beim Melden: schlägt passende Meldungen der gewählten Software zum Unterstützen vor
- **Entwickler pro Software**: dürfen Meldungen bearbeiten, zuweisen, labeln, vertraulich machen oder veröffentlichen, löschen
- Betrieb: **Sicherung/Wiederherstellung** (auch automatisch), **ClamAV-Virenscan** der Anhänge, Begrenzung von Beiträgen pro Stunde
- Anmeldung über **lokale Konten**, **LDAP/Active Directory** und/oder **OpenID Connect** (PKCE, Nonce), frei kombinierbar; Admin-Rechte optional über eine Verzeichnis- bzw. IdP-Gruppe
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

### LDAP / Active Directory

LDAP ist aktiv, sobald `MS_LDAP_URL` und `MS_LDAP_BASE_DN` gesetzt sind. Die Anmeldung erfolgt über das normale Formular mit Benutzername und Passwort.

| Variable | Standard | Bedeutung |
|---|---|---|
| `MS_LDAP_URL` | – | `ldaps://dc01.firma.local:636` oder `ldap://…:389` |
| `MS_LDAP_STARTTLS` | `false` | StartTLS bei `ldap://` (empfohlen statt Klartext) |
| `MS_LDAP_CA_FILE` | – | CA-Zertifikat (PEM) der Domäne, falls nicht im System hinterlegt |
| `MS_LDAP_BIND_DN` | – | Dienstkonto für die Suche, z. B. `CN=svc-meldestelle,OU=Dienste,DC=firma,DC=local` |
| `MS_LDAP_BIND_PASSWORD` / `_FILE` | – | Passwort des Dienstkontos |
| `MS_LDAP_BASE_DN` | – | Suchbasis, z. B. `DC=firma,DC=local` |
| `MS_LDAP_USER_FILTER` | sucht `sAMAccountName`, `userPrincipalName` oder `uid` | Filter mit Platzhalter `{username}` (wird maskiert) |
| `MS_LDAP_ATTR_USERNAME` | `sAMAccountName` | Attribut für den Benutzernamen (OpenLDAP: `uid`) |
| `MS_LDAP_ATTR_EMAIL` | `mail` | E-Mail, wird bei jeder Anmeldung abgeglichen |
| `MS_LDAP_ATTR_NAME` | `displayName` | Anzeigename beim ersten Login (OpenLDAP: `cn`) |
| `MS_LDAP_ATTR_ID` | automatisch | Stabile ID; automatisch `objectGUID` (AD), `entryUUID` (OpenLDAP), `ipaUniqueID` (FreeIPA) |
| `MS_LDAP_REQUIRED_GROUP` | – | Nur Mitglieder dieser Gruppe (DN) dürfen sich anmelden |
| `MS_LDAP_ADMIN_GROUP` | – | Mitglieder (DN) werden Administratoren, bei jeder Anmeldung synchronisiert |
| `MS_LDAP_NESTED_GROUPS` | `false` | Verschachtelte AD-Gruppen auflösen (`LDAP_MATCHING_RULE_IN_CHAIN`) |
| `MS_LDAP_HINT` | „Du kannst dich mit deinem Domänenkonto anmelden.“ | Hinweis im Anmeldeformular (leer = aus) |
| `MS_LDAP_TIMEOUT_SECONDS` | `10` | Zeitlimit für Verbindung und Abfragen |
| `MS_LDAP_INSECURE_SKIP_VERIFY` | `false` | Zertifikatsprüfung abschalten – nur zum Testen |

Beispiel für Active Directory:

```env
MS_LDAP_URL=ldaps://dc01.firma.local
MS_LDAP_CA_FILE=/run/secrets/firma-root-ca.pem
MS_LDAP_BIND_DN=CN=svc-meldestelle,OU=Dienstkonten,DC=firma,DC=local
MS_LDAP_BIND_PASSWORD_FILE=/run/secrets/ldap_bind
MS_LDAP_BASE_DN=DC=firma,DC=local
MS_LDAP_REQUIRED_GROUP=CN=GG-Meldestelle-Nutzer,OU=Gruppen,DC=firma,DC=local
MS_LDAP_ADMIN_GROUP=CN=GG-Meldestelle-Admins,OU=Gruppen,DC=firma,DC=local
MS_LDAP_NESTED_GROUPS=true
MS_ALLOW_REGISTRATION=false
```

Gesperrte und deaktivierte AD-Konten scheitern bereits am Bind. Das Dienstkonto braucht nur Leserechte.

Konfiguration prüfen, ohne den Server zu starten:

```bash
meldestelle ldap-test -user jdoe
```

Hinweise:

- Konten werden über die stabile Verzeichnis-ID verknüpft, nicht über den Namen. Umbenennungen und OU-Wechsel (z. B. Abteilungswechsel) behalten das Konto.
- Bei der Anmeldung wird zuerst ein lokales Konto mit diesem Namen und Passwort geprüft, danach LDAP. Ein lokal registriertes Konto kann ein Verzeichniskonto gleichen Namens nicht übernehmen. Belegt ein lokales Konto den Namen schon, bekommt das Verzeichniskonto einen Zusatz (`jdoe-2`). Mit LDAP daher am besten `MS_ALLOW_REGISTRATION=false` setzen.
- Mit `MS_LOCAL_LOGIN=false` sind nur noch Verzeichnis- und SSO-Konten möglich. Administratoren dann über `MS_LDAP_ADMIN_GROUP` bestimmen.

### E-Mail-Benachrichtigungen

Aktiv, sobald `MS_SMTP_HOST` und `MS_SMTP_FROM` gesetzt sind. E-Mails laufen über eine Warteschlange in der Datenbank und werden bei Fehlern bis zu sieben Mal wiederholt (1 Min. bis 12 Std.). Ein ausgefallener Mailserver blockiert also nie die Anwendung. Status und Testmail: *Verwaltung → Betrieb*.

| Variable | Standard | Bedeutung |
|---|---|---|
| `MS_SMTP_HOST` | – | Mailserver |
| `MS_SMTP_PORT` | `587` | Port |
| `MS_SMTP_TLS` | `starttls` | `starttls`, `tls` (implizit, Port 465) oder `none` |
| `MS_SMTP_USER` | – | Benutzer (leer = ohne Anmeldung, z. B. internes Relay) |
| `MS_SMTP_PASSWORD` / `_FILE` | – | Passwort |
| `MS_SMTP_FROM` | – | Absender, z. B. `Meldestelle <meldestelle@firma.de>` |

Wer was bekommt (jeweils im Konto abbestellbar):

- **Entwickler** einer Software: neue Meldungen dieser Software
- **Folgende** einer Meldung: Antworten und Änderungen. Meldende und Antwortende folgen automatisch, alle anderen per „Folgen“-Knopf.
- **Zuständige**: wenn ihnen eine Meldung zugewiesen wird
- Niemand bekommt E-Mails zu eigenen Aktionen.

Zu **vertraulichen Meldungen** enthält eine E-Mail nur Software, Nummer und Link, nie Titel oder Inhalt. Wird eine Meldung vertraulich, erhalten Folgende ohne Sichtrecht keine E-Mails mehr. E-Mails einer Meldung tragen dieselbe `References`-Kennung und erscheinen im Mailprogramm als ein Thread.

### Virenscan (ClamAV)

```env
MS_CLAMAV_ADDR=tcp://clamav:3310      # oder unix:///run/clamav/clamd.ctl
MS_CLAMAV_REQUIRED=true               # Uploads ablehnen, wenn clamd nicht erreichbar ist
```

Anhänge öffentlicher Meldungen, die ClamAV erkennt, werden abgelehnt. In **vertraulichen Sicherheitsmeldungen** sind Exploits und Proof-of-Concepts legitim: Sie werden angenommen, aber als Schadsoftware markiert, nie inline angezeigt und erst nach einer Rückfrage heruntergeladen.

### Begrenzung

| Variable | Standard | Bedeutung |
|---|---|---|
| `MS_LIMIT_REPORTS_PER_HOUR` | `10` | Meldungen pro Konto und Stunde |
| `MS_LIMIT_REPLIES_PER_HOUR` | `60` | Antworten pro Konto und Stunde |

Entwickler und Administratoren sind ausgenommen. `0` schaltet die jeweilige Begrenzung ab.

### Sicherung und Wiederherstellung

```bash
meldestelle backup -out meldestelle-2026-11-08.tar.gz   # auch im laufenden Betrieb (VACUUM INTO)
meldestelle restore -in meldestelle-2026-11-08.tar.gz   # Server vorher stoppen; -force überschreibt vorhandene Daten
```

Automatische Sicherungen:

| Variable | Standard | Bedeutung |
|---|---|---|
| `MS_BACKUP_DIR` | – | Zielverzeichnis (leer = aus) |
| `MS_BACKUP_INTERVAL_HOURS` | `24` | Abstand zwischen Sicherungen |
| `MS_BACKUP_KEEP` | `14` | Anzahl aufbewahrter Sicherungen |

Die Wiederherstellung prüft die Datenbank vor dem Austausch (`integrity_check`) und nimmt nur bekannte Dateinamen aus dem Archiv an.

## Arbeiten mit Meldungen

- **Markdown**: `**fett**`, `` `code` ``, Codeblöcke mit ```` ``` ````, Listen, Tabellen, Links. Roh-HTML wird nicht übernommen, Links öffnen mit `rel="nofollow noopener"`, externe Bilder blockiert die CSP.
- **Bearbeiten**: Meldende und Entwickler können Titel, Beschreibung, Version und Anhänge ändern. Antworten bearbeitet nur, wer sie geschrieben hat. Änderungen sind im Verlauf sichtbar („bearbeitet“).
- **Löschen**: Antworten löschen ihre Verfasser selbst, Entwickler können sie als Moderation entfernen (bleibt als Hinweis sichtbar). Meldende können ihre Meldung zurückziehen, solange sich niemand sonst beteiligt hat, sonst nur Entwickler.
- **Duplikate**: Status „Duplikat“ wählen und die Original-Nummer angeben (Vorschläge erscheinen automatisch). Stimmen und Folgende werden übertragen, Ketten werden auf das Original aufgelöst, und auf Duplikate kann nicht mehr abgestimmt werden.
- **Labels** legen Entwickler unter *Software → Einstellungen* an (acht feste Farben mit gutem Kontrast in hell und dunkel).

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

# optional: LDAP-Integrationstest gegen einen echten Server (siehe ldap_test.go)
MS_TEST_LDAP_URL=ldap://localhost:389 MS_TEST_LDAP_BASE_DN=… go test -run Integration ./...
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

- GLPI-Übergabe bestätigter Meldungen
- `security.txt`, Veröffentlichungsfristen und CVE-Feld für Sicherheitsmeldungen
- Entwickler dürfen weitere Entwickler ihrer Software ernennen
