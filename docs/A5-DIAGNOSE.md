# A5 – Diagnose der Scan-Abschlussprüfung („terminal status is not clean no-paper“)

Stand 25.10.2026. Grundlage: Befundbericht (Review E) und
Implementierungsplan A5 im Control-Repo (`review/2026-10-24-architektur/`).

**Status:** vorbereitet. **Nicht deployt.** Der Hardwaretest ist ein eigener
Freigabepunkt (FP-H1). Vollständig freigabefähig ist A5 erst, wenn die
Simulator-Tests aus A2 vorliegen (Anforderung vom 25.10.).

## 1. Zweck und Grenze

Echte iX500-Scans enden nach der letzten Seite mit „terminal status is not
clean no-paper“. Die Prüfung in `confirmDocumentEnd` verlangt zwei Dinge
über alle 32 Bit:

- Scanzustand (Offset 40) = `0x00000080`
- Fehlerfeld (Offset 44) = `0`

Keines der beiden Felder wurde protokolliert. Drei Ursachen passen zur
Beobachtung (H1–H3, siehe Abschnitt 4).

Der Diagnose-Build protokolliert die Felder getrennt und liest nach einer
Ablehnung einmal Sense und Status nach. **Die Entscheidung bleibt
unverändert.** Es wird nichts gelockert und kein Scan zusätzlich
angenommen.

## 2. Änderungen

| Commit | Inhalt |
|---|---|
| `a5016ee` | Getrennte Logzeilen `before_wait`, `terminal`, `after_sense`; `TerminalStatusError` nennt das betroffene Feld; Reproduktionstests H1–H3; Matrixtest der Entscheidung |
| `b348bec` | Jede Anfrage der Abschlussprüfung ist begrenzt (`endConfirmationTimeout`, 5 s). Tests fixieren die Befehlsfolge, das Verhalten bei Zeitüberschreitung und bei Verbindungsverlust. |
| `2619438` | Statuswörter als benannte Felder statt Rohbytes. `RegisterToken` schwärzt auch Token-Hälften im Wortformat. |

## 3. Seiteneffekt-Prüfung der zusätzlichen Protokollabfragen

### 3.1 Befehlsfolge am Dokumentende (Tests `TestDiagnosticsSendOnlyKnownRequests`, `TestReviewTerminalRequestOrder`)

| Fall | Folge (SCSI-Opcode) |
|---|---|
| sauberes Ende (unverändert) | GET_STATUS `C2` → WAIT `E0` → GET_STATUS `C2` → REQUEST SENSE `03` → END SCAN `D6` |
| Ablehnung (neu) | GET_STATUS `C2` → WAIT `E0` → GET_STATUS `C2` → **REQUEST SENSE `03` → GET_STATUS `C2`** → END SCAN `D6` |

- Neu sind genau zwei Befehle, und nur **nach** einer Ablehnung.
- Beide gehören zum normalen Ablauf jedes Scans: GET_STATUS vor jedem
  Blatt, REQUEST SENSE nach jeder Seite und nach einem Wait-Status ≠ 0
  (so auch Upstream beim Scanstart).
- Kein neuer Opcode, kein READ_PIXELSIZE (laut Quelltext bringt es die
  Firmware zum Absturz).

### 3.2 Zeitbedarf

- Jede Anfrage ist auf `endConfirmationTimeout` = 5 s begrenzt. Nach einer
  Ablehnung kommen höchstens 2 × 5 s hinzu.
- Antwortet der Scanner nicht, kostet das **eine** Zeitüberschreitung; die
  zweite Anfrage entfällt (`TestDiagnosticsBoundedWhenScannerStopsAnswering`).
- Danach folgt wie bisher END SCAN mit 5 s.

### 3.3 Fehlerfälle

- **Verbindungsverlust nach dem Abschlussstatus:** Die Ablehnung bleibt,
  und `Close` meldet den Fehler (`TestDiagnosticsKeepRejectionAfterConnectionLoss`).
- **Abgelehnter Scan:** Die Reservierung wird wie bisher mit
  `Finish(false)` auf `recovery_required` gesetzt. Es wird kein Dokument
  erzeugt, und die Seiten werden verworfen (Quarantäne folgt mit C7+A7).
- **Entscheidung:** Für 40 × 40 Wertepaare (Grenzwerte und Zufallswerte)
  gilt Annahme genau dann, wenn `state == 0x80 && error field == 0`. Der
  Test ist auf `a78441a` und auf diesem Branch grün
  (`TestReviewTerminalDecisionUnchanged`).

### 3.4 Protokollierung und Geheimnisse

- Protokolliert werden nur die Wörter ab Offset 40 als benannte Felder:
  - `state`, `no_paper`, `cover_open`, `jam`, `unknown_state_bits`
  - `error_field`, `error_code` (untere 16 Bit), `error_upper`
  - `reserved_48`, `reserved_52`, `device_flags`, `reserved_60/64/68`
  - aus der Sense-Antwort: `format`, `key`, `asc`, `ascq`

  Der Paketkopf und Rohbytes werden nie protokolliert (`redact.go`).
- Legt ein Scanner Token-Hälften in ein Statuswort, schwärzt der
  `RedactingHandler` sie (`TestDiagnosticWordsNeverShowTheSessionToken`).
  Ohne die Erweiterung von `RegisterToken` schlägt dieser Test fehl.
- Die statische Logrichtlinie (`TestLogPolicy`) ist grün.

## 4. Auswertung nach dem Hardwaretest

Die drei Logzeilen eines Scans bestimmen die Hypothese:

```
level=INFO msg="scan status fields" phase=before_wait state=0x… error_field=0x… …
level=WARN msg="terminal status rejected" phase=terminal state=0x… error_field=0x… error_code=0x… error_upper=0x… …
level=WARN msg="terminal status rejected: sense" format=0x70 key=0x… asc=0x… ascq=0x…
level=WARN msg="terminal status rejected: status after sense" phase=after_sense state=0x… error_field=0x… …
```

| Befund | Hypothese | Nächster Schritt (A6, eigener PR) |
|---|---|---|
| `terminal` `error_code≠0`, `after_sense` `error_field=0`, Sense MEDIUM ERROR 80/03 | H1: Bedingung bis zum Sense-Lesen anhängig | Reihenfolge Sense → Status (protokollkonform), gleiche Strenge |
| `error_code=0`, `error_upper≠0` (auch in `before_wait`) | H2: obere Bits des Fehlerfelds | nur den belegten Wert der oberen Bits zulassen; unbekannte weiter ablehnen |
| `state≠0x00000080` (z. B. `unknown_state_bits≠0`) | H3: weitere Zustandsbits | nur das belegte Bit zulassen; Deckel offen, Stau und unbekannte Bits weiter ablehnen |
| Sense mit Fehler (Stau, Deckel, Mehrfacheinzug) | echter Fehler | Ablehnung ist richtig; Meldung an den Benutzer verbessern |

Jede Korrektur bekommt die echten Bytes als Regressionstest und als
Simulatorprofil (A2).

## 5. Container-Regression (isoliert, ohne QNAP)

**Testcontainer:** Ubuntu 24.04 mit der unveränderten Go-Toolchain
1.26.0 aus `golang:1.26.0-bookworm`, dazu libjpeg/libpng. Die Paketquellen
von Debian sind im Sitzungsnetz gesperrt, die von Ubuntu nicht. Ausgeführt
wurden `go vet ./...`, `go test ./...` und `go test -race` für vens,
scanner und authz; alles grün (`docs/evidence/a5/container-regression.txt`).

**Image:** gleiche Laufzeitstufe wie `Dockerfile` (distroless base,
UID 10001). Nur die Build-Stufe vertraut zusätzlich dem Proxy-CA der
Sitzung.

- Rauchtest ohne Netz und ohne Konfiguration: Start verweigert mit
  „AIRSCAP_SCANNER_IP must be the scanner's IPv4 address“ (erwartet).

**Reproduzierbare Binärdateien** (Go 1.26.0, `-mod=vendor -trimpath
-ldflags="-s -w"`, `CGO_ENABLED=0`, Overlay):

| Commit | linux/amd64 | linux/arm64 (QNAP) |
|---|---|---|
| `a78441a` (deployter LAN-MVP) | `5fea9f1bd382202be8049a7d024516fc444b259dc6cc654917dfd56d54e2e97c` | `e38718684231e1e57ad13f684b74eb74070fdb97c1bfcff8b95ce66b1efc8e11` |
| `2619438` (Diagnose) | `7ac14cf02775346c77b94cbfdea1e315e146028e40346f27b29b4eedc766682f` | `4d5c01bcc02537c5c2daad184e36e446b5044679dd6ef878289e56a10259f091` |

Die amd64-Binärdatei im gebauten Image hat genau den Hash des lokalen
Builds. Ein Buildx-Build für arm64 mit derselben Toolchain sollte dieselben
arm64-Hashes ergeben. Damit lässt sich vor und nach dem Test prüfen,
welche Version läuft.

## 6. Ablauf FP-H1 (genau ein Hardwaretest) – erst nach ausdrücklicher Freigabe

Alle Befehle auf dem QNAP im Verzeichnis `deploy/lan` des
Control-Checkouts, mit denselben Umgebungsvariablen wie beim Start
(`SSC_HOST_DIR`, `SSC_SECRETS_DIR`, `AIRSCAP_SECRETS_DIR`).
Compose-Projekt `scansnap-lan`, Dienst `airscap`.
Control, Datenbank, Intake, Ablage und Pairing-Daten werden nicht
angefasst.

**0. Vorher, nur lesend:**

```sh
docker compose ps
docker image inspect airscap:lan-mvp --format '{{.Id}}' | tee ~/a5-before-image-id.txt
C=$(docker compose ps -q airscap)
docker cp "$C":/usr/local/bin/airscap - | tar -xO | sha256sum   # erwartet e3871868… (a78441a, arm64)
```

Außerdem muss feststehen:

- Es gibt keine blockierende Reservierung.
- Der Scanner ist frei.

**1. Image bauen** (Entwicklungsrechner, wie im LAN-MVP), übertragen und
prüfen:

```sh
git -C AirScap checkout 2619438
docker buildx build --platform linux/arm64 -t airscap:diag-2619438 --load AirScap
docker save airscap:diag-2619438 | ssh admin@qnap docker load
# QNAP:
C=$(docker create airscap:diag-2619438); docker cp "$C":/usr/local/bin/airscap - | tar -xO | sha256sum; docker rm "$C"
# erwartet 4d5c01bc…; bei Abweichung abbrechen
```

**2. Rückweg sichern und umschalten:**

```sh
docker image tag airscap:lan-mvp airscap:rollback-a78441a
docker image tag airscap:diag-2619438 airscap:lan-mvp
docker compose up -d --no-build --no-deps airscap
docker compose logs --tail 20 airscap        # "scanner identity computed", keine Fehler
```

**3. Genau ein Scan:**

1. Anmelden.
2. Scansitzung „Briefe“, einseitig, 300 dpi.
3. **Ein Blatt** einlegen, Scan-Taste drücken.

**4. Logzeilen sichern:**

```sh
docker compose logs --since 15m airscap 2>&1 | grep -E 'scan status fields|terminal status|terminal sense' | tee ~/a5-terminal.txt
```

**5. Reservierung:** Wenn abgelehnt, die Reservierung wie in den Schritten
434/437 kontrolliert mit `controlled_recovery.quarantine()` in Quarantäne
setzen (bis C4 verfügbar ist). Keine Datenbank löschen.

**6. Rollback** (nach Entscheidung, spätestens nach der Auswertung):

```sh
docker image tag airscap:rollback-a78441a airscap:lan-mvp
docker compose up -d --no-build --no-deps airscap
docker image inspect airscap:lan-mvp --format '{{.Id}}' | diff - ~/a5-before-image-id.txt && echo "Rollback: Image-ID wie vorher"
C=$(docker compose ps -q airscap); docker cp "$C":/usr/local/bin/airscap - | tar -xO | sha256sum   # wieder e3871868…
```

**7. Prüfpunkte nach dem Rollback:**

- Container läuft.
- Ein Tastendruck ohne Scansitzung wird verweigert (Log „no active
  session“).
- Control ist erreichbar.

## 7. Offen bis zur vollständigen Freigabe

- A2: Simulator-Tests der Befehlsfolge gegen ein vollständiges
  VENS-Gegenüber, inklusive Tastenscan, Teilscan, Deckel offen, Stau und
  der Profile H0–H3.
- Ausdrückliche Freigabe FP-H1.
