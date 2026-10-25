# A2 – VENS-Simulator mit reproduzierbaren Scannerzuständen

Stand 25.10.2026. Grundlage ist der Implementierungsplan A2 im Control-Repo
(`review/2026-10-24-architektur/`).

**Status:** Testwerkzeug. Es kommt **nicht** ins Produktions-Image: Das
Root-Dockerfile baut nur `./cmd/airscap`, `cmd/vensim/main_test.go` prüft das.
Kein Hardwaretest, keine Änderung an Scannerkonfiguration oder QNAP.

## 1. Bestandteile

| Teil | Zweck |
|---|---|
| `internal/vens/vensim` | Simulierter iX500 auf einer frei wählbaren IPv4-Adresse: Discovery (UDP 52217), Kopplung mit Identität aus dem Passwort, Steuer- (53219) und Datenkanal (53218), Tastenmeldung an den gekoppelten Client (55265) |
| `cmd/vensim` | Eigenständiges Binary mit Test-Steuer-API (`/health`, `/profile`, `/press`, `/offline`, `/online`, `/requests`), ohne Authentifizierung: nur an Loopback oder ein Testnetz binden |
| `cmd/vensim/Dockerfile` | Test-Image für die Versionsmatrix von ScanSnap Control (`tests/matrix/`) |
| `internal/testlock` | Datei-Sperre für die festen VENS-Client-Ports, damit Paket-Tests nicht parallel kollidieren |

## 2. Reproduzierbare Zustände (`vensim.Profile`)

| Feld | Zustand |
|---|---|
| `Sheets` | Blätter im Einzug; `0` bedeutet kein Papier |
| `CoverOpen` | ADF-Abdeckung offen |
| `JamAtSheet` | Papierstau beim n-ten Blatt |
| `MultiFeedAt` | Doppeleinzug beim n-ten Blatt |
| `Terminal` | Verhalten am Dokumentende: `H0`, `H0-scan-complete`, `H1`, `H2`, `H3` (Review E / A5) |
| `ChunkSize`, `PageWidth` | JPEG-Seiten über mehrere Blöcke |
| `EndDelayMS` | Verzögerung vor der Antwort auf END SCAN: Zeitfenster nach der letzten Seite, etwa für die Abmeldung in der Versionsmatrix |

`H1`–`H3` bilden die **Hypothesen** aus A5 nach, keine gemessenen
Hardwarewerte. Die strikte Abschlussprüfung bleibt unverändert: Sie nimmt
nur `H0` an. Eine Lockerung gibt es nur mit echten Hardwarebefunden (FP-H1).

## 3. Tests

Der echte `Scanner` (Discovery, Kopplung, Heartbeat, Datenkanal) läuft
gegen den Simulator auf 127.0.0.2
(`internal/scanner/vensim_integration_test.go`):

- Kopplung nur mit der richtigen Identität;
- Simplex und Duplex mit 3 Blättern, Ablage in die private Intake;
- kein Papier, Abdeckung offen, Stau, Doppeleinzug: keine Freigabe;
- H0 und H0-scan-complete werden angenommen;
- H1, H2 und H3 werden abgelehnt, mit Feldangabe und A5-Diagnosezeilen;
- JPEG-Seiten über mehrere Blöcke;
- Scanner offline und zurück;
- Tastenmeldung erreicht den Listener.

Behobener Fehler (`a9111f4`): `ButtonListener.Stop` kam nicht zurück,
solange der Kontext lebte (Schleife nach geschlossenem Socket). Ein
Mutationstest bestätigt die Korrektur.

Ergebnisse stehen in [`docs/evidence/a2/tests.txt`](evidence/a2/tests.txt):

- volle Suite mit `go vet` und `-race` grün;
- Simulator- und Listener-Tests (9 Tests) in drei Durchläufen: 27/27 PASS, kein SKIP.

## 4. Einsatz in der Versionsmatrix

ScanSnap Control `tests/matrix/` startet das Simulator-Image in einem
internen Docker-Netz. AirScap lehnt Loopback-Scanneradressen weiterhin ab,
der Simulator bekommt deshalb 172.31.250.10.

Ergebnis: 246/246 Prüfungen für beide Deploy-Reihenfolgen, Rückfall und
Neustart während eines Scans (Nachweis `docs/evidence/c2-a1-matrix/` im
Control-Repo).

## 5. Grenzen

- Der Simulator beweist die Protokollabläufe von AirScap, nicht das Verhalten des echten iX500.
- Der Hardwaretest bleibt ein eigener Freigabepunkt.
- A5 kann mit diesen Tests als vollständig vorbereitet gelten. Freigabe und Hardwaretest (FP-H1) stehen weiter aus.
