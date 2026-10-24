# Paket 12 – Integrations- und Abnahmegrundlage (keine Produktivfreigabe)

## Umfang

Die zehn bestehenden Draft-PRs wurden über ihre Git-Head- und Testmerge-Refs
geprüft. Vollständige Head-/Base-SHAs, Basisbranches und die zwölf Original-
Befunde stehen im separaten Audit `phase-a.md` / `pr-refs.json` unter
`/workspace/scansnap-audit`. Nach Wiederverfügbarkeit der PR-API sind alle zehn ursprünglichen Drafts
als offen/mergbar bestätigt; Worker #3/#4 zeigen je 16 erfolgreiche Checks,
QNAP/AirScap keine Checks. Branch-Protection/Required-Policy bleibt separat
mit API-403 unlesbar. Keine lokalen Tests werden als GitHub-CI ausgegeben.

Dieser Feature-Stack enthält Pakete 8–11 und diese Integrationskorrekturen:

- QNAP-PR-1-Korrektur per Cherry-pick in den Integrationsbranch übernommen;
  vorher fehlte sie im gestapelten PR-3–7-Stand. Kein Branch-Merge/Force-Push.
- Explizite QNAP-Orchestrierung `app.coordinator.run_once` für Transfer,
  verifizierte Rücknahme und nachgelagerte Filing-ACKs. Sie publiziert nicht.
- Expliziter Worker-Runner `ready_runner.run_ready/next_ready`: atomarer Slot,
  vorhandene feste Renderprofil-/Start-/Nachweiskette, privater Ergebnisexport;
  kein automatischer Zweitstart bei Fehlern. Produktiver Startadapter bleibt
  gesondert autorisierungspflichtig. Import startet keine Prozesse.
- Browser-Dokumentansicht mit vier expliziten Prüfbestätigungen, exakter SHA,
  separatem Ablageknopf nur bei operatorseitig aktivierter Veröffentlichung.
  Zugriff bleibt sitzungs-/auftragsgebunden, API-Antworten no-store.
- Handover einer abgelaufenen Eigentümersitzung ausschließlich als lokale
  Operatoraktion: keine aktive alte Sitzung, kein aktiver Job, kein Publish-
  Intent. Eine frühere Zustimmung wird ausdrücklich widerrufen; der neue
  Owner muss die PDF erneut ansehen und freigeben.
- Recovery einer unterbrochenen Ergebnisrücknahme schreibt nur unter neuer
  Entscheidungs-ID; alte Pending-Dateien bleiben erhalten. Erneuter PRE-RENDER-
  Intake-Recovery nach Collector-Crash verlangt neue explizite Entscheidung;
  ein begonnener Renderlauf wird niemals dadurch wiederholt.

## Durch Integration gefundene und behobene Fehler

Der bisherige FPDF-Generator erzeugte selbst bei reinen Scans einen leeren
EmbeddedFiles-Baum und bei gleichen Bildern doppelte Ressourcen. Der Worker
lehnte die PDF korrekt ab. Der neue Aufnahme-Writer erzeugt begrenzte,
bildbasierte PDFs ohne Anhänge, Aktionen, Formulare oder externe Ressourcen;
identische Seiten bleiben als einzelne Seiten erhalten. Keine Lockerung der
Worker-Policy, keine OCR/TTS-Verarbeitung. Blankseitenentfernung ist im
Intake deaktiviert. Erfassungs-Duplex ist im bisherigen Manifest nicht
attestiert und wird explizit als unbekannt behandelt, nicht erfunden.

Der private QNAP-Prüfdeskriptor musste nach der Hash-Prüfung zurückgesetzt
werden, sonst lieferte PDF-GET 503. Der echte Ansichtsschritt im
Integrationsfall prüft jetzt die zurückgegebenen Bytes gegen die Ergebnis-SHA.

VENS-EndScan-ACK-Fehler wurden zuvor verschluckt. Sie werden nun weitergegeben.
Ein Scanfehler setzt den Claim auf recovery_required. Erfolg nach Sessionablauf
ist nicht zulässig; neue Starts bleiben bei ungeklärtem Abschluss gesperrt.
Activity-/Finish-ACKs werden strukturell statt allein über HTTP 200 geprüft.
Die QNAP-Gateway-Verbindungen werden explizit geschlossen, nicht nur committed.
Ein eingewickeltes Transport-EOF ist kein normales Dokumentende. Native
VENS-Abschlüsse brauchen einen vollständigen, eindeutigen Status-/Sense-Frame
und ein erfolgreiches EndScan-ACK. Abbruch nach drei Seiten bleibt unvollständig.

Öffentliche Scanaufträge sind an ihre serverseitige Browsersitzung gebunden.
Ablauf und Logout sperren weitere Reservierung, Activity und Erfolgsabschluss.
Der explizite Sitzungsabbruch entzieht ebenfalls Scanautorität, gibt einen
ungeklärten Scannerclaim aber nicht frei. Legacy-/Servicejobs ohne Browserowner
verwenden weiterhin die interne serverseitige Autorisierung; sie sind über
die Browser-API weder erzeugbar noch zugreifbar.

Finale Ablage erfordert zusätzlich eine explizite Consumer-GID. Erst nach
Zustimmung wird die private Ergebniskopie auf 0440 mit dieser Gruppe gesetzt;
das private 0700-Elternverzeichnis schützt sie bis zum finalen Link. GID,
Quell-/Ziel-Inodes und Hash sind im persistenten Publish-Intent gebunden.
Alte Intents ohne Gruppenpolicy erfordern Operatorprüfung statt stiller Migration.

## Harte Sicherheitsgrenzen

HTTP-Scanpreview und eSCL sind im Scannercheckpoint bedingungslos deaktiviert,
auch wenn ein Authorizer hierfür einen Grant liefern könnte. Keine Freischaltung
unauthentifizierter HTTP-Scanpfade. Unauthentifiziertes PUT der AirScap-Settings
ist ebenfalls gesperrt. Der Button verlangt bekannte Scanner-IP, dokumentierten
Ereignistyp/-daten und eine Ruhephase zwischen UDP-Bursts; jede Wiederholung
verlängert diese Ruhephase. **UDP besitzt keine kryptografische Herkunft und
keine eindeutige Event-ID**: Segmentierung/Firewall und direkte fremde VENS-
Clients bleiben ein separates Betriebsrisiko. Der QNAP-Grant bleibt Pflicht.

TLS-Material muss regulär, nicht fremdbeschreibbar, im erlaubten Besitz und
für private Keys ohne Gruppen-/Weltzugriff sein. CA, Kette und Schlüssel werden
über geprüfte Deskriptoren geladen; keine TOCTOU-Umlenkung des Pfads. Keine
Symlink-Keydateien, kein interaktiver Passwortprompt, keine Prüfungsabschaltung.
TLS mindestens 1.3, korrekte EKU/Gültigkeit, DNS-SAN statt CN-Fallback und genau
eine Service-URI für die jeweilige Rolle. Rotation mit CA-Überlappung und
anschließender Sperre der alten Client-CA ist synthetisch geprüft.

Aus dem vorhandenen D5-Branch wurden ausschließlich Root-Parent-/Manifest-/
Artefakttest-Härtungen übernommen: `/run/scansnap-worker` soll root:root 0755
sein. Kein Migrationsprototyp und kein Live-Root-Eingriff wurde ausgeführt.
Ein alter/falscher Runtime-Baum wird vom Installer vor tmpfiles-Aufrufen
verweigert, niemals still chowned. Realer D5-/Cross-UID-Nachweis bleibt eine
separat freizugebende Betreiberabnahme. Der frühere D4/K1-PASS bleibt ein
Nachweis seines früheren Umfangs; er wurde nicht wiederholt.

Die mitgelieferte AirScap-Unit verlangt jetzt den dedizierten Account airscap;
der Account wurde nicht angelegt und keine vorhandene Unit geändert.
Vor echter Installation sind Accounts, Rechte, Volumes und Laufzeitabhängigkeiten
zu prüfen. Ein ARM64-Build allein beweist keine QNAP-Ausführbarkeit.

## Nachweis und Wiederholung

Siehe `PR12-TESTMATRIX.md` (AirScap: `pr12-testmatrix.md`). Rohlogs/Befehle und
Quellhash-Manifeste liegen in `/workspace/scansnap-audit/evidence`.
Versionierte Kurzbelege: `docs/audit/phase-a.md`, `test-results.json`,
`tested-sources.json` und `tls-compatibility.json`.
Der verpflichtende Cross-Repo-Test liegt im Worker unter
`integration/test_system_contract.py`; er läuft nur auf expliziten Aufruf,
nicht als still übersprungene Abnahme. Beispiel aus dem Worker-Checkout:

```sh
# Ausschließlich isolierte Entwicklungs-Venv und eigene temporäre Daten.
# Testabhängigkeiten: Worker/requirements-test.txt + Control/requirements-test.txt
# Go 1.26.0; im AirScap-Checkout zuvor go mod vendor (mit Verifikation).
export SCANSNAP_CONTROL_SOURCE=<QNAP-Checkout-des-geprüften-Refs>
export SCANSNAP_AIRSCAP_SOURCE=<AirScap-Checkout-des-geprüften-Refs>
export SCANSNAP_GO=<Go-1.26.0-Binary>
PYTHONPATH=.:tests:integration python -m unittest test_system_contract -v
```

Es werden reale Cookie-/CSRF-Routen und die echte interne QNAP-API verwendet,
AirScaps tatsächlicher Aufnahmeweg mit simuliertem Datenkanal, echtes
Loopback-mTLS und der vorhandene kontrollierte Test-Renderer mit systemd-
Double. Nur künstliche Bilder/PDFs und neue private Temp-Verzeichnisse.
Kein physischer iX500, keine echte Unit, keine produktiven Schlüssel.

QNAP erhält einen gezielten Safety-Workflow. AirScaps Workflow erfasst nun
Feature-Branches und gestapelte PR-Bases. Der Worker erhält einen manuell
anzustoßenden Cross-Repo-Workflow mit expliziten Ref-Eingaben und read-only
Cross-Repo-Zugang. Eine vorhandene geeignete GitHub-App-/Actions-Bindung ist
zu verwenden; die Anwesenheit des dort benannten Secrets ist hier unbekannt.
Der Workflow verweigert bei fehlendem Zugang, statt eine grüne Abnahme durch
Überspringen vorzutäuschen. CI-Aussagen sind immer an den abgefragten Head
gebunden; der Fortschrittsbericht enthält den abschließenden Live-Snapshot.

Erste Worker-CI-Läufe fanden zwei Fixturefehler: fehlende AKI-/SKI-/KeyUsage-
Erweiterungen für Python 3.13 Strict-X.509 und umaskabhängig gruppenschreibbare
Testzertifikate. Beide sind lokal reproduziert und ausschließlich in der
synthetischen Test-PKI korrigiert; Produktionsprüfungen bleiben streng.
Sieben TLS-Tests bestehen mit Python 3.11/3.13 jeweils unter umask 022/002.
Der Testfix wurde ohne Rebase/Force-Push separat in die Worker-Stacks
cherry-gepickt. Die neueren Basis-Heads sind deshalb nicht überall direkte
Vorfahren; der identische notwendige Fixturefix ist in allen Heads vorhanden.
Keine Branches wurden gemergt.

## Verbleibende Abnahme-/Sicherheitsblocker

1. Alle elf Drafts sind erstellt; PR-/Check-Metadaten sind abrufbar.
   Branch-Protection-/Required-Policy-Abnahme bleibt wegen API-Rechten/
   Planbeschränkung offen. Bestehende Anbindung weiterverwenden; kein Token
   im Chat nötig. Der zuvor gespeicherte additive Netzwerkentwurf ist keine
   noch bestehende Voraussetzung der erfolgreichen PR-Erstellung.
2. Parser-Ressourcenisolation vor dem isolierten Renderer bleibt offen (F05).
   Größen-/Objektgrenzen ersetzen keine vollständige Prozess-/UID-Isolation
   und keinen Kapazitätsnachweis für reale Scans. Visuelle Papierabsicht
   bleibt deshalb immer manuell; keine Vollständigkeits- oder Vernichtungszusage.
3. Echte Laufzeit-/D5-/Cross-UID-/Filesystem-/Zertifikats-/Browserabnahme und
   Prozessmanager-Anbindung sind nicht ausgeführt. Keine Produktionsfreigabe.
   Andere Prozesse unter der Render-UID dürfen die Peer-Unit-Annahme nicht
   unterlaufen; SO_PEERCRED bindet weiterhin UID/GID, nicht allein eine Unit.
4. Lokale Operatorfunktionen sind keine öffentlich authentifizierten Admin-
   APIs. Die spätere Betriebsanbindung muss tatsächliche Operatoridentität und
   Stillstand erheben. Ein Actor-String ist kein eigener Authentifizierungsbeweis.
5. HMAC ist gemeinsames Vertrauen, keine unabhängige Nichtabstreitbarkeit.
   SQLite-Trigger sind keine WORM-/Root-Kompromittierungsgrenze (F11).
   Externe Audit-/Backup-Verankerung und Restore-Abnahme sind Betreiberaufgaben.
6. Kapazität, echte Firmware-EndScan-ACKs, reale Duplex-/Einzelseitenfälle,
   Netzsegmentierung und tatsächliche GUI-Sichtprüfung fehlen vor Systemabnahme.

Die Implementierung ist damit als synthetisch integrierter Draft prüfbar,
nicht als produktiv abgenommenes System. Alle bestehenden Backups und
Quellartefakte wurden erhalten. Keine produktiven Dokumente verschoben oder
gelöscht, keine realen Schlüssel/Zertifikate erstellt/gelesen/geändert,
kein Deployment, kein Merge und kein Force-Push.
