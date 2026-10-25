# Ziel 1 – Container-Nachweise, 25.10.2026

Kein QNAP-/SynapseNode-Zugriff, keine echte Scanneraktion, kein Deployment.
Ausgangsstände und genaue Quell-Hashes stehen in `tested-sources.json`.
Alle Anwendungsprüfungen liefen in isolierten Containern, nicht auf dem Host.

| Prüfung | Ergebnis |
|---|---|
| Control: neue Notbetrieb-Negativtests + betroffene C3/Vertrag/Session/Publication/Receipt/Service/UI-Regressionen | **75 bestanden**, 0 fehlgeschlagen |
| AirScap: authz/scanner/vens/webui/cmd, Go 1.26.0 | **184 Top-Level-Tests bestanden**, 1 optionaler alter Cross-Repository-Fixture-Test übersprungen |
| AirScap go vet und CGO=0 ARM64-Crossbuild mit vorhandenem Overlay | Exit 0; kein ARM64-/QNAP-Lauf behauptet |
| Echter Chromium-Browser + HTTPS-Control + AirScap + eigenständiger A2-VENS-Simulator | **57 Prüfpunkte bestanden**: C3-Baseline 4, Ziel 1 48, Rollback-Browser 5 |
| Dateisystem/DB | 4 getrennt bestätigte PDFs, 4 fehlgeschlagene Aufträge quarantänisiert, **keine** Worker-Lifecycle-Freigabe |
| Rollback | Identische C3-/A1-Image-IDs, alter Job erhalten, neuer Datenbestand erhalten; erneuter Notbetriebsstart erhält alle PDF-Hashes |
| HTTP-Vorschau | weiterhin 403 |
| Compose-Vorschlag | `docker compose -f deploy/emergency/compose.yaml config --no-interpolate --quiet` Exit 0; kein Start |

`results.json` enthält die einzelnen Browserprüfpunkte und Rollbackbehauptungen.
`goal-duplex.png` zeigt die echte native PDF-Ansicht mit vier Bildseiten.
Container-Metadaten enthalten nur ausgewählte IDs, Zustände und Mounts; keine
Umgebungsvariablen. Logs enthalten ausschließlich synthetische Simulatorläufe.
Der optionale Go-Skip betrifft die alte externe Python-Fixture, nicht den
vollständig ausgeführten Browser-/VENS-Verbundtest.

## Aussagekräftige Fehlerprüfungen

- Fehlender/abgebrochener Abschluss, H1/H2/H3 und Papierstau nach drei gültigen
  Bildseiten erzeugen kein freigegebenes Dokument. Strikte A5-Abschlussentscheidung
  bleibt unverändert.
- Getrennte Browser-/Scanner-Autorisierung, CSRF/Origin und arming-session;
  parallele/erneute Aufträge, Neustart ohne automatische Wiederholung.
- Hash/Manifest/Reservierung, genau zwei ZIP-Einträge, abgebrochene PDFs,
  aktive Fremd-PDFs mit passendem Hash, falsche Seitenzahlen und Deflate-Bomben.
- Keine Freigabe ohne aktuelle Ansicht und vier manuelle Bestätigungen;
  kollidierendes Ausgabeziel wird nie überschrieben; paralleles Speichern und
  DB-Ausfall nach atomarem Link bleiben nachvollziehbar und wiederholsicher.
- `view-audit-before-fix.log` ist der **absichtlich rote** neue Regressionstest
  vor der Korrektur der Transaktion. Derselbe Test besteht im finalen 75er-Lauf.
- Eine im ersten Verbundlauf zu frühe Recovery-Bereitschaftsanzeige wurde
  korrigiert: jetzt frischer Software-Idle-Nachweis nach Dispatch auch für
  failed/interrupted. Die Backend-Prüfung war bereits geschlossen.

Es wurde keine bereits abgeschlossene vollständige Altsystem-/Hardwaretestserie
wiederholt. Die zwei abschließenden Verbundläufe waren durch konkret gefundene
Recovery-/DB-Fehler begründet. Der bestehende ResourceWarning im Service-Test
wird im Originalprotokoll sichtbar belassen; der Test besteht.

## Reproduktion und Grenzen

Control: `tests/emergency/README.md`, `Dockerfile.unit`, `stack.py` und `browser.cjs`.
AirScap: `.github/workflows/test.yml` zeigt die zielgerichteten Containerbefehle.
Dependency-Download/Imagevorbereitung darf Netz benötigen; Unit-/Go-Tests laufen
mit `--network none`, der Verbund in einem eigenen `--internal` Netz ohne
Hostports/Proxy-Außenroute. Zur Wiederholung sind die dokumentierten lokalen
Images bzw. neu gebaute gleichwertige Testimages erforderlich.

Image-IDs sind lokale Entwicklungsartefakte, kein veröffentlichtes Registry-
Release. Hardwareursache und tatsächliche QNAP-Konfiguration bleiben ungeprüft.
Die Ablehnung unklarer Terminalstatus bleibt absichtlich bestehen. Kein Nachweis
für physische Vollständigkeit/Blindseiten oder sichere Darstellung beliebiger
Fremd-PDFs; nur die begrenzte vorhandene Bild-PDF-Grammatik wird zugelassen.

## Entwicklungsumgebung

Der VFS-Docker-Treiber füllte durch gestoppte Testcontainer den kleinen Root-
Datenträger. Nur eigene neue gestoppte read-only-Testcontainer wurden nach
Log-/Metadatensicherung entfernt, ohne Volumes/Images allgemein zu bereinigen.
Ein fehlgeschlagener Export von vier neu geladenen unbenutzten Hilfsimages
führte dennoch zu deren Entfernung; dieser Export ist **kein gültiges Backup**.
Baseline-/Zielimages, Quellen, Buildartefakte und alle Testdatenvolumes blieben
vorhanden. Der Runner sichert jetzt seine eigenen Logs/Metadaten und entfernt
nur seine eigenen gestoppten read-only-Container ohne `-f`/`-v`.
