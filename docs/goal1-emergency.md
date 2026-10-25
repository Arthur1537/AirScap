# Ziel 1 – abgesicherter lokaler Scan-Notbetrieb

Stand 25.10.2026. **Entwicklungsstand, kein Deployment und kein Hardwaretest.**
Der Notbetrieb verwendet die bestehende QNAP-Webanmeldung, Scanreservierung,
AirScap-Scanroutine und Bild-PDF-Erzeugung. Er benötigt keinen SynapseNode und
startet weder Worker-Koordinator noch Renderer. Die normale Worker-Freigabekette
bleibt erhalten. Für den Notbetrieb gibt es ausdrücklich eigene Zustände und
keinen erfundenen Worker-Abschlussnachweis.

## Verbindliche Grundlagen

| Rolle | Commit | Verwendung |
|---|---|---|
| Control C3, enthält C1/C2 | `98f1e3797a81063ffe51c62893822534f74c4dcf` | Basis des neuen Branches `fix/goal1-emergency-scan` |
| AirScap A1 | `c1725df46d83d307a5abc6a662687b4c0777fcd5` | Basis des gleichnamigen AirScap-Branches |
| A2-Simulator | `af5045ad0562b283d4cee71ff6bcab99482aadd1` | Eigenständiges Testimage; kein Branch-Merge und kein Simulator im Produktivimage |
| A5-Diagnostik | `59d6f61b98d10a873d9aec0323a397f81a6be68e` | Nur Delta unter `internal/vens/`: Diagnose, Schwärzung, zugehörige Tests |
| Funktionale Upstream-Referenz | `177fdaec3416280acfc278e6408b41e6c7a2bbe6` | Vergleich von Browserstart, Scanroutine und `GeneratePDF`; nicht deployt |

Die vorhandenen C1/C2/C3/A1/A2/A5-Refs bleiben unverändert. Das allgemeine
Scanner-Vertragsdokument v2 bleibt bytegleich (`fc404b33…`). Der opt-in
Notbetriebszusatz ist in `contracts/emergency-scan.json` beschrieben; AirScap
führt dessen identische Kopie unter `internal/authz/testdata/`.

## Root-Cause-Abgleich

1. **Browserstart fehlt absichtlich:** C3 versteckt/deaktiviert `#scan-start`.
   Die frühere AirScap-Oberfläche startete über `POST /ui/api/scan/preview`.
   Dieser ungeschützte Pfad wird nicht wieder freigeschaltet. Der neue
   sichtbare Knopf „Scannen“ verwendet die vorhandene C3-Anmeldung und einen
   einmaligen Auftrag über die private Control-API.
2. **PDF-Anzeige hängt am Worker:** Der normale Koordinator erwartet einen
   attestierten Worker-/Renderer-Abschluss. Ohne dessen Freigabe bleibt das
   Dokument vor der Ansicht stehen. Der lokale Notbetrieb hat deshalb eine
   klar benannte eigene Kette `review_required -> approved -> saved`, mit
   `processing=emergency_local_no_worker`; keine Umdeutung zu
   `security_confirmed` und keine Änderung der normalen Freigabegates.
3. **Reale Fehler vom 24.10.:** Laut dem vorhandenen Review auf
   `review/architektur-funktionsreview-2026-10-24` (`e175d1f…`, Befund E und
   Abschnitt 10.1) wurden Bildseiten übertragen; beide Scans scheiterten am
   strikten Terminalstatus. Zwischen den Versuchen erfolgte ausdrücklich
   kontrollierte Quarantäne, kein DB-Reset. Die damaligen Logs enthielten
   weder das gesamte Fehlerfeld noch den abgelehnten Terminalzustand.
   H1 (anhängige Sense-Bedingung), H2 (obere Fehlerbits) und H3 (weitere
   Zustandsbits) bleiben Hypothesen. **Ein Hardwaredefekt ist nicht belegt.**
4. `confirmDocumentEnd` akzeptiert weiterhin nur `state == 0x80` und
   `error_field == 0`, vollständige zulässige Sense-Daten und erfolgreiches
   EndScan-ACK. A5 protokolliert zusätzliche Felder ausschließlich redigiert,
   liest nach einer Ablehnung begrenzt Sense/Status nach und behält die
   Ablehnung bei. **Keine Lockerung ohne Hardwarebefund.**
5. Wiederverwendet wird `GenerateIntakePDF`, der bereits vorhandene
   begrenzte Bild-PDF-Writer. Der ältere `GeneratePDF`/FPDF-Pfad wird nicht
   wieder zum Aufnahmeweg: der aktuelle Writer bewahrt gleiche/blanke Seiten
   ohne Anhänge, Aktionen, Formulare oder doppelte Bildressourcenschlüssel.

## Ablauf und Sicherheitsgrenzen

1. C3-Anmeldung mit Secure/HttpOnly/SameSite-Cookie, exakter HTTPS-Origin,
   CSRF-Prüfung und bestehender Login-Bremse. Ein dauerhaftes lokales Konto;
   Dokumente bleiben nach erneuter Anmeldung sichtbar. Hintergrundpolling
   verlängert weder Browser-Leerlauf noch die 10-Minuten-Scanfrist.
2. Einstellungen wählen und Scansitzung starten. „Scannen“ erzeugt einen
   einmaligen Auftrag. Nur die armerende Browsersitzung darf ihn erzeugen.
   AirScap holt ihn mit dem **Scanner-Token**, nicht mit dem Browser-Token.
   Alternativ bleibt die Hardwaretaste nutzbar, ebenfalls nur reserviert.
3. Auftrag, Job und Reservierung werden vor dem ersten Feed gebunden. Ein
   verbrauchter/staler Auftrag wird nicht wiederholt. Eine durchgehende
   AirScap-Mutex schützt Browser- und Tastenscan; kein Timer öffnet einen
   zweiten Scan bei noch laufendem ersten Prozess. Zusätzlich gilt die
   zentrale transaktionale Reservierung.
4. Der bestehende vollständige Scanpfad prüft Bilder, sauberes Ende,
   Autorität, Close/ACK und atomaren privaten Umschlag. Teilscans liefern
   kein fertiges Dokument. `staged_not_released` bedeutet nur technische
   Aufnahme. Das Original-Envelope bleibt erhalten.
5. Der lokale Collector prüft Receipt/Manifest/Größen/Hash/ZIP-CRC und exakt
   das begrenzte Bild-PDF-Format des vorhandenen Writers (Index, Objekte,
   Seitenreihenfolge, RGB-Deflate-Längen und Expansionsbudget). Er ist kein
   allgemeiner PDF-Parser oder Rasterrenderer. Keine PDF-Uploads. Grenzen:
   128 MiB PDF, 500 Seiten, 40 Mio. Pixel/Seite und 120 Mio. Pixel insgesamt.
   Große Stapel gegebenenfalls aufteilen. Das ist kein physischer Nachweis
   fehlender Rückseiten, vollständigen Papiereinzugs oder visueller Qualität.
6. Private Prüfkopia unter `SSC_ROOT/emergency-review`, 0700/0400.
   PDF-Ansicht wird an SHA und aktuelle Sitzung gebunden. Ansichtsnachweis
   und Ereignis sind eine DB-Transaktion: Auditfehler erteilt keine Freigabe.
   Danach muss der Benutzer vier Prüfpunkte bestätigen. Eine erneute
   Anmeldung erfordert für ungespeicherte Ergebnisse eine neue Sichtprüfung.
7. Erst ein weiterer expliziter Klick speichert nach
   `SSC_ROOT/emergency-output/<Reservierung>.pdf`. Speichern ist standardmäßig
   aus. Der Zielordner bleibt getrennt von allen fünf bisherigen Scanordnern
   und ihren Verbrauchern. Dateiname serverseitig, private Rechte 0700/0400,
   kein Überschreiben. Persistenter Inode-/Hash-/Sitzungs-Intent vor atomarem
   Link; Directory-fsync und erneute Integritätsprüfung vor DB-Status `saved`.
   DB und Dateisystem sind keine gemeinsame Transaktion: ein Fehler nach dem
   Link wird als unbestätigt gemeldet; passender Replay ist idempotent.
8. Ein fehlgeschlagener/unklarer Scan bleibt gesperrt. Web-Recovery verlangt
   einen frischen Idle-Heartbeat **nach** dem betroffenen Auftrag, ein
   unverändertes Intake-Inventar, Begründung und ausdrückliche Bestätigung,
   dass Scanner UND bisheriger Producer stillstehen. Die Software kann den
   tatsächlichen Hardwarestillstand nicht allein beweisen. Die Entscheidung
   wird unter der angemeldeten Sitzung protokolliert. Quarantäne gibt kein
   Dokument frei, löscht nichts und wiederholt keinen Scan automatisch.
   Bei bestehendem vollständigem Receipt/unklarem Ablage-Intent erfolgt
   keine blinde Rücksetzung; Betreiberprüfung erforderlich.

Der Start verweigert eine vorhandene unmarkierte Control-Datenbank bereits
vor den normalen Initialisierungs-/Migrationsroutinen. Der normale
`app.service` verweigert seinerseits `SSC_EMERGENCY_MODE=1`. Es ist keine
Datenbankrücksetzung vorgesehen. eSCL und HTTP-Scanpreview bleiben gesperrt;
AirScap bekommt keinen zusätzlichen HTTP-Scan-Endpunkt. Direkte fremde
VENS-Clients/UDP-Spoofing bleiben ein separates Betriebsrisiko: genau ein
Scannerprozess, kontrolliertes Quellnetz und keine fremden Scanclients.

SQL-Trigger/Ereignisse sind innerhalb der eigenen Vertrauensdomäne geschützt,
kein unabhängiges WORM. Control und AirScap teilen wie im vorhandenen QNAP-MVP
UID/Intake-Vertrauen. Der Notbetrieb ist kein Ersatz für die langfristige
Worker-Isolation. Papieroriginale aufbewahren; keine Vernichtungsfreigabe.

## Isolierte Tests und Wiederholung

Siehe `docs/evidence/goal1/README.md` und `tests/emergency/README.md`.
Alle Anwendungs-, Browser- und Simulatorprüfungen laufen in Containern:
Unit-Container `--network none`; gesamter Ablauf in einem neuen internen
Docker-Netz ohne Host-Portfreigabe, mit ausschließlich synthetischen Daten,
Test-PKI und eigener A2-Komponente. Keine QNAP-/iX500-/SynapseNode-Verbindung.
Ausgangsimages und neue Images werden anhand ihrer IDs festgehalten.

Die nativen Laufzeitprüfungen sind linux/amd64. AirScap ist zusätzlich für
linux/arm64 crosskompiliert; daraus folgt keine QNAP-Laufzeitabnahme.
Frühere vollständige C3-/Versionsmatrix- und D4/K1-Systemserien werden nicht
wiederholt. GitHub-CI und lokale Containerergebnisse bleiben getrennt.

## Konkreter Vorschlag zur kontrollierten Inbetriebnahme – noch nicht ausgeführt

Dateien unter `deploy/emergency/` sind ein **Prüfvorschlag**, kein Auftrag zur
Ausführung. Der erste Schritt braucht keine Renderer-Freigabe.

1. **Review und lesender Ist-Nachweis:** Tatsächliche QNAP-Architektur,
   Compose-Projekt/Container, unveränderliche aktuelle Image-IDs, Env-/Mount-
   Zuordnung, vorhandene Reservierungen und freien Speicher festhalten.
   Nicht annehmen, dass dort bereits exakt C3/A1 läuft. Die gegebene
   Entwicklungsbasis ist keine Behauptung über den aktiven Produktionsstand.
   Prüfen, dass das bestehende HTTPS-Zertifikat zum verwendeten Host passt
   und Browser/Scanner-Token verschieden und owner-only sind. Keine Schlüssel
   ausgeben, ersetzen oder neu erzeugen.
2. **Images vorbereiten:** Aus den geprüften neuen Commits für die tatsächliche
   Architektur bauen. Control: `deploy/emergency/Dockerfile.control`;
   AirScap: vorhandenes Root-Dockerfile. Archivierte Git-Quellen verwenden,
   keine versehentlichen `.env`/Buildreste in den Buildkontext. Image-IDs und
   Binary-Hash protokollieren. Die gelieferten amd64-Testimages nicht als
   ungeprüfte QNAP-ARM64-Images verwenden. Native Offline-Startprüfung auf
   der Zielarchitektur vor dem Gerätekontakt separat freigeben.
3. **Eigenes Datenverzeichnis:** Neues leeres, privates Verzeichnis für UID/GID
   10001 bereitstellen. Keine vorhandene DB/Scanablage dort einhängen.
   Vorhandene Web- und Scannergeheimnisse nur einzeln read-only mounten;
   keine Worker-/Receipt-Schlüssel. Metadaten aus `goal1.env.example`
   anpassen. Anfangs `SSC_EMERGENCY_SAVE_ENABLED=0`. Ports 18643/18682/18680
   sind Vorschlagswerte und vorab auf Konflikte zu prüfen.
4. **Eigener Freigabepunkt:** Erst nach ausdrücklicher Zustimmung den genau
   benannten bisherigen AirScap-Container ordentlich stoppen und seinen
   tatsächlichen Stillstand prüfen. Keine zwei Prozesse am iX500. Den
   bisherigen Control-/Worker-Stack nicht ändern. Erst dann den geprüften
   neuen Stack starten. Ein privates Browserfenster vermeidet, dass die
   bestehende Hostcookie-Anmeldung des alten Control auf demselben Host
   durch die neue Anmeldung überschrieben wird.
5. **Genau ein freizugebender Hardware-Canary:** Ein bekanntes einseitiges
   Testblatt, 300 dpi, keine produktiven Originale. Anmeldung → Sitzung →
   „Scannen“. A5-Felder `before_wait`, `terminal`, `after_sense` sowie
   Sense-Key/ASC/ASCQ auswerten. Bei unklarem Ende: keine PDF-Freigabe;
   stoppen und zurückrollen. Erst mit echten Feldwerten darf ein separater
   kleiner Protokollfix geprüft werden. Nicht voraussetzen, dass die
   bisherigen zwei Hardwarefehler mit diesem Build schon verschwunden sind.
6. **Erst nach sauberem Abschluss:** PDF visuell am Testblatt prüfen. Die
   Freischaltung des Speicherns im separaten Ordner ist eine weitere
   ausdrückliche Entscheidung. Zunächst kein produktiver Zielordner und
   keine Änderung von Verbraucher-/SMB-ACLs. Die angemeldete Oberfläche kann
   gespeicherte PDFs weiter anzeigen; der Browser bietet PDF-Download.
   Direkter NAS-Dateizugriff benötigt gegebenenfalls eine gesondert geprüfte
   Leserechteentscheidung. Keine automatische Dokumentweiterleitung.

### Rückfall

Vor dem Umschalten die **tatsächlichen** bisherigen Image-IDs und die
unveränderte Env-/Mount-Konfiguration sichern. Nach fehlgeschlagenem Canary:

- Neuen AirScap-Prozess zuerst stoppen; Stillstand prüfen, danach neuen
  Control stoppen. Nur das neue Projekt `scansnap-goal1` anfassen.
- Den vorherigen AirScap mit genau der gesicherten Image-ID und seiner alten
  Konfiguration starten. Der alte Control-/Worker-Stack bleibt unverändert.
- Neuen Zustand, Intake, Prüfkopia, Ausgabe und Audit aufbewahren. Kein
  `down -v`, kein DB-Reset, kein Aufräumen bestehender Scanordner.
- Nie einen unklaren Auftrag automatisch nochmals scannen oder einen
  ungeprüften Umschlag manuell in einen produktiven Ordner verschieben.

Im isolierten Test wurde der Rückfall auf die exakt vorherigen C3-/A1-
Testimages mit deren separatem ursprünglichem Datenbestand ausgeführt.
Danach wurde der neue Notbetrieb mit unveränderten gespeicherten Dokumenten
neu gestartet. Das ersetzt keinen Nachweis des tatsächlichen QNAP-Ist-Zustands.
