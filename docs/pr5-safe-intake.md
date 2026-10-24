# PR 5: private Scanannahme, keine Dokumentfreigabe

Basis: AirScap PR-3-Branch ee1239f; QNAP-Gegenstück benötigt den neuen
`POST /internal/v1/scan-receipts`-Endpunkt. PR 1–4 werden nicht erneut
vollständig systemgetestet. Die Originalreferenz des Reviews ist für diese
Fortsetzung nicht als verbindliche Quelle verfügbar; vorläufige Zuordnung
nur nach Thema: Teilscans, direkte Ausgabe, Reservierungsbindung, sichere
Annahme. Keine neuen/rekonstruierten Befund-IDs.

Der Button nutzt ausschließlich `StageButtonScan`. Er benötigt eine gültige
QNAP-Reservierung, eindeutige Job-ID und Modus sowie `AIRSCAP_STAGING_DIR`.
Dieser vorab bereitgestellte absolute Pfad muss der Service-UID gehören und
0700 haben. Keine Symlinks, keine fremdbeschreibbaren Vorfahren (Ausnahme:
root-eigene Sticky-Verzeichnisse). Das Verzeichnis liegt außerhalb aller
produktiven Consumer-Ziele; bestehende SavePath/FTP/Paperless-Einstellungen
werden im Buttonpfad nicht mehr ausgewertet. Ohne Intakepfad kein Scan.

Vor Aufnahme: fehlerfreies EOF, keine leeren Seiten, vollständiges Decoding
jeder Bildseite, maximal 500 Seiten/128 MiB und 40 Millionen Pixel pro Seite,
erneute Aktivitätsbestätigung und erfolgreicher Scanabschluss samt QNAP-ACK.
Ein Abbruch nach mehreren Seiten liefert kein vollständiges Artefakt.
Ein ZIP enthält genau `manifest.json` und `scan.pdf`: Version, Reservation,
Job, Modus, Quelle, Seitenzahl, PDF-Größe, SHA-256 und
`state=staged_not_released`. Dateiname ausschließlich aus Reservierungs-ID.
Ein exklusiver 0600-Pending-Eintrag wird geschlossen, 0400 gesetzt,
fsync-gesichert und aus dem Dateisystem zurückgelesen/verglichen. Ein
Hardlink publiziert das vollständige Envelope atomar im **privaten Intake**,
ohne vorhandene Namen zu ersetzen, dann folgt Directory-fsync.

Pending und fertiger Intake bleiben erhalten; keine automatische Löschung.
Ein Crash vor Link hinterlässt nur Pending. Nach Link/bei fsync-Fehler ist
der Zustand unklar: kein Retry und keine Freigabe. Das atomare Envelope
verhindert einen sichtbaren PDF/Manifest-Halbsatz. Das ist technische
Annahme, KEINE endgültige Freigabe und KEIN Nachweis visueller Qualität.
Die PDF wird aus vollständig dekodierten Scanbildern erzeugt; zusätzliche
unabhängige PDF-Prüfung, Worker-Nachweise und finales Publish bleiben
separate Gates. Keine Roh-PDF wird in einen produktiven Zielordner bewegt.

Nach dem Link muss QNAP den Manifest-Receipt bestätigen. Fehlender Endpoint,
DB-Fehler, abgelaufene Session oder widersprüchliches Replay melden Fehler;
ein bereits verlinktes Envelope bleibt zur manuellen Prüfung privat liegen.
Der Receipt ist nur eine Aussage des authentifizierten Scanneradapters,
keine kryptografische Scannerattestation und keine Worker-Freigabe.

Verbleibend: eSCL/HTTP-Preview bleiben standardmäßig durch die QNAP-Quellenpolicy
gesperrt; keine Freischaltung in diesem PR. Fremde VENS-Clients bleiben ein
separates Betriebsrisiko. Alte exportierte Save-Helfer sind kein erlaubter
Produktionsweg; der Button ruft sie nicht mehr auf. Bei beliebigem Scanfehler
verwirft auch deren gemeinsamer Wrapper jetzt alle Teilseiten.

Gezielte Prüfungen: StagedScan*, ArtifactNoClobberConcurrent, StageRequiresGrant,
SessionClose, ScannerError und LostAuthorization; ausschließlich synthetische
Seiten/Scanner und temporäre Dateien. Getestet werden EOF, Abbruch nach drei
Seiten, Close-/DB-/Receiptfehler, Timeout, Cancel, Bildfehler, Pfadrechte,
Symlink und Konkurrenz. ARM64-Cross-Build ohne Ausführung. Keine reale
Scanneraktion, Installation oder systemd-Probe.
