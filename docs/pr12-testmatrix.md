# Abnahmematrix – ausschließlich synthetische Daten

Stand 24.10.2026. Alle folgenden ausgeführten Tests verwenden die im
Evidenzverzeichnis gespeicherten Befehle. Lokale Ergebnisse sind keine
GitHub-CI-Ergebnisse. D4/K1 und produktive QNAP-/SynapseNode-Systemtests
wurden nicht wiederholt. Keine reale Scanneraktion.

| Voraussetzung | Testgegenstand / Nachweis | Erwartung | Tatsächliches Ergebnis |
|---|---|---|---|
| Gepinnte QNAP-Testvenv, private SSC_ROOT | `test_browser_sessions` | Secure/HttpOnly, CSRF, Origin, Widerruf/Ablauf/Logout entziehen Scannerautorität; expliziter Abbruch hält Claim gesperrt; falscher Bearer/DB-Ausfall sperren | bestanden; Teil von qnap.log |
| Temporäre Jobs/Browser | `test_document_lifecycle` | Fremde Eigentümer sperren; kein Überspringen der Nachweiskette; exakte Ergebnis-SHA und manuelle Bestätigungen | bestanden |
| Temporäre private Dateien / gleicher Mount | `test_final_publication` | Ohne Zustimmung/Autorisierung kein Ziel; kein Clobber; Crash/Parallelität nur ein finaler Name; explizite Consumer-GID und 0440-Rechte | 7 Tests bestanden |
| Temporäre SQLite-Datei | `test_controlled_recovery` QNAP | Expliziter Stillstand, Snapshot, Actor/Grund; aktive Jobs/DB-Fehler sperren; Originale erhalten | 4 Tests bestanden einschließlich unterbrochener Ergebnisrücknahme |
| Temporäre Reservation | `test_scan_receipts`, Gateway/Internal-Operationen | Abbruch/Expiry/DB-Fehler keine fertige Aufnahme; Fehlerclaim bleibt gesperrt | bestanden |
| Uvicorn 0.34.2, temporäre Loopbackprozesse | `test_container_start` | Integrierter PR-1-CMD startet, alte Syntax nicht; Forwarded-Header unvertraut | 7 Tests bestanden, kein Container/produktiver Dienst |
| Alle vorgenannten betroffenen QNAP-Module | `evidence/qnap.json` und `.log` | Kein fehlgeschlagener Test | **75 ausgeführt, bestanden** |
| Temporäre Worker-DB/ZIP/PDF | `test_scan_handoff` | Signatur, Replay, Manifest, Pfadnamen, Größen/Hash; Crash verlangt Recovery; höchstens ready | 6 bestanden |
| Temporäre synthetische PKI und echter Loopback-TLS | `test_worker_transport` | Client/Serverrolle, CA, Hostname, Gültigkeit, keine fehlenden/falschen Clients; Rotation mit Überlappung/Entfernen alter CA; Trunkierung/Ack-Konflikt sperren | 7 bestanden; TLS tatsächlich ausgeführt |
| Unterbrochener künstlicher Intake | Worker `test_controlled_recovery` | Kein Render-Zweitstart, Operator-/Snapshot-Gates, Crashsperre, verifizierter Abschluss | 5 neue Recoverytests bestanden |
| Bestehender kontrollierter Renderer / systemd-Double | `test_result_attestation` | Kein Ergebnis vor vollständiger Nachweiskette; Export lässt Slot belegt | 1 bestanden |
| Kontrollierter Renderer / signierte Filing-Receipt | `test_publication_completion` | Nur passende authentisierte filed-Receipt gibt genau ihren Slot frei | 2 bestanden |
| Künstlicher aktiver PDF-Korpus | `test_pdf_active_content` | Aktive Inhalte auch bei gültigem Hash/Seitenzahl abweisen | 10 bestanden |
| Vorgenannte Worker-Module, gepinnte Venv | `evidence/worker.json` / `.log` | Keine Fehler/Überspringungen | **43 ausgeführt, bestanden** einschließlich der D5-Artefakt-/Installationsguards; vorheriger Teilstand 30 |
| Go 1.26.0, vendor + Overlay, private TMPDIR | `evidence/airscap.json` / `.log` | Reservierung vor Feed, alle HTTP-Scanquellen gesperrt, UDP-Filter, Teil-/Close-/ACKfehler, Secret-Schutz | **154 Testfunktionen bestanden; 1 optionaler Cross-Repo-Fixture-Test im Einzelpaketlauf übersprungen** |
| Expliziter Cross-Repo-Runner | Derselbe Go-Fixture-Test über reale QNAP-Reservierungs-API, danach echter mTLS-Worker-Intake, kontrollierter Renderer, Rücknahme, PDF-GET, Zustimmung, einmalige Ablage, Filing-ACK | Vollständige Kette; keine Freigabe vor Ansicht/Zustimmung; Slot erst nach Filing-ACK; Original-Envelope unverändert | **1 Integrationsfall bestanden, inklusive explizit aktivierter zuvor übersprungener Go-Fixture**; `evidence/contract.log` |
| Go-Crosscompiler, keine Ausführung | `evidence/arm64.json` | AirScap als ARM64 bauen | Exit 0; ELF AArch64 bestätigt. Dynamischer Loader vorhanden; keine QNAP-Laufzeitabnahme daraus ableiten |
| Identischer geteilter Transportcode | Bytevergleich QNAP/Worker + Assertion im Integrationsrunner | Kein Protokolldrift | bestanden |
| Dashboard-Script | Node `--check` | Syntax gültig | bestanden; keine echte Browser-/iPad-Sichtprüfung behauptet |
| Github-API-Zugriff | PR-/CI-/Required-Checks-Abfrage | API-Zugriff, keine Annahme aus Git-Push | **blockiert**: api.github.com nicht in bisheriger Laufzeit-Allowlist; Ergänzung nur als Entwurf gespeichert |
| Zertifikate/Accounts/Volumes auf Zielmaschinen | Echte Dienst-/Cross-UID-/Kapazitäts-/Browserabnahme | Separate Betreiberfreigabe und geeignete Testdaten | **nicht ausgeführt**, ausdrücklich außerhalb dieses Auftrags |

## Fehler, die der integrierte Test gefunden hat

1. Der alte AirScap-PDF-Generator produzierte einen leeren EmbeddedFiles-Baum;
   der Worker lehnte korrekt ab. Außerdem doppelte Bildressourcenschlüssel bei
   identischen Seiten. Behoben durch bildbasierten, begrenzten Intake-Writer;
   Worker-Policy wurde nicht gelockert. Derselbe Drei-Seiten-Test besteht jetzt.
2. Der QNAP-Prüfdeskriptor stand nach dem Hash am Dateiende: PDF-GET scheiterte
   mit 503. Rücksetzen des Deskriptors behoben; der echte PDF-GET im Vertragstest
   liefert nun die erwartete Ergebnis-SHA.
3. EndScan-ACK-Fehler wurden im Treiber verschluckt; sie werden jetzt propagiert.
   Fehlgeschlagene Claims bleiben recovery_required statt still freigegeben.
   Ein `success=true` nach Ablauf macht keine Aufnahme berechtigt.
4. Ein eingewickeltes Transport-EOF durfte nicht als Dokumentende gelten.
   Nun ist nur exaktes io.EOF mit bestätigtem vollständigem VENS-Status/
   Sense-Abschluss zulässig; Teilscans nach drei Seiten und uneindeutige
   Abschlussframes werden verweigert. Reale Firmwareannahmen bleiben offen.

## Aussagegrenzen

Papierabsicht, fehlende Rückseiten und reale Seitenreihenfolge sind nicht
vollständig automatisch attestiert. AirScap-Intake unterbindet automatische
Blankseitenentfernung. `capture_duplex=not_attested` bleibt explizit; Benutzer
muss am Original prüfen. Echte GUI-Bedienung, reale Firmware, Quellnetz gegen
UDP-Spoofing, neue Laufzeitinstallation, angewendetes D5/Peer-PID-Binding und Parser-
Ressourcenisolation sind dadurch nicht zusätzlich abgenommen.
