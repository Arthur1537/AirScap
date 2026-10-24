# Phase A – Audit der zehn Draft-PRs

Datum: 24.10.2026. Ausschließlich lesende Quellprüfung abgeschlossen. Git-Refs wurden lokal abgerufen; keine Branches gemergt, kein Quellcode geändert.

**Grenze:** API antwortet auf REST/GraphQL mit Forbidden. PR-Nummern/Links laut Auftrag, Heads und Testmerge-Eltern durch Git bestätigt; Draft-/Open-Status, Reviews, Actions-Läufe und Required Checks nicht unabhängig verifizierbar. Keine grünen CI-Ergebnisse behauptet.

| PR | Head (vollständig) | Base (vollständig) | Basisbranch | Vorgänger enthalten | Testmerge | Tests / CI |
|---|---|---|---|---|---|---|
| [scansnap-control #2](https://github.com/Arthur1537/scansnap-control/pull/2) | `bbe0cface98d5ec3ee8cbc39434d85977666a8c6` | `27cf4c8c63fb082fa6b9181df83c56ccc96cae99` | feature/airscap-session-gateway | ja | Eltern passen; konfliktfrei erzeugter GitHub-Testmerge | kein Workflow im Head; lokale Nachweise siehe unten |
| [scansnap-control #3](https://github.com/Arthur1537/scansnap-control/pull/3) | `290d58ff4c89840188efa199902abff7dcd52f55` | `27cf4c8c63fb082fa6b9181df83c56ccc96cae99` | feature/airscap-session-gateway | ja | Eltern passen; konfliktfrei erzeugter GitHub-Testmerge | kein Workflow im Head; lokale Nachweise siehe unten |
| [scansnap-control #4](https://github.com/Arthur1537/scansnap-control/pull/4) | `5b03322a8f3a1ff3b89336e106c49b8417fa3818` | `290d58ff4c89840188efa199902abff7dcd52f55` | feature/pr3-scan-authorization | ja | Eltern passen; konfliktfrei erzeugter GitHub-Testmerge | kein Workflow im Head; lokale Nachweise siehe unten |
| [scansnap-control #5](https://github.com/Arthur1537/scansnap-control/pull/5) | `f8c0acaca12d27f17b8bcd15e11bf86f65d07bad` | `5b03322a8f3a1ff3b89336e106c49b8417fa3818` | feature/pr5-safe-scan-artifacts | ja | Eltern passen; konfliktfrei erzeugter GitHub-Testmerge | kein Workflow im Head; lokale Nachweise siehe unten |
| [scansnap-control #6](https://github.com/Arthur1537/scansnap-control/pull/6) | `684310f837811ecef5113194ba5090beeac2dbb2` | `f8c0acaca12d27f17b8bcd15e11bf86f65d07bad` | feature/pr6-browser-sessions | ja | Eltern passen; konfliktfrei erzeugter GitHub-Testmerge | kein Workflow im Head; lokale Nachweise siehe unten |
| [AirScap #1](https://github.com/Arthur1537/AirScap/pull/1) | `f6caeb64b321802de64335f00df189a2f2c78d18` | `f78a5000f21bfc975bd7f7aca649575f4ac8b0ab` | feature/scansnap-redact-auth-logs | ja | Eltern passen; konfliktfrei erzeugter GitHub-Testmerge | Workflow nur master; gestapelte Base nicht erfasst; lokale Nachweise siehe unten |
| [AirScap #2](https://github.com/Arthur1537/AirScap/pull/2) | `ee1239f26b1bdd6c2e5cb8e93cbd39f889aad7c5` | `f6caeb64b321802de64335f00df189a2f2c78d18` | feature/pr2-redact-secrets | ja | Eltern passen; konfliktfrei erzeugter GitHub-Testmerge | Workflow nur master; gestapelte Base nicht erfasst; lokale Nachweise siehe unten |
| [AirScap #3](https://github.com/Arthur1537/AirScap/pull/3) | `c8774ba333168da1994963452f1bf6ecec63ca91` | `ee1239f26b1bdd6c2e5cb8e93cbd39f889aad7c5` | feature/pr3-scan-authorization | ja | Eltern passen; konfliktfrei erzeugter GitHub-Testmerge | Workflow nur master; gestapelte Base nicht erfasst; lokale Nachweise siehe unten |
| [scansnap-worker #3](https://github.com/Arthur1537/scansnap-worker/pull/3) | `e23ebc8ef8d7a44ce6280ea28c36472a175fc479` | `4e2d6a9fe94525e4e88a3c0c50e17a2a297344bc` | feature/render-completion-gate-v1 | ja | Eltern passen; konfliktfrei erzeugter GitHub-Testmerge | Laufergebnis/API unbestätigt; lokale Nachweise siehe unten |
| [scansnap-worker #4](https://github.com/Arthur1537/scansnap-worker/pull/4) | `d0ced785bb71aeb56b30a5d2f6ae7fcb9a3f43a5` | `e23ebc8ef8d7a44ce6280ea28c36472a175fc479` | feature/pr4-pdf-active-content | ja | Eltern passen; konfliktfrei erzeugter GitHub-Testmerge | Laufergebnis/API unbestätigt; lokale Nachweise siehe unten |

## Lokale Tests und Dokumentation

Bereits vorhandene Nachweise aus der vorherigen Arbeit: Paket 5: fünf QNAP-Receipt-Tests und zuletzt 56 Scanner/authz-Unit-Tests ohne Skip, ARM64-Build; Paket 6: 13 gezielte Tests mit gepinnten Abhängigkeiten; Paket 7: sieben QNAP-/sechs Worker-Tests plus synthetischer Signier-/Intake-Vertrag. Diese wurden im Audit nicht wiederholt und sind keine GitHub-CI-Bestätigung. PR 1–4: bestehende Testquellen und Betreiberabnahmen berücksichtigt, aktuelle CI-Ergebnisse unbekannt. D4/K1 realer PASS bleibt bestehen.

Überholte Dokumentation: QNAP INBETRIEBNAHME nennt noch keine Web-UI; Worker INSTALLATION beschreibt D4/K1 teils als ungetestet. Aktuelle Paketdokumente sagen korrekt, dass mTLS, schreibende Recovery und finales Publish fehlen. Alte Originalbericht-Dateilinks zeigen in veränderliche Checkouts; Befundmatrix wird deshalb an den Originaltext und dessen alte Commitstände gebunden.

## Stack-Lücken / Sicherheitsblocker

- QNAP #3 basiert neben #2 auf demselben Ausgangscommit; #2 ist kein Vorgänger von #3–#6. Das Docker-CLI-Problem besteht im neuesten Stack fort. Integration benötigt eine explizite Commitübernahme in einen neuen Feature-Branch, keinen automatischen Merge.
- Worker-D5-Branch 418bc5d ist nicht im PR-7-Stack; D5/Peer-Unit-Bindung bleibt gesondert offen.
- mTLS fehlt vollständig, PR 7 ist eine lokale Bibliothek mit HMAC-Receipt.
- Recovery ist nur lesend; visuelle Freigabe und finale Veröffentlichung fehlen.
- AirScap: UDP-Herkunft/Typ und alte direkte Save-Helfer/unauthentifizierte Settings bleiben zu überprüfen. eSCL/Preview bleiben durch Defaultpolicy gesperrt; keine Aktivierung.
- CI-Lücken und API-Zugriff sind Abnahmeblocker. API-Zugriff ist auch für neue Draft-PRs erforderlich; Git-Push funktioniert.

## Zwölfteilige Originalbefundmatrix

| Original-ID | Titel aus Originalquelle | Stand nach Paketen 1–7 |
|---|---|---|
| F01 | Hoch / P0: AirScap kann die QNAP-Autorisierung vollständig umgehen | Teilweise geschlossen durch PR3/5: Reservierungscheckpoint; HTTP-Sources müssen gesperrt bleiben. |
| F02 | Hoch / P0: Geheimnisse bleiben in Go-Debuglogs und Python-Werkzeugen sichtbar | PR2 redigiert Paket-/Python-/Serienausgaben; bisherige Nachweise erhalten, keine neue CI-Bestätigung. |
| F03 | Hoch / P0: AirScap liefert Teilscans aus und schreibt ohne atomaren No-Clobber-Vertrag | Buttonpfad nutzt private atomare Intake-Artefakte; endgültige Dokumentveröffentlichung fehlt. |
| F04 | Hoch / P1: `page-rewrite` entfernt aktive PDF-Inhalte nicht vollständig | PR4 weist aktive Inhalte ab; kein visueller Qualitätsnachweis. |
| F05 | Hoch / P1: PDF-Strukturprüfung ist kein vollständiges Seitenrendering; Parser läuft auch im Worker | Offen: Parser läuft auch privilegierter im Worker; vollständige visuelle Prüfung fehlt. |
| F06 | Mittel / P1: Dauerhafter Browser-Bearer in `localStorage` | PR6: HttpOnly-Sitzung, CSRF, Origin, kein dauerhaft gespeicherter Browser-Bearer. |
| F07 | Mittel / P1: Scanner-Ausschluss ist zeitbasiert und deckt eSCL nicht gemeinsam ab | Teilweise: zentrale DB-Reservierung schützt; alter Zeitguard bleibt zusätzliche, nicht maßgebliche Logik. |
| F08 | Mittel / P1: UDP-Ereignis wird ohne Herkunfts- und Typbindung als Button behandelt | Offen: UDP-Callback ohne hinreichende Herkunft-/Typbindung. |
| F09 | Hoch / P1: AirScap-Settings geben Zielgeheimnisse aus; mitgelieferte Unit läuft standardmäßig als root | Teilweise: Secret-Responses/Persistenz gehärtet; Root-Unit und unauthentifizierte Settingsänderung bleiben. |
| F10 | Mittel / P1: Bekannte Worker-Vertrauensannahmen bleiben trotz K1-PASS bestehen | Offen: D5 nicht integriert und Peer nur UID/GID, nicht konkrete Unit. |
| F11 | Mittel / P1: Nachweise sind datenbankseitig unveränderlich, nicht unabhängig manipulationssicher | Offene Vertrauensgrenze: Trigger sind kein unabhängiger WORM-/extern attestierter Nachweis. |
| F12 | Mittel / P1: Mitgelieferter QNAP-Docker-Startbefehl scheitert vor Anwendungsstart | Fix in QNAP #2 vorhanden, aber nicht im neuesten Stack enthalten. |

Originalquelle: `/workspace/scansnap-review-2026-10-23.md`, SHA-256 `2d31401b2e9a9d17d902ea864ca4ffd402c9eb61aa6e16d380ac1cd8d9a3a69c`. Keine Befund-ID erfunden. Die Bewertungen oben sind aktuelle Nachprüfung, nicht nachträgliche Änderungen des Originals.

Phase A ist in den lokal zugänglichen Teilen abgeschlossen; die CI-/Draft-/Required-Check-Verifikation bleibt konkret durch API-403 blockiert. Phase B–D dürfen unabhängig lokal mit synthetischen Daten fortgesetzt werden. Produktivfreigabe bleibt gesperrt.
