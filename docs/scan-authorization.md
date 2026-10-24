# Scan authorization (ScanSnap Control fork)

AirScap sends a scan command to the scanner only with a **grant from
ScanSnap Control** (QNAP). The grant is bound to the single armed job
(session) in ScanSnap Control and to the entry point that wants to scan.
Without configuration every scan is refused.

## One checkpoint

`Scanner.StartScan(ctx, source, cfg)` is the only code path that reaches the
data channel's scan commands (`vens.DataChannel.StartScan` already feeds the
first sheet). It asks the configured `authz.Authorizer` for a grant first;
on refusal nothing is sent to the scanner.

| Entry point | Source | Code |
|---|---|---|
| Scan button (local, FTP, Paperless) | `button` | `scanWithPartial` → `Scanner.Scan` |
| eSCL / AirScan client | `escl` | `ESCLAdapter.Scan` → `Scanner.StartScan` |
| Web UI preview `POST /ui/api/scan/preview` | `preview` | `handleScanPreview` → `Scanner.Scan` (403 `scan_not_authorized`) |

`TestScanCommandsOnlyBehindCheckpoint` (source-level policy) fails if
production code calls `vens.DataChannel.StartScan`, `RunScan` or a scan
packet marshaler anywhere else.

## Lifecycle of a grant

1. `POST /internal/v1/reservations {"source": "..."}` → `201` with
   `reservation_id`, `job_id`, `mode`, `source`, `status: "reserved"`.
   Anything else refuses the scan (fail closed). A reservation that cannot be
   used (wrong source, malformed id) is released as failed.
2. Before **every** page `POST …/{id}/activity` → `200`. If the session was
   closed or expired, or ScanSnap Control restarted, the scan is ended at once
   (`EndScan`), the call returns `authz.ErrAuthorizationLost` and pages of
   this scan are **discarded** (button jobs save nothing).
3. `POST …/{id}/finish {"success": bool}` exactly once, also when the
   requesting client went away. `success` is true only if the scanner
   signalled the end of the document; a scan stopped early, a scanner error
   or a lost grant report `false`.

Parallel scans are refused by ScanSnap Control (`scanner busy`). After a
restart of ScanSnap Control, open reservations become `recovery_required`
and block further scans until they are resolved (recovery: PR 7).

## Source policy

ScanSnap Control allows only `button` by default (`SSC_SCAN_SOURCES`).
**eSCL and preview return the pages to the requesting HTTP client**, and
AirScap's eSCL server and Web UI have no authentication yet (PR 6): any host
that reaches AirScap's port could receive the scan of an armed session.
Enable `escl`/`preview` only after PR 6, or when the port is reachable from
trusted hosts only.

## Configuration

```sh
AIRSCAP_CONTROL_URL=http://127.0.0.1:18082          # internal API, never the public proxy
AIRSCAP_CONTROL_TOKEN_FILE=/etc/airscap/control-token # SSC_SCANNER_TOKEN, >= 32 chars
```

- Neither set: AirScap starts, logs a warning and refuses every scan.
- Only one set, an invalid URL (scheme other than http/https, credentials,
  query), or a token file that is not a regular file, is accessible by group
  or others, or holds fewer than 32 characters: AirScap does not start.
- The token is sent only as `Authorization: Bearer` to the configured URL.
  Redirects are not followed. The token is registered for log redaction
  (`docs/secret-handling.md`); refusal details from ScanSnap Control are
  shortened, made printable and scrubbed.

## Limits

- The authorization gates AirScap. Any other VENS client that knows the
  scanner password (for example the Python reference CLI `scan.py` in this
  repository, or ScanSnap apps) can still scan directly. Keep the scanner
  in a network segment that only the QNAP reaches, and change the default
  password (last four characters of the serial).
- Verified with a simulated data channel only. A test with the physical
  iX500 (button, eSCL) is part of the commissioning gates and needs
  separate approval.

## Tests

```sh
go mod vendor
CGO_ENABLED=0 go test -mod=vendor -overlay=build/overlay.json ./...
```

Cross-repository integration with a real ScanSnap Control internal API
(build tag `integration`, skipped without configuration): start
`app.scanner_internal.create_app` with a throwaway database and run

```sh
AIRSCAP_IT_CONTROL_URL=http://127.0.0.1:PORT AIRSCAP_IT_CONTROL_TOKEN=<scanner token> \
AIRSCAP_IT_CONTROL_HELPER="<command>" AIRSCAP_IT_CONTROL_DB=<db> \
CGO_ENABLED=0 go test -mod=vendor -overlay=build/overlay.json -tags integration \
  -run ControlIntegration ./internal/scanner/
```

The helper command gets `reset|expire|close|restart|dump <db>` and changes
only that throwaway database (see `control_integration_test.go`).
