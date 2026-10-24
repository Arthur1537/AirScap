# Secret handling (ScanSnap Control fork)

AirScap handles four kinds of secrets. None of them may appear in logs, debug
traces, error messages or API responses, also not at `AIRSCAP_LOG_LEVEL=debug`.

| Secret | Why it is sensitive |
|---|---|
| Scanner password | Pairs with the scanner. The **default password is the last four characters of the serial** (`vens.PasswordFromSerial`), so a full serial discloses it. |
| Pairing identity | Derived from the password (`vens.ComputeIdentity`); sent in the reserve request. |
| Session token | 6 random bytes in every control and data packet. |
| FTP password, Paperless token | Upload credentials in `settings.json`. |

## Rules in the code

- **Packets** are logged only as `vens.PacketSummary`: length, magic and command
  word. Raw bytes, hex dumps and payload fragments are never logged.
- **Serials** are shown as `vens.RedactSerial` (`iX500-****`) in logs, in the
  Web UI status and in the eSCL `ScannerCapabilities`. `Scanner.DisplaySerial()`
  replaces the raw accessor.
- **Defence in depth:** `cmd/airscap` installs `vens.RedactingHandler`.
  Password, identity, serial and token are registered with `vens.RegisterSecret`
  as soon as they are known (also the FTP password and Paperless token from the
  settings store). Every log record is scrubbed: message, attributes, groups,
  errors, Stringers. Values shorter than three characters are not registered;
  they are protected only by not being logged.
- **Settings API:** `GET /ui/api/settings` returns `ftpPassword` and
  `paperlessToken` empty, plus `ftpPasswordSet` and `paperlessTokenSet`.
  `PUT` with an empty secret keeps the stored one; responses never echo
  secrets. A stored secret cannot be cleared through the UI; overwrite it or
  edit `settings.json`.
- **Storage:** `settings.json` is written owner-only (0600, via a fresh
  temporary file) in a directory created 0700.
- **Upload errors** keep at most 256 bytes of the server response, printable
  only and without the Paperless token. Paperless URLs are logged without
  user information.
- **Python client** (`scan.py`, `scansnap/`): the same rules
  (`scansnap.redact`), `RedactingFilter` on the log handlers. `pair` prints the
  identity only with `--show-identity`.

## Tests

```sh
go mod vendor
CGO_ENABLED=0 go test -mod=vendor -overlay=build/overlay.json ./...
python3 -m unittest discover -s tests
```

- `internal/vens/redact_test.go`, `session_log_test.go`: test secrets, fake
  control channel and fake discovery on 127.0.0.1, debug level, plain
  TextHandler (secrets must be absent at the source).
- `internal/vens/logpolicy_test.go`: AST check of every `slog` call and
  `fmt.Errorf` in `cmd/` and `internal/`.
- `internal/config`, `internal/webui`, `internal/scanner`: settings API,
  file modes, eSCL serial, token registration, bounded upload errors.
- `tests/test_redaction.py`: the Python client, including a fake control
  channel and a static check of log and print calls.

## Operation

- Logs written by earlier versions may contain the identity, the token or
  raw packets: rotate and remove them.
- An existing `settings.json` keeps its mode until the next save. Check
  with `ls -l` and use `chmod 600` and `chmod 700` on the directory if needed.
- `scan.py --password`/`--identity` are visible in the process list; prefer
  the Go service with `AIRSCAP_PASSWORD_FILE`.
