# Network trust (audit block 2, ScanSnap Control fork)

The VENS protocol has no cryptographic authentication: discovery and button
notifications are plain UDP, the control and data channels plain TCP, and
the pairing identity is a reversible encoding of the scanner password
(`vens.ComputeIdentity`). AirScap therefore trusts the network only as far
as the operator restricts it, and narrows what a forged packet can do.

## What the code enforces

| Path | Enforcement |
|---|---|
| Startup | `AIRSCAP_SCANNER_IP` (IPv4 literal) and `AIRSCAP_PASSWORD_FILE` (regular, owner-only file) are required. No broadcast discovery (the first host to answer would be paired with and receive the identity), no serial-derived default password, no `AIRSCAP_PASSWORD` in the environment. The README options "auto-discover" / "auto-derive" do not apply to this fork. |
| Discovery on (re)connect | Only a reply from the configured scanner IP that describes that IP is accepted; forged replies cannot change ports, name or serial. |
| Button (UDP 55265) | Only from the scanner IP, event type 1 / data 0x02000000, one event per burst (quiet period). The packet carries no token, so it cannot be authenticated: a host that forges the scanner's source address can still start a scan, but only for an armed ScanSnap Control session, into that session's job. |
| Scan start | Every scan needs a ScanSnap Control grant; HTTP sources (eSCL, preview) are disabled unconditionally (`docs/scan-authorization.md`). |
| ScanSnap Control API | Bearer scanner token; plain HTTP only to a loopback IP literal, otherwise HTTPS with certificate verification; no redirects. Covers reservations, activity, finish and scan receipts. |

## Operator requirements (acceptance preconditions)

These risks cannot be closed in code:

1. **Network segment:** scanner and QNAP alone in a dedicated SSID/VLAN
   (WPA2/WPA3 with its own key, client isolation for everything else). No
   other host may reach the scanner (TCP 53218/53219, UDP 52217) or AirScap
   (UDP 55264/55265, HTTP port). Otherwise a passive listener learns the
   identity, i.e. the password, from any reserve request, can pair directly
   and bypass AirScap, and can read or replace scanned pages.
2. **Scanner password:** change the default (last four characters of the
   serial, which every discovery reply discloses) and store it only in the
   owner-only `AIRSCAP_PASSWORD_FILE`.
3. **AirScap connected:** the scanner accepts one paired client at a time.
   While AirScap holds the pairing, direct clients are refused; after an
   outage, re-check that AirScap (and not another client) is paired.
4. **ScanSnap Control internal API** bound to 127.0.0.1 only (not published,
   not behind the public reverse proxy).
