"""Redaction of scanner secrets in the Python client (scan.py, scansnap/).

Run from the repository root:  python3 -m unittest discover -s tests

* redact_serial() masks the part of the serial that holds the default
  password; RedactingFilter scrubs registered secrets from every record.
* A fake control channel on 127.0.0.1 exercises the real ControlSession at
  DEBUG level without the filter: token and identity must be absent at the
  source.
* A static check keeps log and print calls from passing secrets.
"""

from __future__ import annotations

import ast
import asyncio
import io
import logging
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scansnap import redact  # noqa: E402
from scansnap.packets import MAGIC  # noqa: E402
from scansnap.scanner import Scanner  # noqa: E402
from scansnap.session import ControlSession  # noqa: E402

TEST_SERIAL = "iX500-QZ9TEST7K3W"
TEST_PASSWORD = "7K3W"
TEST_TOKEN = bytes.fromhex("dec0ad5ec731") + b"\x00\x00"


def capture(level=logging.DEBUG, with_filter=False):
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
    if with_filter:
        redact.install(handler)
    root = logging.getLogger()
    previous = (root.level, list(root.handlers))
    root.handlers = [handler]
    root.setLevel(level)

    def restore():
        root.handlers = previous[1]
        root.setLevel(previous[0])

    return stream, restore


def secret_forms():
    identity = Scanner.compute_identity(TEST_PASSWORD)
    return {
        "serial": TEST_SERIAL,
        "identity": identity,
        "token": TEST_TOKEN.hex(),
        "token prefix": TEST_TOKEN[:6].hex(),
    }


class RedactSerialTests(unittest.TestCase):

    def test_password_is_tail_of_serial(self):
        self.assertEqual(Scanner.password_from_serial(TEST_SERIAL), TEST_PASSWORD)

    def test_masks_password(self):
        cases = {
            TEST_SERIAL: "iX500-****",
            "iX500-AK6ABB0700": "iX500-****",
            "iX1600-AB12\x00\x00": "iX1600-****",
            "AK6ABB0700": "****",
            "iX500-": "****",
            "": "",
        }
        for serial, want in cases.items():
            with self.subTest(serial=serial):
                got = redact.redact_serial(serial)
                self.assertEqual(got, want)
                tail = Scanner.password_from_serial(serial)
                if len(tail) == 4:
                    self.assertNotIn(tail, got)


class FilterTests(unittest.TestCase):

    def test_registered_secrets_scrubbed_in_message_args_and_exceptions(self):
        identity = Scanner.compute_identity(TEST_PASSWORD)
        for secret in (TEST_SERIAL, TEST_PASSWORD, identity, TEST_TOKEN):
            redact.register_secret(secret)
        stream, restore = capture(with_filter=True)
        try:
            log = logging.getLogger("scansnap.test")
            log.debug("identity %s for %s", identity, TEST_SERIAL)
            log.info("token=%s", TEST_TOKEN.hex())
            try:
                raise ValueError(f"pairing failed with {TEST_PASSWORD}")
            except ValueError:
                log.exception("error")
        finally:
            restore()
        out = stream.getvalue()
        for name, secret in secret_forms().items():
            self.assertNotIn(secret, out, name)
        self.assertNotIn(TEST_PASSWORD, out)
        # identity, serial, token, exception message
        self.assertEqual(out.count(redact.REDACTED), 4, out)
        self.assertIn("pairing failed with", out)

    def test_short_values_not_registered(self):
        redact.register_secret("ab")
        self.assertEqual(redact.scrub("ab"), "ab")


class FakeControlServer:
    """Scanner control channel: welcome, one request, response."""

    def __init__(self):
        self.requests = []

    async def handle(self, reader, writer):
        welcome = bytearray(16)
        struct.pack_into("!I", welcome, 0, 16)
        welcome[4:8] = MAGIC
        writer.write(bytes(welcome))
        head = await reader.readexactly(12)
        size = struct.unpack_from("!I", head, 0)[0]
        request = head + await reader.readexactly(size - 12)
        self.requests.append(request)
        if size == 32:
            response = bytes(16)  # register/deregister ack, not length-prefixed
        else:
            # Reserve response: length, status 0 (accepted) at [8:12] and,
            # as the scanner may do, the echoed token.
            response = bytearray(20)
            struct.pack_into("!I", response, 0, 20)
            response[12:20] = request[16:24]
            response = bytes(response)
        writer.write(response)
        await writer.drain()
        writer.close()


class ControlSessionLogTests(unittest.TestCase):

    def test_register_and_configure_log_no_secrets_at_debug(self):
        identity = Scanner.compute_identity(TEST_PASSWORD)
        server = FakeControlServer()

        async def scenario():
            srv = await asyncio.start_server(server.handle, "127.0.0.1", 0)
            port = srv.sockets[0].getsockname()[1]
            async with srv:
                session = ControlSession("127.0.0.1", port)
                await session.register(TEST_TOKEN)
                accepted = await session.try_configure(
                    TEST_TOKEN, "192.168.0.238", identity=identity,
                )
            return accepted

        stream, restore = capture()  # no filter: secrets must be absent at the source
        try:
            accepted = asyncio.run(scenario())
        finally:
            restore()
        self.assertTrue(accepted)
        out = stream.getvalue()
        for name, secret in secret_forms().items():
            self.assertNotIn(secret, out, name)
        for request in server.requests:
            self.assertNotIn(request.hex(), out)
        self.assertIn("Registration response: 16 bytes", out)
        self.assertIn("Pairing accepted", out)


SENSITIVE = {"password", "identity", "ident", "token", "serial", "pair_identity"}


def leaks(node):
    """Names or calls in an expression that carry a secret unredacted."""
    found = []
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name == "redact_serial":
                # Contents are redacted: skip the subtree.
                for sub in ast.walk(child):
                    sub._redacted = True
                continue
            if name == "hex" and isinstance(func, ast.Attribute):
                found.append(".hex()")
    for child in ast.walk(node):
        if getattr(child, "_redacted", False):
            continue
        if isinstance(child, ast.Name) and child.id in SENSITIVE:
            found.append(child.id)
        elif isinstance(child, ast.Attribute) and child.attr in SENSITIVE:
            found.append("." + child.attr)
    return found


def output_calls(tree):
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "print":
            yield node
        elif isinstance(func, ast.Attribute) and func.attr in {
            "debug", "info", "warning", "error", "exception", "critical",
        } and isinstance(func.value, ast.Name) and func.value.id in {"log", "logging", "logger"}:
            yield node


class LogPolicyTests(unittest.TestCase):

    def sources(self):
        return [ROOT / "scan.py", *sorted((ROOT / "scansnap").glob("*.py"))]

    def test_no_secret_in_log_or_print(self):
        checked = 0
        for path in self.sources():
            tree = ast.parse(path.read_text(), str(path))
            for call in output_calls(tree):
                checked += 1
                found = []
                for arg in [*call.args, *(k.value for k in call.keywords)]:
                    found += leaks(arg)
                # scan.py prints the identity only behind --show-identity.
                if found == ["ident"] and path.name == "scan.py":
                    continue
                self.assertEqual(found, [], f"{path.name}:{call.lineno}")
        self.assertGreater(checked, 80)

    def test_identity_printed_only_on_request(self):
        tree = ast.parse((ROOT / "scan.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.If) and any(
                isinstance(n, ast.Attribute) and n.attr == "show_identity"
                for n in ast.walk(node.test)
            ):
                guarded = {id(n) for n in ast.walk(node)}
                break
        else:
            self.fail("no --show-identity guard")
        for call in output_calls(tree):
            if "ident" in sum((leaks(a) for a in call.args), []):
                self.assertIn(id(call), guarded, f"scan.py:{call.lineno}")

    def test_policy_detects_leaks(self):
        for source in (
            'log.info("x %s", password)',
            'log.debug("x %s", resp.hex())',
            'print(f"Serial: {info.serial}")',
            'log.info("Pairing complete! identity=%s", identity)',
        ):
            call = next(output_calls(ast.parse(source)))
            self.assertTrue(sum((leaks(a) for a in call.args), []), source)
        call = next(output_calls(ast.parse('print(f"Serial: {redact_serial(info.serial)}")')))
        self.assertEqual(sum((leaks(a) for a in call.args), []), [])


if __name__ == "__main__":
    unittest.main()
