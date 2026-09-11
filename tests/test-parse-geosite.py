#!/usr/bin/env python3
"""Offline protobuf fixtures; never download rules or operate services."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PARSER = ROOT / "deploy/bot/parse-geosite.py"
spec = importlib.util.spec_from_file_location("geosite_parser", PARSER)
parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parser)


def varint(value):
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def field(number, value):
    return varint(number << 3 | 2) + varint(len(value)) + value


def domain(value, kind=None):
    # Type zero is normally absent in proto3 serialization.
    return (b"" if kind is None else b"\x08" + varint(kind)) + field(2, value)


def database(cn=None):
    entries = []
    for category in (b"CN", b"GEOLOCATION-!CN", b"APPLE", b"GFW"):
        domains = cn if category == b"CN" and cn is not None else [domain(b"example.com", 2)]
        entries.append(field(1, field(1, category) + b"".join(field(2, value) for value in domains)))
    return b"".join(entries)


class GeositeParserTests(unittest.TestCase):
    def setUp(self):
        scratch = (ROOT / ".tmp").resolve()
        scratch.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="geosite-parser-", dir=scratch)
        self.root = Path(self.temporary.name).resolve()
        assert self.root.is_relative_to(scratch)
        self.addCleanup(self.temporary.cleanup)
        self.source = self.root / "geosite.dat"
        self.output = self.root / "rules"

    def run_parser(self, data):
        self.source.write_bytes(data)
        return subprocess.run([sys.executable, "-X", "utf8", "-B", str(PARSER), str(self.source), str(self.output)],
                              capture_output=True, text=True, encoding="utf-8", timeout=10)

    def test_matching_types_and_omitted_proto3_default(self):
        result = self.run_parser(database([
            domain(b"implicit"), domain(b"explicit", 0), domain(b"^example$", 1),
            domain(b"example.com", 2), domain(b"www.example.com", 3),
        ]))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.output / "geosite_cn.txt").read_text(encoding="utf-8"),
                         "keyword:implicit\nkeyword:explicit\nregexp:^example$\n"
                         "domain:example.com\nfull:www.example.com\n")
        self.assertEqual(len(list(self.output.glob("*.txt"))), 4)

    def test_field_bounds_and_varint_limits(self):
        for invalid in (b"\x80", b"\x08\x80", b"\x12\x05abc", b"\x0dabc", b"\x09abcdefg",
                        b"\x00\x00", varint(1 << 32) + b"\x00", b"\x0b",
                        b"\x08" + b"\xff" * 9 + b"\x02", b"\x08" + b"\x80" * 10 + b"\x00"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parser._fields(invalid)
        self.assertEqual(parser._rv(varint((1 << 64) - 1), 0), ((1 << 64) - 1, 10))

    def test_well_formed_unknown_fields_remain_skippable(self):
        unknown = (varint(10 << 3) + varint(300)
                   + varint(11 << 3 | 1) + b"12345678"
                   + field(12, b"unused") + varint(13 << 3 | 5) + b"1234")
        result = self.run_parser(unknown + database())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_payloads_leave_existing_outputs_untouched(self):
        self.output.mkdir()
        sentinel = self.output / "geosite_cn.txt"
        sentinel.write_text("original\n", encoding="utf-8")
        invalid_payloads = (
            database() + b"\x12\x05abc",
            database([b"\x08\x02\x12\xff\x01example.com"]),
            database([domain(b"bad\xffname", 2)]),
            database([domain(b"example.com", 4)]),
        )
        for invalid in invalid_payloads:
            with self.subTest(invalid=invalid[-30:]):
                result = self.run_parser(invalid)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(sentinel.read_text(encoding="utf-8"), "original\n")
                self.assertEqual(list(self.output.iterdir()), [sentinel])

    def test_missing_required_category_remains_an_error(self):
        result = self.run_parser(field(1, field(1, b"CN") + field(2, domain(b"example.com", 2))))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
