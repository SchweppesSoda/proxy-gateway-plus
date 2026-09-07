#!/usr/bin/env python3
"""Exercise the actual parser without the Bot's unrelated Linux service imports."""
import ast
import io
import json
import re
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "deploy/bot/pdg-bot.py"
WANTED = {"_fetch_surge", "_build_source", "_PHONE_DIRECT_DOMAIN_RE", "_mihomo_rulesets"}
tree = ast.parse(SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE))
nodes = [n for n in tree.body if (
    isinstance(n, ast.FunctionDef) and n.name in WANTED
    or isinstance(n, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id in WANTED for t in n.targets))]
namespace = {"urllib": __import__("urllib"), "re": re, "json": json}
exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), "exec"), namespace)
assert WANTED <= namespace.keys(), "required production parser definitions missing"


class DomainProviderTest(unittest.TestCase):
    def parse(self, text, direct=False):
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
                "urllib.request.urlopen", return_value=io.BytesIO(text.encode())):
            path = str(Path(tmp) / "rules.json")
            result = namespace["_build_source"](
                "https://feed.example/AI.yaml", path, phone_direct=direct)
            return result, json.loads(Path(path).read_text())

    def test_exact_and_suffix_domain_payload(self):
        for direct in (False, True):
            with self.subTest(direct=direct):
                result, data = self.parse(
                    "# generated\npayload:\n  - ai.google.dev\n"
                    "  - '+.openai.com'\n  - API.Anthropic.com # exact\n", direct)
                self.assertEqual(result, (3, False))
                self.assertEqual(data, {"version": 1, "rules": [{
                    "domain": ["ai.google.dev", "api.anthropic.com"],
                    "domain_suffix": ["openai.com"]}]})

    def test_classical_payload_compatibility(self):
        result, data = self.parse(
            "payload:\n  - DOMAIN,api.example.com\n"
            "  - DOMAIN-SUFFIX,example.org\n  - DOMAIN-KEYWORD,example\n")
        self.assertEqual(result, (3, False))
        self.assertEqual(data["rules"][0], {
            "domain": ["api.example.com"], "domain_suffix": ["example.org"],
            "domain_keyword": ["example"]})

    def test_unsupported_wildcard_refuses_whole_candidate(self):
        for entry in ("*.openai.com", ".openai.com", "foo.*.example", "+.bad..example"):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                self.parse("payload:\n  - ai.google.dev\n  - '" + entry + "'\n")

    def test_yaml_behavior_survives_runtime_rendering(self):
        for behavior in ("domain", "ipcidr", "classical", None):
            for suffix in ("yaml", "yml?revision=2"):
                with self.subTest(behavior=behavior, suffix=suffix):
                    meta = {"AI": {"url": "https://feed.example/AI." + suffix,
                                   "outbound": "AI", "behavior": behavior}}
                    provider = namespace["_mihomo_rulesets"](meta)["AI"]
                    self.assertEqual(provider["behavior"], behavior or "classical")
                    self.assertEqual(provider["format"], "yaml")

    def test_empty_input_is_not_success(self):
        with self.assertRaises(ValueError):
            self.parse("payload:\n")


if __name__ == "__main__":
    unittest.main()
