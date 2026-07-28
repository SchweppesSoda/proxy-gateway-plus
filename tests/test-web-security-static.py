#!/usr/bin/env python3
"""Security/setup regressions that intentionally do not exercise the Web backend."""
from __future__ import annotations

import base64
import copy
import importlib.util
import io
import os
from pathlib import Path
import re
import stat
import tempfile
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SETUP_PATH = ROOT / "deploy/web/pdg-web-setup.py"
SETUP_SOURCE = SETUP_PATH.read_text(encoding="utf-8")
CTL_SOURCE = (ROOT / "deploy/web/pdg-webctl.sh").read_text(encoding="utf-8")
UNIT_SOURCE = (ROOT / "deploy/web/pdg-web.service").read_text(encoding="utf-8")
BOT_SOURCE = (ROOT / "deploy/bot/pdg-bot.py").read_text(encoding="utf-8")
TX_SOURCE = (ROOT / "deploy/bot/pdgtx.py").read_text(encoding="utf-8")

spec = importlib.util.spec_from_file_location("pdg_web_setup", SETUP_PATH)
setup = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(setup)
import pdgwebconfig  # noqa: E402


def decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


assert setup.PBKDF2_ITERATIONS >= 600_000
assert setup.runtime_validate_config is pdgwebconfig.validate_config
assert setup.runtime_load_config is pdgwebconfig.load_config
assert setup.CONFIG_PATH == "/etc/privdns-gateway/web.json"

first = setup.make_auth("correct horse battery staple")
second = setup.make_auth("correct horse battery staple")
assert first["algorithm"] == "pbkdf2_sha256"
assert first["iterations"] >= 600_000
assert len(decode(first["salt"])) >= 16
assert len(decode(first["password_hash"])) >= 32
assert len(decode(first["session_secret"])) >= 32
assert first["salt"] != second["salt"]
assert first["session_secret"] != second["session_secret"]
for auth in (first, second):
    for key in ("salt", "password_hash", "session_secret"):
        assert "=" not in auth[key]
        assert re.fullmatch(r"[A-Za-z0-9_-]+", auth[key])

# Secrets may come only from getpass or a one-line stdin secret channel.
assert 'parser.add_argument("--password"' not in SETUP_SOURCE
assert "os.environ" not in SETUP_SOURCE
assert "getpass.getpass" in SETUP_SOURCE
assert "sys.stdin.readline()" in SETUP_SOURCE

# Same-directory, durable, atomic replacement and exact on-disk ownership/modes.
for marker in (
    'tempfile.mkstemp(prefix=".web.json.", dir=parent)',
    "stream.flush()", "os.fsync(stream.fileno())", "os.replace(temp_path, path)",
    "os.fsync(directory_fd)", "os.fchmod(fd, 0o600)", "os.chmod(parent, 0o700)",
    "os.fchown(fd, 0, 0)", "os.chown(parent, 0, 0)",
    "validate_config_file_security(config_path)",
):
    assert marker in SETUP_SOURCE, marker
assert "stat.S_IMODE(parent_info.st_mode) != 0o700" in SETUP_SOURCE
assert "stat.S_IMODE(info.st_mode) != 0o600" in SETUP_SOURCE
assert "os.path.realpath(parent) != parent" in SETUP_SOURCE

# Production setup is pinned to its dedicated config path.  An /etc-like
# override is rejected before any operation that could alter a parent path.
unsafe_config = "/etc/not-the-pdg-directory/web.json"
filesystem_mutations = []


def record_mutation(name):
    def recorder(*_args, **_kwargs):
        filesystem_mutations.append(name)
        raise AssertionError("unexpected filesystem mutation: " + name)
    return recorder


with (
    mock.patch.object(setup.os, "geteuid", return_value=0, create=True),
    mock.patch.object(setup.os, "chmod", side_effect=record_mutation("chmod")),
    mock.patch.object(
        setup.os, "chown", side_effect=record_mutation("chown"), create=True
    ),
    mock.patch.object(setup.os, "mkdir", side_effect=record_mutation("mkdir")),
):
    for operation in (
        lambda: setup.main(
            ["--config", unsafe_config, "--validate-only"]
        ),
        lambda: setup._ensure_parent(unsafe_config),
    ):
        try:
            operation()
        except setup.ConfigError:
            pass
        else:
            raise AssertionError("non-canonical production config path accepted")
assert filesystem_mutations == []

# Even the canonical dedicated directory is not chmod/chown repaired until an
# existing object has proved root:root ownership and safe write permissions.
unsafe_parent = SimpleNamespace(
    st_mode=stat.S_IFDIR | 0o777,
    st_uid=0,
    st_gid=0,
)
safe_container = SimpleNamespace(
    st_mode=stat.S_IFDIR | 0o755,
    st_uid=0,
    st_gid=0,
)
filesystem_mutations = []
with (
    mock.patch.object(setup.os, "lstat", side_effect=[safe_container, unsafe_parent]),
    mock.patch.object(setup.os.path, "realpath", side_effect=lambda path: path),
    mock.patch.object(setup.os, "mkdir", side_effect=FileExistsError),
    mock.patch.object(setup.os, "chmod", side_effect=record_mutation("chmod")),
    mock.patch.object(
        setup.os, "chown", side_effect=record_mutation("chown"), create=True
    ),
):
    try:
        setup._ensure_parent(setup.CONFIG_PATH)
    except setup.ConfigError:
        pass
    else:
        raise AssertionError("unsafe existing dedicated directory accepted")
assert filesystem_mutations == []

# Strict source/network/certificate validation and loopback trust are mandatory.
assert setup.parse_trusted_cidrs(["10.20.0.0/16"]) == [
    "10.20.0.0/16", "127.0.0.1/32", "::1/128",
]
for unsafe in ("0.0.0.0/0", "::/0", "10.20.1.1/16"):
    try:
        setup.parse_trusted_cidrs([unsafe])
    except setup.ConfigError:
        pass
    else:
        raise AssertionError("unsafe/non-canonical CIDR accepted: " + unsafe)
for combined_full_space in (
    ["0.0.0.0/1", "128.0.0.0/1"],
    ["::/1", "8000::/1"],
):
    try:
        setup.parse_trusted_cidrs(combined_full_space)
    except setup.ConfigError:
        pass
    else:
        raise AssertionError("CIDR union equivalent to /0 was accepted")
assert "context.load_cert_chain(cert, key)" in SETUP_SOURCE
assert "_validate_dns_san_hostname(decoded, domain)" in SETUP_SOURCE
assert "ssl.match_hostname" not in SETUP_SOURCE
assert "ssl.cert_time_to_seconds" in SETUP_SOURCE
assert "now < not_before" in SETUP_SOURCE
assert "now > not_after" in SETUP_SOURCE
assert "os.lstat(current)" in SETUP_SOURCE
assert 'getattr(info, "st_uid", 0) != 0' in SETUP_SOURCE
assert "info.st_mode & 0o022" in SETUP_SOURCE
assert "os.readlink(current)" in SETUP_SOURCE
assert "runtime_validate_config(config, testing=False)" in SETUP_SOURCE
assert "runtime_load_config(temp_path, testing=False)" in SETUP_SOURCE
assert "runtime_load_config(config_path, testing=False)" in SETUP_SOURCE
assert 'if name in ("cert_fullchain", "cert_privkey"):' in TX_SOURCE
assert 'atomic_write(t["path"], t["data"], t["mode"], 0, 0)' in TX_SOURCE

# Python 3.13 removed ssl.match_hostname.  Hostname verification remains
# strict and SAN-only, including when that module attribute does not exist.
def decoded_with_sans(*patterns):
    return {
        "subjectAltName": tuple(("DNS", pattern) for pattern in patterns),
        "notBefore": "before",
        "notAfter": "after",
    }


def assert_hostname_rejected(decoded, domain):
    try:
        setup._validate_dns_san_hostname(decoded, domain)
    except setup.ConfigError:
        pass
    else:
        raise AssertionError("unsafe or mismatched DNS SAN accepted")


setup._validate_dns_san_hostname(
    decoded_with_sans("pdg.example.com"), "pdg.example.com"
)
setup._validate_dns_san_hostname(
    decoded_with_sans("*.example.com"), "pdg.example.com"
)
assert_hostname_rejected(
    decoded_with_sans("other.example.com"), "pdg.example.com"
)
assert_hostname_rejected(
    decoded_with_sans("*.example.com"), "example.com"
)
assert_hostname_rejected(
    decoded_with_sans("*.example.com"), "deep.pdg.example.com"
)
for malformed_wildcard in (
    "pdg*.example.com",
    "*pdg.example.com",
    "pdg.*.example.com",
    "*.*.example.com",
    "**.example.com",
    "*..example.com",
    "*.example.com.",
):
    assert_hostname_rejected(
        decoded_with_sans(malformed_wildcard), "pdg.example.com"
    )
assert_hostname_rejected(
    {
        "subject": ((("commonName", "pdg.example.com"),),),
        "notBefore": "before",
        "notAfter": "after",
    },
    "pdg.example.com",
)
# A matching exact SAN does not excuse another malformed DNS wildcard.
assert_hostname_rejected(
    decoded_with_sans("pdg.example.com", "pdg*.example.com"),
    "pdg.example.com",
)


class FakeTLSContext:
    def __init__(self):
        self.loaded = []

    def load_cert_chain(self, cert, key):
        self.loaded.append((cert, key))


fake_tls_context = FakeTLSContext()
missing_api = object()
saved_match_hostname = getattr(setup.ssl, "match_hostname", missing_api)
if saved_match_hostname is not missing_api:
    delattr(setup.ssl, "match_hostname")
try:
    with (
        mock.patch.object(
            setup, "validate_path", side_effect=lambda value, *_args, **_kwargs: value
        ),
        mock.patch.object(
            setup.ssl, "SSLContext", return_value=fake_tls_context
        ),
        mock.patch.object(
            setup.ssl._ssl,
            "_test_decode_cert",
            return_value=decoded_with_sans("pdg.example.com"),
        ),
        mock.patch.object(
            setup.ssl,
            "cert_time_to_seconds",
            side_effect=lambda value: 0 if value == "before" else 200,
        ),
        mock.patch.object(setup.time, "time", return_value=100),
    ):
        setup.validate_certificate(
            "/secure/fullchain.pem",
            "/secure/privkey.pem",
            "pdg.example.com",
        )
finally:
    if saved_match_hostname is not missing_api:
        setattr(setup.ssl, "match_hostname", saved_match_hostname)
assert fake_tls_context.loaded == [
    ("/secure/fullchain.pem", "/secure/privkey.pem")
]

# Certbot-style root-owned live symlinks into a secure archive are accepted,
# while a writable directory anywhere in the chain is rejected.
fake_root = os.path.abspath(os.path.sep)
fake_le = os.path.join(fake_root, "etc", "letsencrypt")
fake_live = os.path.join(fake_le, "live", "pdg.example.com", "fullchain.pem")
fake_target = os.path.join(
    fake_le, "archive", "pdg.example.com", "fullchain1.pem"
)
fake_nodes = {}


def fake_info(mode, path):
    return SimpleNamespace(
        st_mode=mode,
        st_uid=0,
        st_dev=1,
        st_ino=abs(hash(os.path.normcase(path))),
    )


def add_fake_parents(path):
    current = os.path.sep
    parts = [part for part in Path(path).parts if part != os.path.sep]
    for component in parts[:-1]:
        current = os.path.join(current, component)
        fake_nodes[os.path.normcase(current)] = fake_info(
            stat.S_IFDIR | 0o755, current
        )


add_fake_parents(fake_live)
add_fake_parents(fake_target)
fake_nodes[os.path.normcase(fake_live)] = fake_info(
    stat.S_IFLNK | 0o777, fake_live
)
fake_nodes[os.path.normcase(fake_target)] = fake_info(
    stat.S_IFREG | 0o644, fake_target
)
original_lstat = setup.os.lstat
original_readlink = setup.os.readlink
try:
    setup.os.lstat = lambda path: fake_nodes[os.path.normcase(path)]
    setup.os.readlink = lambda path: os.path.relpath(
        fake_target, os.path.dirname(path)
    )
    assert setup.validate_path(fake_live, "TLS certificate") == fake_live
    unsafe_parent = os.path.dirname(fake_live)
    fake_nodes[os.path.normcase(unsafe_parent)] = fake_info(
        stat.S_IFDIR | 0o777, unsafe_parent
    )
    try:
        setup.validate_path(fake_live, "TLS certificate")
    except setup.ConfigError:
        pass
    else:
        raise AssertionError("writable parent in certificate link chain accepted")
finally:
    setup.os.lstat = original_lstat
    setup.os.readlink = original_readlink

# Setup and validate-only use duplicate-rejecting, finite, size-bounded JSON.
with tempfile.TemporaryDirectory() as directory:
    duplicate = Path(directory) / "duplicate.json"
    duplicate.write_text('{"auth": {}, "auth": {}}\n', encoding="utf-8")
    try:
        setup.read_config(str(duplicate))
    except setup.ConfigError:
        pass
    else:
        raise AssertionError("duplicate JSON key accepted")
assert "strict_json_loads(data)" in SETUP_SOURCE
assert "MAX_CONFIG_BYTES + 1" in SETUP_SOURCE

# Exact fields, JSON types, and auth byte maxima are one shared contract.
base_config = {
    "listen": "127.0.0.1",
    "port": 9091,
    "trusted_cidrs": ["127.0.0.1/32", "::1/128"],
    "allowed_hosts": ["pdg.example.com:9091"],
    "allowed_origins": ["https://pdg.example.com:9091"],
    "session_hours": 8,
    "tls": {
        "cert": str(ROOT / "test-cert.pem"),
        "key": str(ROOT / "test-key.pem"),
    },
    "auth": setup.make_auth("correct horse battery staple"),
}
pdgwebconfig.validate_config(base_config, testing=False)
invalid_configs = []
unexpected = copy.deepcopy(base_config)
unexpected["unexpected"] = True
invalid_configs.append(unexpected)
string_port = copy.deepcopy(base_config)
string_port["port"] = "9091"
invalid_configs.append(string_port)
missing_auth = copy.deepcopy(base_config)
missing_auth["auth"].pop("salt")
invalid_configs.append(missing_auth)
for field, size in (
    ("salt", 65),
    ("password_hash", 31),
    ("password_hash", 33),
    ("session_secret", 65),
):
    invalid = copy.deepcopy(base_config)
    invalid["auth"][field] = setup._b64url(b"x" * size)
    invalid_configs.append(invalid)
for invalid in invalid_configs:
    try:
        pdgwebconfig.validate_config(invalid, testing=False)
    except pdgwebconfig.ConfigError:
        pass
    else:
        raise AssertionError("shared production schema accepted invalid config")

# Reject format/bidi and all other Unicode category-C controls in passwords.
original_stdin = setup.sys.stdin
try:
    for unsafe_password in ("valid-password\u202e", "valid-password\x00"):
        setup.sys.stdin = io.StringIO(unsafe_password + "\n")
        try:
            setup._password_from_user(stdin_mode=True)
        except setup.ConfigError:
            pass
        else:
            raise AssertionError("Unicode control accepted in password")
finally:
    setup.sys.stdin = original_stdin

# ctl only reports the exact service interface; it never edits a firewall.
assert "服务接口: %s:%d" in CTL_SOURCE
assert "可信来源 CIDR: %s" in CTL_SOURCE
assert "官方推荐路径是 SSH 隧道" in CTL_SOURCE
assert "忽略 X-Forwarded-For" in CTL_SOURCE
assert "external 模式直连该服务接口" in CTL_SOURCE
assert "当前为 managed input policy" in CTL_SOURCE
assert "unreadable/unknown" in CTL_SOURCE
assert not re.search(
    r"(?m)^\s*(?:sudo\s+)?(?:nft|iptables|ip6tables|ufw|firewall-cmd)(?:\s|$)",
    CTL_SOURCE,
)

for exact in (
    "ConditionPathExists=/etc/privdns-gateway/web.json",
    "User=root", "Group=root", "UMask=0077",
    "ExecStart=/usr/bin/python3 /opt/pdg-web/pdg-web.py",
    "Restart=on-failure", "NoNewPrivileges=true", "PrivateTmp=true",
):
    assert exact in UNIT_SOURCE

# Reject group/supergroup updates before every operation, including callbacks.
message_block = BOT_SOURCE.split('if "message" in u:', 1)[1].split(
    'elif "callback_query" in u:', 1
)[0]
assert message_block.index('get("type") != "private"') < message_block.index(
    'm["from"]["id"] not in ALLOWED'
) < message_block.index("handle_text(")

callback_block = BOT_SOURCE.split('elif "callback_query" in u:', 1)[1]
assert callback_block.index('get("type") != "private"') < callback_block.index(
    'answer_cb_async(q["id"])'
) < callback_block.index('q["from"]["id"] in ALLOWED') < callback_block.index(
    'handle_cb(message["chat"]["id"], message["message_id"], q["data"])'
)
assert '"callback_data": "panel:on:0"' not in BOT_SOURCE
assert 'raw_mins not in ("10", "30")' in BOT_SOURCE
assert 'if ttl <= 0:' in BOT_SOURCE

print("[OK] Web setup/install security static regressions")
