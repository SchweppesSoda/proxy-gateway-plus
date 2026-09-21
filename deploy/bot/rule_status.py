#!/usr/bin/env python3
"""Rule refresh receipts; no URLs, rule names or exception bodies are persisted.

The existing transaction engine still owns rule application and recovery.
This module records attempts and full successes, never promotes a partial result.
"""
import argparse
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import time

DIRECTORY = "/opt/pdg-bot/rule-status"
COMPONENTS = ("geosite", "rulesets")
WARN_AGE = 48 * 3600
FAIL_AGE = 7 * 86400
RUN_MAX_AGE = 3600
GEOSITE_FILES = ("geosite_cn.txt", "geosite_geolocation-!cn.txt",
                 "geosite_apple.txt", "geosite_gfw.txt")


def content_version(files):
    digest = hashlib.sha256()
    for name, data in sorted(files.items()):
        digest.update(name.encode("utf-8") + b"\0")
        digest.update(hashlib.sha256(data).digest())
    return "sha256:" + digest.hexdigest()


def _trusted(path, directory=False):
    info = os.lstat(path)
    valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    if not valid or (os.name == "posix" and (info.st_uid != os.geteuid() or info.st_mode & 0o022)):
        raise ValueError("unsafe rule status path")


def read(component, directory=DIRECTORY):
    if component not in COMPONENTS:
        raise ValueError("unknown component")
    path = os.path.join(directory, component + ".json")
    _trusted(directory, True)
    _trusted(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(8193)
    if len(raw) > 8192:
        raise ValueError("oversized rule status")
    row = json.loads(raw)
    if (not isinstance(row, dict) or row.get("schema") != 1 or row.get("component") != component
            or not {"lastAttempt", "lastSuccess", "sourceVersion", "failure", "failureCount", "running"} <= row.keys()):
        raise ValueError("invalid rule status")
    for field in ("lastAttempt", "lastSuccess"):
        value = row.get(field)
        if value is not None and (type(value) not in (int, float) or not math.isfinite(value) or value < 0):
            raise ValueError("invalid rule timestamp")
    version = row.get("sourceVersion")
    if version is not None and (not isinstance(version, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", version)):
        raise ValueError("invalid rule version")
    failure = row.get("failure")
    if (type(row.get("running")) is not bool or type(row.get("failureCount")) is not int
            or not 0 <= row["failureCount"] <= 1000000
            or failure not in (None, "refresh_failed", "partial", "exception")):
        raise ValueError("invalid rule outcome")
    return row


class Update:
    def __init__(self, component, directory=DIRECTORY):
        if component not in COMPONENTS:
            raise ValueError("unknown component")
        self.component, self.directory = component, directory
        self.path = os.path.join(directory, component + ".json")
        self.fd = None
        self.finished = False

    def _write(self):
        from pdgtx import atomic_write
        if os.path.lexists(self.path):
            _trusted(self.path)
        atomic_write(self.path, (json.dumps(self.row, sort_keys=True) + "\n").encode(), mode=0o600)

    def __enter__(self):
        import fcntl
        _trusted(os.path.dirname(self.directory), True)
        try:
            os.mkdir(self.directory, 0o700)
        except FileExistsError:
            pass
        _trusted(self.directory, True)
        lock = self.path + ".lock"
        if os.path.lexists(lock):
            _trusted(lock)
        self.fd = os.open(lock, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                self.row = read(self.component, self.directory)
            except FileNotFoundError:
                self.row = {"schema": 1, "component": self.component, "lastSuccess": None,
                            "sourceVersion": None, "failure": None, "failureCount": 0}
            self.row.update(lastAttempt=time.time(), running=True)
            self._write()
            return self
        except BaseException:
            os.close(self.fd)
            self.fd = None
            raise

    def finish(self, success, version=None, partial=False):
        if success and (not isinstance(version, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", version)):
            raise ValueError("missing source version")
        self.row["running"] = False
        if success:
            self.row.update(lastSuccess=time.time(), sourceVersion=version, failure=None, failureCount=0)
        else:
            self.row.update(failure="partial" if partial else "refresh_failed",
                            failureCount=min(1000000, self.row["failureCount"] + 1))
        self._write()
        self.finished = True

    def __exit__(self, *error):
        try:
            if not self.finished:
                self.row.update(running=False, failure="exception",
                                failureCount=min(1000000, self.row["failureCount"] + 1))
                self._write()
        finally:
            os.close(self.fd)


def assessment(component, directory=DIRECTORY, now=None):
    now = time.time() if now is None else now
    try:
        row = read(component, directory)
    except FileNotFoundError:
        return "warn", "unknown", None
    except (OSError, ValueError, TypeError):
        return "warn", "invalid", None
    success, attempt = row["lastSuccess"], row["lastAttempt"]
    age = None if success is None else max(0, now - success)
    detail = dict(row, ageSeconds=None if age is None else int(age))
    if (success is not None and success > now + 300) or attempt is None or attempt > now + 300:
        return "warn", "clock", detail
    if age is not None and age >= FAIL_AGE:
        return "fail", "stale-7d", detail
    if row["running"] and now - attempt >= RUN_MAX_AGE:
        return "warn", "interrupted", detail
    if row["failure"]:
        return "warn", row["failure"], detail
    if age is None:
        return "warn", "unknown", detail
    if age >= WARN_AGE:
        return "warn", "stale-48h", detail
    return "ok", "fresh", detail


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["run-geosite"])
    parser.add_argument("script")
    args = parser.parse_args()
    try:
        with Update("geosite") as update:
            result = subprocess.run(["/bin/bash", args.script, "--recorded-live"], check=False)
            version = None
            if result.returncode == 0:
                files = {}
                for leaf in GEOSITE_FILES:
                    with open("/etc/mosdns/rules/" + leaf, "rb") as stream:
                        files[leaf] = stream.read()
                version = content_version(files)
            update.finish(result.returncode == 0, version)
            return result.returncode
    except Exception as error:
        print("rule update/status unavailable: " + type(error).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
