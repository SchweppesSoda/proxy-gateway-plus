#!/usr/bin/env python3
"""Persistent, root-only maintenance jobs for the native PDG Web API.

The HTTPS process creates a small immutable job description and asks systemd to
run this file with only the server-generated job id.  The runner reconstructs a
fixed argv from that root-only record; request data is never used as a command
or unit name.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import json
import os
import re
import secrets
import stat
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable, Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover - production is Linux; enables Windows contract tests
    fcntl = None


STATE_DIR = os.environ.get(
    "PDG_WEB_JOB_STATE_DIR", "/var/lib/privdns-gateway/web-jobs")
SNAPSHOT_DIR = os.environ.get(
    "PDG_SNAPSHOT_DIR", "/var/lib/privdns-gateway/backups")
PDG_CLI = os.environ.get("PDG_CLI", "/usr/local/bin/pdg")
RUNNER = os.environ.get("PDG_WEB_JOB_RUNNER", "/opt/pdg-web/pdg-web-job.py")
SYSTEMD_RUN = os.environ.get("PDG_SYSTEMD_RUN", "/usr/bin/systemd-run")
PYTHON = os.environ.get("PDG_PYTHON", "/usr/bin/python3")

_JOB_ID_RE = re.compile(r"^[0-9]{8}t[0-9]{6}z-[a-f0-9]{12}$")
_SNAPSHOT_ID_RE = re.compile(
    r"^[0-9]{8}-[0-9]{6}(?:-[a-f0-9]{8})?$")
_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_ACTIVE = {"queued", "running"}
_TERMINAL = {"succeeded", "failed", "interrupted"}
_RESULTS = {
    "runner_interrupted", "launcher_failed", "boot_changed",
    "operation_failed", "completed", "operation_timed_out",
}
_MAX_RECORD_BYTES = 64 * 1024
_MAX_RECORDS = 50
_WINDOWS_TEST_LOCK = threading.Lock()


class JobError(RuntimeError):
    """Base exception whose text must not be returned by the Web API."""


class JobBusy(JobError):
    pass


class JobInvalid(JobError):
    pass


class JobNotFound(JobError):
    pass


class JobStartError(JobError):
    pass


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(
        microsecond=0).isoformat().replace("+00:00", "Z")


def _boot_id() -> str:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="ascii").strip().lower()
    except OSError:
        return "unknown"
    return value if re.fullmatch(r"[a-f0-9-]{32,40}", value) else "unknown"


class JobStore:
    """Secure persistent state and the single-maintenance-job gate."""

    def __init__(
            self, *, state_dir: str = STATE_DIR, snapshot_dir: str = SNAPSHOT_DIR,
            cli: str = PDG_CLI, runner: str = RUNNER,
            systemd_run: str = SYSTEMD_RUN, python: str = PYTHON,
            run_command: Callable[..., Any] = subprocess.run,
            enforce_root_owner: bool = True):
        self.state_dir = os.path.abspath(state_dir)
        self.snapshot_dir = os.path.abspath(snapshot_dir)
        self.cli = os.path.abspath(cli)
        self.runner = os.path.abspath(runner)
        self.systemd_run = os.path.abspath(systemd_run)
        self.python = os.path.abspath(python)
        self._run_command = run_command
        self._enforce_root_owner = bool(enforce_root_owner)
        self._ensure_state_dir()

    def _ensure_state_dir(self) -> None:
        try:
            before = os.lstat(self.state_dir)
        except FileNotFoundError:
            before = None
        if before is not None and (
                not stat.S_ISDIR(before.st_mode)
                or stat.S_ISLNK(before.st_mode)):
            raise JobInvalid("invalid state directory")
        os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        info = os.lstat(self.state_dir)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise JobInvalid("invalid state directory")
        if os.name != "nt" and self._enforce_root_owner:
            try:
                if info.st_uid != 0 or info.st_gid != 0:
                    os.chown(self.state_dir, 0, 0)
                info = os.lstat(self.state_dir)
            except OSError as exc:
                raise JobInvalid("state directory is not root-owned") from exc
            if info.st_uid != 0 or info.st_gid != 0:
                raise JobInvalid("state directory is not root-owned")
        os.chmod(self.state_dir, 0o700)

    @property
    def _lock_path(self) -> str:
        return os.path.join(self.state_dir, ".lock")

    @contextlib.contextmanager
    def _locked(self, *, blocking: bool = False) -> Iterator[None]:
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self._lock_path, flags, 0o600)
        stream = os.fdopen(fd, "r+", encoding="ascii")
        fallback_locked = False
        try:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise JobInvalid("invalid lock file")
            if os.name != "nt" and self._enforce_root_owner:
                try:
                    if info.st_uid != 0 or info.st_gid != 0:
                        os.fchown(stream.fileno(), 0, 0)
                    info = os.fstat(stream.fileno())
                except OSError as exc:
                    raise JobInvalid("lock file is not root-owned") from exc
                if info.st_uid != 0 or info.st_gid != 0:
                    raise JobInvalid("lock file is not root-owned")
            if hasattr(os, "fchmod"):
                os.fchmod(stream.fileno(), 0o600)
            else:  # pragma: no cover - Windows contract tests
                os.chmod(self._lock_path, 0o600)
            if fcntl is None:
                fallback_locked = _WINDOWS_TEST_LOCK.acquire(blocking=blocking)
                if not fallback_locked:
                    raise JobBusy("job state is busy")
            else:
                try:
                    fcntl.flock(
                        stream.fileno(),
                        fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
                except BlockingIOError as exc:
                    raise JobBusy("job state is busy") from exc
            yield
        finally:
            if fcntl is not None:
                try:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
            elif fallback_locked:
                _WINDOWS_TEST_LOCK.release()
            stream.close()

    def _record_path(self, job_id: str) -> str:
        if not isinstance(job_id, str) or not _JOB_ID_RE.fullmatch(job_id):
            raise JobInvalid("invalid job id")
        return os.path.join(self.state_dir, job_id + ".json")

    @staticmethod
    def _validate_record(record: Any, job_id: str) -> dict[str, Any]:
        if (
                not isinstance(job_id, str)
                or not _JOB_ID_RE.fullmatch(job_id)
                or not isinstance(record, dict)
                or set(record) - {
                "id", "kind", "status", "createdAt", "bootId", "unit",
                "snapshotId", "startedAt", "finishedAt", "result"}):
            raise JobInvalid("invalid job record")
        required = {"id", "kind", "status", "createdAt", "bootId", "unit"}
        if not required <= set(record) or record.get("id") != job_id:
            raise JobInvalid("invalid job record")
        if (
                not isinstance(record.get("createdAt"), str)
                or not _UTC_RE.fullmatch(record["createdAt"])):
            raise JobInvalid("invalid job record")
        kind = record.get("kind")
        status = record.get("status")
        if kind not in {"rollback", "software-update"}:
            raise JobInvalid("invalid job record")
        if status not in _ACTIVE | _TERMINAL:
            raise JobInvalid("invalid job record")
        if record.get("unit") != "pdg-web-job-" + job_id + ".service":
            raise JobInvalid("invalid job record")
        boot_id = record.get("bootId")
        if not isinstance(boot_id, str) or not (
                boot_id == "unknown"
                or re.fullmatch(r"[a-f0-9-]{32,40}", boot_id)):
            raise JobInvalid("invalid job record")
        parsed_times: dict[str, dt.datetime] = {}
        for field in ("createdAt", "startedAt", "finishedAt"):
            if field not in record:
                continue
            value = record[field]
            if not isinstance(value, str) or not _UTC_RE.fullmatch(value):
                raise JobInvalid("invalid job record")
            try:
                parsed_times[field] = dt.datetime.strptime(
                    value, "%Y-%m-%dT%H:%M:%SZ")
            except ValueError as exc:
                raise JobInvalid("invalid job record") from exc
        if (
                parsed_times.get("startedAt", parsed_times["createdAt"])
                < parsed_times["createdAt"]
                or parsed_times.get("finishedAt", parsed_times["createdAt"])
                < parsed_times["createdAt"]
                or (
                    "startedAt" in parsed_times
                    and "finishedAt" in parsed_times
                    and parsed_times["finishedAt"] < parsed_times["startedAt"])):
            raise JobInvalid("invalid job record")
        if kind == "rollback":
            if not isinstance(record.get("snapshotId"), str) or not (
                    _SNAPSHOT_ID_RE.fullmatch(record["snapshotId"])):
                raise JobInvalid("invalid job record")
        elif "snapshotId" in record:
            raise JobInvalid("invalid job record")
        if status == "queued" and set(record) & {
                "startedAt", "finishedAt", "result"}:
            raise JobInvalid("invalid job record")
        if status == "running" and (
                "startedAt" not in record
                or set(record) & {"finishedAt", "result"}):
            raise JobInvalid("invalid job record")
        if status in _TERMINAL and (
                "finishedAt" not in record
                or record.get("result") not in _RESULTS):
            raise JobInvalid("invalid job record")
        result = record.get("result")
        if (
                (status == "succeeded" and result != "completed")
                or (status == "failed" and result not in {
                    "launcher_failed", "operation_failed",
                    "operation_timed_out"})
                or (status == "interrupted" and result not in {
                    "runner_interrupted", "boot_changed"})):
            raise JobInvalid("invalid job record")
        requires_started = (
            status == "succeeded"
            or result in {"operation_failed", "operation_timed_out"}
        )
        forbids_started = result in {"launcher_failed", "boot_changed"}
        if (
                (requires_started and "startedAt" not in record)
                or (forbids_started and "startedAt" in record)):
            raise JobInvalid("invalid job record")
        return record

    def _read_record(self, job_id: str) -> dict[str, Any]:
        path = self._record_path(job_id)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
            info = os.fstat(fd)
            if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or (
                        os.name != "nt"
                        and info.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
                    or not 1 <= info.st_size <= _MAX_RECORD_BYTES):
                os.close(fd)
                raise JobInvalid("invalid job record")
            if (
                    os.name != "nt" and self._enforce_root_owner
                    and (info.st_uid != 0 or info.st_gid != 0)):
                os.close(fd)
                raise JobInvalid("job record is not root-owned")
            with os.fdopen(fd, "r", encoding="utf-8") as stream:
                record = json.load(stream)
        except FileNotFoundError as exc:
            raise JobNotFound("job not found") from exc
        except (OSError, ValueError, TypeError) as exc:
            raise JobInvalid("invalid job record") from exc
        return self._validate_record(record, job_id)

    def _write_record(self, record: dict[str, Any]) -> None:
        job_id = record.get("id")
        self._validate_record(record, job_id)
        path = self._record_path(job_id)
        data = json.dumps(
            record, ensure_ascii=True, sort_keys=True,
            separators=(",", ":")).encode("utf-8")
        if not 1 <= len(data) <= _MAX_RECORD_BYTES:
            raise JobInvalid("invalid job record size")
        fd, temporary = tempfile.mkstemp(
            prefix="." + job_id + ".", dir=self.state_dir)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            else:  # pragma: no cover - Windows contract tests
                os.chmod(temporary, 0o600)
            if os.name != "nt" and self._enforce_root_owner:
                os.fchown(fd, 0, 0)
            with os.fdopen(fd, "wb", closefd=True) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            if os.name != "nt":
                directory_fd = os.open(
                    self.state_dir, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def _record_ids(self) -> list[str]:
        try:
            names = os.listdir(self.state_dir)
        except OSError as exc:
            raise JobInvalid("cannot list job state") from exc
        return sorted(
            (name[:-5] for name in names
             if name.endswith(".json") and _JOB_ID_RE.fullmatch(name[:-5])),
            reverse=True,
        )

    def _unit_state(self, unit: str) -> str:
        try:
            result = self._run_command(
                ["systemctl", "is-active", unit],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, timeout=5, check=False)
            value = str(getattr(result, "stdout", "")).strip()
        except Exception:
            return "unknown"
        return value if value in {
            "active", "activating", "deactivating", "inactive", "failed"
        } else "unknown"

    def _reconcile(self, record: dict[str, Any]) -> dict[str, Any]:
        if record.get("status") not in _ACTIVE:
            return record
        interrupted = record.get("bootId") != _boot_id()
        unit = record.get("unit")
        # systemd-run --no-block can return just before the transient unit moves
        # out of inactive.  Never turn a freshly queued job into interrupted
        # during that harmless launch window.
        age = 0.0
        age_field = (
            "startedAt" if record.get("status") == "running" else "createdAt")
        try:
            observed = dt.datetime.fromisoformat(
                str(record.get(age_field, "")).replace("Z", "+00:00"))
            age = max(0.0, (
                dt.datetime.now(dt.timezone.utc) - observed
            ).total_seconds())
        except (TypeError, ValueError):
            age = float("inf")
        check_unit = record.get("status") == "running"
        if not check_unit and record.get("status") == "queued":
            check_unit = age >= 60
        if not interrupted and check_unit and isinstance(unit, str):
            unit_state = self._unit_state(unit)
            interrupted = unit_state in {"inactive", "failed"}
            if unit_state == "unknown":
                if record.get("status") == "queued":
                    interrupted = age >= 5 * 60
                else:
                    maximum = (
                        50 * 60 if record.get("kind") == "software-update"
                        else 20 * 60)
                    interrupted = age >= maximum
        if interrupted:
            record = dict(record)
            record["status"] = "interrupted"
            record["finishedAt"] = _utc_now()
            record["result"] = "runner_interrupted"
            self._write_record(record)
        return record

    def _assert_idle_locked(self) -> None:
        records: list[dict[str, Any]] = []
        for job_id in self._record_ids():
            record = self._reconcile(self._read_record(job_id))
            records.append(record)
            if record.get("status") in _ACTIVE:
                raise JobBusy("maintenance job already active")
        self._prune_terminal_locked(records)

    def _prune_terminal_locked(
            self, records: list[dict[str, Any]] | None = None) -> None:
        if records is None:
            records = [
                self._reconcile(self._read_record(job_id))
                for job_id in self._record_ids()
            ]
        terminal = [
            record for record in records
            if record.get("status") in _TERMINAL
        ]
        removed = False
        for record in terminal[_MAX_RECORDS:]:
            # _read_record above already validated regular-file/link/owner/mode
            # invariants before this exact server-generated path is unlinked.
            os.unlink(self._record_path(record["id"]))
            removed = True
        if removed and os.name != "nt":
            directory_fd = os.open(
                self.state_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

    @contextlib.contextmanager
    def maintenance_guard(self) -> Iterator[None]:
        """Exclude job submission while a synchronous maintenance action runs."""

        with self._locked():
            self._assert_idle_locked()
            yield

    def list_snapshots(self) -> list[dict[str, Any]]:
        root = Path(self.snapshot_dir)
        try:
            root_info = root.lstat()
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise JobInvalid("cannot list snapshots") from exc
        if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
            raise JobInvalid("invalid snapshot directory")
        if (
                os.name != "nt" and self._enforce_root_owner
                and (
                    root_info.st_uid != 0 or root_info.st_gid != 0
                    or root_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH))):
            raise JobInvalid("untrusted snapshot directory")
        try:
            entries = list(root.iterdir())
        except OSError as exc:
            raise JobInvalid("cannot list snapshots") from exc
        out: list[dict[str, Any]] = []
        for entry in entries:
            snapshot_id = entry.name
            if not _SNAPSHOT_ID_RE.fullmatch(snapshot_id):
                continue
            archive = entry / "snap.tar.gz"
            try:
                dir_info = entry.lstat()
                file_info = archive.lstat()
            except OSError:
                continue
            if (
                    not stat.S_ISDIR(dir_info.st_mode)
                    or stat.S_ISLNK(dir_info.st_mode)
                    or not stat.S_ISREG(file_info.st_mode)
                    or stat.S_ISLNK(file_info.st_mode)
                    or file_info.st_nlink != 1
                    or not 0 < file_info.st_size <= 1024 * 1024 * 1024
                    or (
                        os.name != "nt" and self._enforce_root_owner
                        and (
                            dir_info.st_uid != 0 or dir_info.st_gid != 0
                            or file_info.st_uid != 0 or file_info.st_gid != 0
                            or dir_info.st_mode & (
                                stat.S_IWGRP | stat.S_IWOTH)
                            or file_info.st_mode & (
                                stat.S_IWGRP | stat.S_IWOTH)
                        )
                    )):
                continue
            created = dt.datetime.fromtimestamp(
                dir_info.st_mtime, tz=dt.timezone.utc).replace(
                    microsecond=0).isoformat().replace("+00:00", "Z")
            out.append({
                "id": snapshot_id,
                "createdAt": created,
                "size": file_info.st_size,
                "_mtime": dir_info.st_mtime,
            })
        out.sort(key=lambda item: (item["_mtime"], item["id"]), reverse=True)
        for item in out:
            item.pop("_mtime", None)
        return out[:10]

    def resolve_snapshot_id(self, snapshot_id: str) -> str:
        if (
                not isinstance(snapshot_id, str)
                or not _SNAPSHOT_ID_RE.fullmatch(snapshot_id)):
            raise JobInvalid("invalid snapshot id")
        if not any(
                item["id"] == snapshot_id for item in self.list_snapshots()):
            raise JobNotFound("snapshot not found")
        return snapshot_id

    def snapshot_id_for_index(self, index: int) -> str:
        snapshots = self.list_snapshots()
        if type(index) is not int or not 0 <= index < len(snapshots):
            raise JobNotFound("snapshot not found")
        return str(snapshots[index]["id"])

    def _new_job_id(self) -> str:
        prefix = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dt%H%M%Sz")
        for _ in range(10):
            job_id = prefix + "-" + secrets.token_hex(6)
            if not os.path.lexists(self._record_path(job_id)):
                return job_id
        raise JobStartError("cannot allocate job id")

    def start(self, kind: str, *, snapshot_id: str | None = None) -> dict[str, Any]:
        if kind not in {"rollback", "software-update"}:
            raise JobInvalid("invalid job kind")
        if kind != "rollback" and snapshot_id is not None:
            raise JobInvalid("unexpected snapshot id")
        with self._locked():
            self._assert_idle_locked()
            if kind == "rollback":
                # Exact snapshot resolution belongs to the same state-lock
                # critical section as the idle gate.  A concurrent Web snapshot
                # maintenance guard therefore cannot prune the accepted ID
                # between validation and job publication.
                snapshot_id = self.resolve_snapshot_id(snapshot_id or "")
            job_id = self._new_job_id()
            unit = "pdg-web-job-" + job_id.lower() + ".service"
            record: dict[str, Any] = {
                "id": job_id,
                "kind": kind,
                "status": "queued",
                "createdAt": _utc_now(),
                "bootId": _boot_id(),
                "unit": unit,
            }
            if snapshot_id is not None:
                record["snapshotId"] = snapshot_id
            self._write_record(record)
        # Release the state lock before systemd can start the runner.  With
        # --no-block the child may execute immediately; launching while holding
        # our nonblocking flock would make that child fail with JobBusy.
        argv = [
            self.systemd_run,
            "--collect",
            "--no-block",
            "--unit=" + unit,
            "--property=Type=exec",
            "--",
            self.python,
            self.runner,
            "run",
            "--job-id",
            job_id,
        ]
        launch_error: Exception | None = None
        try:
            result = self._run_command(
                argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=30, check=False)
            if getattr(result, "returncode", 1) != 0:
                launch_error = JobStartError("cannot launch job")
        except Exception as exc:
            launch_error = exc
        if launch_error is not None:
            with self._locked():
                latest = self._read_record(job_id)
                if latest.get("status") == "queued":
                    latest["status"] = "failed"
                    latest["finishedAt"] = _utc_now()
                    latest["result"] = "launcher_failed"
                    self._write_record(latest)
            raise JobStartError("cannot launch job") from launch_error
        return dict(record)

    def get(self, job_id: str) -> dict[str, Any]:
        with self._locked():
            return dict(self._reconcile(self._read_record(job_id)))

    def list(self) -> list[dict[str, Any]]:
        with self._locked():
            records = [
                dict(self._reconcile(self._read_record(job_id)))
                for job_id in self._record_ids()[:_MAX_RECORDS]
            ]
        return records

    def run(self, job_id: str) -> int:
        # A read request can briefly hold the state lock just as systemd starts
        # us.  The dedicated runner waits for that finite critical section
        # instead of losing the job; Web request paths remain nonblocking.
        with self._locked(blocking=True):
            record = self._read_record(job_id)
            if record.get("status") != "queued":
                raise JobInvalid("job is not queued")
            if record.get("bootId") != _boot_id():
                record["status"] = "interrupted"
                record["finishedAt"] = _utc_now()
                record["result"] = "boot_changed"
                self._write_record(record)
                return 1
            record["status"] = "running"
            record["startedAt"] = _utc_now()
            self._write_record(record)
        status = "failed"
        result_code = "operation_failed"
        try:
            kind = record.get("kind")
            if kind == "rollback":
                snapshot_id = self.resolve_snapshot_id(
                    record.get("snapshotId", ""))
                argv = [
                    self.cli, "rollback", "--dir",
                    os.path.join(self.snapshot_dir, snapshot_id),
                ]
                timeout = 15 * 60
            elif kind == "software-update":
                argv = [self.cli, "update"]
                timeout = 45 * 60
            else:
                raise JobInvalid("invalid job operation")
            if not argv:
                raise JobInvalid("invalid job operation")
            result = self._run_command(
                argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=timeout, check=False)
            if getattr(result, "returncode", 1) == 0:
                status = "succeeded"
                result_code = "completed"
        except subprocess.TimeoutExpired:
            result_code = "operation_timed_out"
        except Exception:
            result_code = "operation_failed"
        finally:
            with self._locked(blocking=True):
                latest = self._read_record(job_id)
                if latest.get("status") in _ACTIVE:
                    latest["status"] = status
                    latest["finishedAt"] = _utc_now()
                    latest["result"] = result_code
                    self._write_record(latest)
        return 0 if status == "succeeded" else 1


def _arguments(argv=None):
    parser = argparse.ArgumentParser(description="PDG Web maintenance job runner")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--job-id", required=True)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = _arguments(argv)
    try:
        store = JobStore()
        if args.command == "run":
            return store.run(args.job_id)
    except JobError:
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
