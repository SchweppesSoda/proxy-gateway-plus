#!/usr/bin/env python3
"""PrivDNS Gateway 健康自检 —— 服务挂 / DNS 不应答 / 证书快到期时 Telegram 私信通知。
按收件人记录观察、确认送达和待发状态；失败有界退避，成功后的相同状态不重复发。
由 pdg-health.timer 定时触发。不把 Telegram 未确认的结果当作送达。
检查逻辑复用 checks.py(与 pdg doctor 同源, 这里只跑轻量子集 checks.ALERT)。
token / 允许 id 读自 /etc/privdns-gateway/bot.env(回退到环境变量 / 旧 unit), 不重复保存。"""
import contextlib
import json
import math
import os
import re
import stat
import sys
import tempfile
import time

ENVF = "/etc/privdns-gateway/bot.env"
SVC = "/etc/systemd/system/pdg-bot.service"   # 仅作旧装兼容回退
STATE = "/opt/pdg-bot/health-state.json"
SCHEMA = 2
RETRY_BASE = 600
RETRY_MAX = 3600
MAX_STATE_BYTES = 1024 * 1024

def _envfile(k):
    try:
        for line in open(ENVF):
            line = line.strip()
            if line.startswith(k + "="):
                return line[len(k) + 1:].strip().strip('"').strip("'")
    except Exception:  # noqa: BLE001
        pass
    return ""

def _svc(k):
    try:
        m = re.search(rf"^Environment={k}=(.*)$", open(SVC).read(), re.M)
        return m.group(1).strip() if m else ""
    except Exception:  # noqa: BLE001
        return ""

def _get(k):  # 环境变量 → bot.env → 旧 unit
    return os.environ.get(k) or _envfile(k) or _svc(k)

os.environ.setdefault("PDG_BOT_TOKEN", _get("PDG_BOT_TOKEN"))
os.environ.setdefault("PDG_CERT", _get("PDG_CERT") or "/etc/mosdns/certs/fullchain.pem")
sys.path.insert(0, "/opt/pdg-bot")
import bot      # noqa: E402  (复用 bot.post 发消息)
import checks   # noqa: E402  (复用检查逻辑)

ALLOWED = [int(x) for x in re.findall(r"\d+", _get("PDG_BOT_ALLOWED"))]

def _problems():
    out = []
    for level, label, detail in checks.run(checks.ALERT):
        if level == "fail":
            out.append(f"❌ {label}: {detail}")
        elif level == "warn":
            out.append(f"⚠️ {label}: {detail}")
    return out

class StateError(Exception):
    """State cannot be used safely; never include its contents in logs."""


def _problem_list(value):
    if (not isinstance(value, list) or len(value) > 128
            or any(not isinstance(item, str) or len(item) > 16384 for item in value)):
        raise StateError("invalid problem list")
    return list(value)


def _timestamp(value):
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value < 0):
        raise StateError("invalid timestamp")
    return value


def _new_recipient(observed=None, unknown=False):
    return {"observed": list(observed or []),
            "delivered": None if unknown else [], "pending": None}


def _decode_state(value, recipients):
    if not isinstance(value, dict):
        raise StateError("invalid state")
    if "schema" not in value:
        # The old file recorded observation even after failed delivery. A nonempty
        # legacy value is unknown, not a receipt; conservatively notify once.
        if set(value) != {"problems"}:
            raise StateError("unknown legacy state")
        previous = _problem_list(value["problems"])
        return {"schema": SCHEMA, "problems": previous,
                "recipients": {str(uid): _new_recipient(previous, bool(previous))
                               for uid in recipients}}
    if value.get("schema") != SCHEMA or not isinstance(value.get("recipients"), dict):
        raise StateError("unsupported state schema")
    result = {"schema": SCHEMA, "problems": _problem_list(value.get("problems")),
              "recipients": {}}
    for uid in recipients:
        key = str(uid)
        if key not in value["recipients"]:
            result["recipients"][key] = _new_recipient()
            continue
        row = value["recipients"][key]
        if not isinstance(row, dict) or not {"observed", "delivered", "pending"} <= row.keys():
            raise StateError("invalid recipient")
        delivered = row.get("delivered")
        result["recipients"][key] = {
            "observed": _problem_list(row.get("observed")),
            "delivered": None if delivered is None else _problem_list(delivered),
            "pending": None,
        }
        pending = row.get("pending")
        if pending is not None:
            if (not isinstance(pending, dict)
                    or pending.get("kind") not in {"problem", "recovery", "resolved"}
                    or type(pending.get("attempts")) is not int
                    or not 0 <= pending["attempts"] <= 4):
                raise StateError("invalid pending notification")
            result["recipients"][key]["pending"] = {
                "kind": pending["kind"], "problems": _problem_list(pending.get("problems")),
                "attempts": pending["attempts"],
                "next_attempt": _timestamp(pending.get("next_attempt")),
            }
        parsed = result["recipients"][key]
        observed, pending = parsed["observed"], parsed["pending"]
        if pending is None:
            consistent = delivered == observed
        elif pending["kind"] == "problem":
            consistent = bool(observed) and pending["problems"] == observed and delivered != observed
        elif pending["kind"] == "recovery":
            consistent = not observed and not pending["problems"] and bool(delivered)
        else:
            consistent = not observed and bool(pending["problems"]) and delivered != pending["problems"]
        if not consistent:
            raise StateError("inconsistent recipient state")
    return result


def _check_parent():
    parent = os.path.dirname(os.path.abspath(STATE))
    info = os.lstat(parent)
    if not stat.S_ISDIR(info.st_mode):
        raise StateError("state directory must be a real directory")
    if os.name == "posix" and (info.st_uid != os.geteuid() or info.st_mode & 0o022):
        raise StateError("unsafe state directory ownership or permissions")
    return parent


def _check_file(info):
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise StateError("state must be a single regular file")
    # Old state can be 0644. Read it without changing its permissions; the next
    # atomic replacement is 0600. Never change the script directory's mode.
    if os.name == "posix" and (info.st_uid != os.geteuid() or info.st_mode & 0o022):
        raise StateError("unsafe state ownership or permissions")


def _check_target(path):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    _check_file(info)


@contextlib.contextmanager
def _state_lock():
    import fcntl  # Linux service; tests replace only this boundary on Windows.
    _check_parent()
    path = STATE + ".lock"
    _check_target(path)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        _check_file(os.fstat(fd))
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise StateError("another health check is running") from None
        yield
    finally:
        os.close(fd)


def _load_state(recipients):
    _check_parent()
    _check_target(STATE)
    try:
        fd = os.open(STATE, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return {"schema": SCHEMA, "problems": [],
                "recipients": {str(uid): _new_recipient() for uid in recipients}}
    with os.fdopen(fd, "rb") as stream:
        _check_file(os.fstat(stream.fileno()))
        raw = stream.read(MAX_STATE_BYTES + 1)
    if len(raw) > MAX_STATE_BYTES:
        raise StateError("state is too large")
    try:
        return _decode_state(json.loads(raw), recipients)
    except (ValueError, TypeError):
        raise StateError("invalid state JSON") from None


def _save_state(value):
    parent = _check_parent()
    _check_target(STATE)
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    if len(raw) > MAX_STATE_BYTES:
        raise StateError("state is too large")
    fd, path = tempfile.mkstemp(prefix=".health-state.", dir=parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        _check_target(STATE)
        os.replace(path, STATE)
        if os.name == "posix":
            directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(path):
            os.unlink(path)


def _observe(row, problems, now):
    previous, delivered, pending = row["observed"], row["delivered"], row["pending"]
    if previous == problems and pending is not None:
        # A backward clock correction must not postpone a retry indefinitely.
        pending["next_attempt"] = min(pending["next_attempt"], now + RETRY_MAX)
        return
    if problems:
        next_pending = None if delivered == problems else {
            "kind": "problem", "problems": list(problems)}
    elif previous and (delivered is None or delivered != previous):
        # Do not send an obsolete alarm followed by an unexplained recovery.
        next_pending = {"kind": "resolved", "problems": list(previous)}
    elif delivered:
        next_pending = {"kind": "recovery", "problems": []}
    else:
        next_pending = None
    row["observed"] = list(problems)
    row["pending"] = next_pending
    if next_pending is not None:
        next_pending.update(attempts=0, next_attempt=now)


def _message(pending):
    if pending["kind"] == "problem":
        text = "🚨 PrivDNS Gateway 异常\n" + "\n".join(pending["problems"])
        text += "\n\n详情: sudo pdg doctor"
    elif pending["kind"] == "resolved":
        text = "✅ PrivDNS Gateway 期间异常已恢复\n之前的异常提醒未确认送达：\n"
        text += "\n".join(pending["problems"])
    else:
        text = "✅ PrivDNS Gateway 已恢复正常"
    # Plain text avoids retrying permanently on an HTML error in check details.
    # Bound UTF-16 units as well as Unicode characters for Telegram's 4096 limit.
    encoded = text.encode("utf-16-le")
    if len(encoded) > 7600:
        text = encoded[:7600].decode("utf-16-le", errors="ignore") + "\n…详情已截短，请运行 sudo pdg doctor"
    return text


def _notify(uid, pending):
    try:
        result = bot.post("sendMessage", {
            "chat_id": uid, "text": _message(pending), "disable_web_page_preview": True})
    except Exception:  # Transport helpers may raise; do not log URL/token/body.
        return False
    # bot.post returns raw Telegram JSON (or {} after transport failure).
    # send/send_plain do not return a receipt, so they cannot be used here.
    return isinstance(result, dict) and result.get("ok") is True


def _update_legacy_view(value):
    rows = list(value["recipients"].values())
    if (rows and all(row["pending"] is None for row in rows)
            and all(row["delivered"] == rows[0]["delivered"] for row in rows)
            and rows[0]["delivered"] is not None):
        value["problems"] = list(rows[0]["delivered"])


def _run(recipients, problems, now):
    value = _load_state(recipients)
    for row in value["recipients"].values():
        _observe(row, problems, now)
    _update_legacy_view(value)
    # Persist the pending event before any send. A crash after acceptance but
    # before the receipt is saved can duplicate. Retries are at least once,
    # not an exactly-once or guaranteed eventual-delivery protocol.
    _save_state(value)
    failed = False
    for uid in recipients:
        row = value["recipients"][str(uid)]
        pending = row["pending"]
        if pending is None or pending["next_attempt"] > now:
            continue
        if _notify(uid, pending):
            row["delivered"] = list(row["observed"])
            row["pending"] = None
        else:
            failed = True
            pending["attempts"] = min(pending["attempts"] + 1, 4)
            pending["next_attempt"] = now + min(RETRY_MAX, RETRY_BASE * 2 ** (pending["attempts"] - 1))
        _update_legacy_view(value)
        _save_state(value)
    if failed:
        print("PDG health notification unconfirmed; retry scheduled", file=sys.stderr)
    return 1 if failed else 0

def main():
    # 凭据判据与 status / doctor / CLI / update 校验门同一份(checks.bot_credentials):
    # 没配齐就没人可通知, 直接安静退出 —— 这不是故障。
    if checks.bot_credentials() != "ready" or not ALLOWED:
        return 0
    try:
        with _state_lock():
            return _run(sorted(set(ALLOWED)), _problem_list(_problems()), time.time())
    except (StateError, OSError, UnicodeError) as error:
        print("PDG health state unavailable: " + type(error).__name__, file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
