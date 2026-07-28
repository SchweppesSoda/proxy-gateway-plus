#!/usr/bin/env python3
"""Safely splice the owned ``table inet pdg`` block into nftables.conf.

Replace:
    nftmerge.py [--mode managed|external] <rendered-block> <target> <output>
Remove:
    nftmerge.py --remove <target> <output>

Only a table with the exact PDG owner marker and a valid schema shape may be
replaced or removed. A markerless or malformed same-name table is foreign and
causes a fail-closed exit without writing the output.

Exit codes: 0=success; 2=unbalanced PDG block; 3=unsafe flush ruleset;
            4=foreign/malformed same-name table; 1=other error.
"""
import os
from pathlib import Path
import re
import subprocess
import sys

try:
    import nftscan
except ImportError:  # Loaded through a path rather than executed beside this file.
    import importlib.util
    _scan_path = Path(__file__).with_name("nftscan.py")
    _spec = importlib.util.spec_from_file_location("nftscan", _scan_path)
    nftscan = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(nftscan)


BANNER = "# ==== PrivDNS Gateway 管理区(table inet pdg): owner/schema 由 pdg 自动维护 ===="
OLD_BANNER = "# ==== PrivDNS Gateway 管理区(table inet pdg): 由 pdg 自动维护, 勿手改 ===="
VALID_MODES = ("managed", "external")
MODE_FILE = "/etc/privdns-gateway/firewall-mode"
PROFILE_FILE = "/etc/privdns-gateway/profile.env"
MANAGED_BEGIN = "# PDG_MANAGED_INPUT_BEGIN"
MANAGED_END = "# PDG_MANAGED_INPUT_END"

DECL = re.compile(r"^\s*table\s+inet\s+pdg\s*$")
DELETE = re.compile(r"^\s*delete\s+table\s+inet\s+pdg\s*$")
OPEN = re.compile(r"^\s*table\s+inet\s+pdg\s*\{")
OTHER_TABLE = re.compile(r"^\s*table\s+\S+\s+(\S+)")
OWNER_MODE = re.compile(
    r"(owner=privdns-gateway;schema=1;component=firewall;mode=)"
    r"(managed|external|__FIREWALL_MODE__)"
)


class MergeError(Exception):
    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


def _read(path):
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError:
        return ""


def _strict_mode(value, source):
    value = value.strip()
    if value not in VALID_MODES:
        raise MergeError("%s 中的 firewall mode 无效: %r（只能是 managed 或 external）"
                         % (source, value), 4)
    return value


def _persisted_mode(block):
    """Resolve mode for callers predating ``--mode`` (notably reload/migration)."""
    marker = ""
    if os.path.exists(MODE_FILE):
        marker = _strict_mode(_read(MODE_FILE), MODE_FILE)
    profile = _read(PROFILE_FILE)
    values = []
    for raw in profile.splitlines():
        match = re.match(r"^\s*PDG_FIREWALL_MODE=(.*)$", raw)
        if match:
            values.append(match.group(1))
    if len(values) > 1:
        raise MergeError("%s 中 PDG_FIREWALL_MODE 重复" % PROFILE_FILE, 4)
    if values:
        profile_mode = _strict_mode(values[0], PROFILE_FILE)
        if marker and marker != profile_mode:
            raise MergeError("firewall-mode state 与 profile.env 不一致", 4)
        return profile_mode
    if marker:
        return marker
    match = OWNER_MODE.search(block)
    if match and match.group(2) in VALID_MODES:
        return match.group(2)
    return "managed"


def _render_mode(block, mode):
    """Render owner mode and remove the host-firewall block for external mode."""
    if mode not in VALID_MODES:
        raise MergeError("firewall mode 只能是 managed 或 external", 4)
    block = OWNER_MODE.sub(lambda match: match.group(1) + mode, block)
    lines, out, inside = block.splitlines(), [], False
    begin_seen = end_seen = 0
    for line in lines:
        stripped = line.strip()
        if stripped == MANAGED_BEGIN:
            if inside:
                raise MergeError("PDG managed input 区重复开始", 2)
            inside = True
            begin_seen += 1
            continue
        if stripped == MANAGED_END:
            if not inside:
                raise MergeError("PDG managed input 区缺少开始标记", 2)
            inside = False
            end_seen += 1
            continue
        if mode == "external" and inside:
            continue
        out.append(line)
    if inside or begin_seen != 1 or end_seen != 1:
        raise MergeError("PDG managed input 区边界不完整", 2)
    rendered = "\n".join(out).rstrip("\n")
    if nftscan.pdg_table_status(rendered) != "owned-" + mode:
        raise MergeError("待合并的 PDG 表 owner/schema marker 或结构无效", 4)
    return rendered


def _target_status(text):
    status = nftscan.pdg_table_status(text)
    banner_count = text.count(BANNER) + text.count(OLD_BANNER)
    naked = sum(1 for line in text.splitlines() if DECL.match(line))
    deletes = sum(1 for line in text.splitlines() if DELETE.match(line))
    bodies = len(nftscan._pdg_blocks(text))
    if status == "absent":
        if banner_count or naked or deletes or bodies:
            return "foreign"
        return status
    if status == "foreign":
        if nftscan.legacy_stock_pdg_status(text):
            return "legacy-stock"
        return status
    # Generated schema contains at most one guard declaration/delete and one body.
    if banner_count > 1 or naked > 1 or deletes > 1 or bodies != 1:
        return "foreign"
    return status


def _remove_owned(text, target, allow_legacy=False):
    status = _target_status(text)
    if status == "legacy-stock" and not allow_legacy:
        raise MergeError(
            "冲突位置: %s 的 markerless 历史 PDG 表只能由升级流程替换，"
            "不能作为 owned schema 删除" % target, 4)
    if status == "foreign":
        raise MergeError(
            "冲突位置: %s 的 `table inet pdg` 不是合法 owned schema；拒绝替换或删除"
            % target, 4)
    if status == "absent":
        return text, None
    lines = text.split("\n")
    keep, i, first_hit = [], 0, None
    while i < len(lines):
        line = lines[i]
        if line.strip() in (BANNER, OLD_BANNER) or DECL.match(line) or DELETE.match(line):
            first_hit = len(keep) if first_hit is None else first_hit
            i += 1
            continue
        if OPEN.match(line):
            first_hit = len(keep) if first_hit is None else first_hit
            start_line, depth = i + 1, 0
            while i < len(lines):
                structural = nftscan._strip_noise(lines[i])
                depth += structural.count("{") - structural.count("}")
                i += 1
                if depth <= 0:
                    break
            if depth:
                raise MergeError(
                    "冲突位置: %s 第 %d 行起的 PDG 表括号不配平"
                    % (target, start_line), 2)
            continue
        keep.append(line)
        i += 1
    return "\n".join(keep), first_hit


def _check_flush(lines, target):
    flush_line = next((index + 1 for index, line in enumerate(lines)
                       if re.match(r"^\s*flush\s+ruleset\s*$", line)), None)
    if not flush_line:
        return
    in_file = set()
    for line in lines:
        match = OTHER_TABLE.match(line)
        if match:
            parts = line.split()
            if len(parts) >= 3:
                in_file.add("%s %s" % (parts[1], parts[2].rstrip("{")))
    in_file.add("inet pdg")
    live = []
    exe = nftscan.nft_bin()
    if exe:
        try:
            proc = subprocess.run(
                [exe, "list", "tables"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                universal_newlines=True,
                timeout=15,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and parts[0] == "table":
                        live.append("%s %s" % (parts[1], parts[2]))
        except (OSError, subprocess.SubprocessError):
            pass
    lost = [table for table in live if table not in in_file]
    if lost:
        details = "\n".join("    table %s" % table for table in lost[:5])
        raise MergeError(
            "冲突位置: %s 第 %d 行 `flush ruleset` 会删除只存在于运行中的表:\n%s\n"
            "  请先把它们写进持久配置（或移除该 flush）再重试。"
            % (target, flush_line, details),
            3,
        )


def _write(path, content):
    if not content.endswith("\n"):
        content += "\n"
    Path(path).write_text(content, encoding="utf-8")


def _replace(block_path, target_path, output_path, explicit_mode):
    source = _read(block_path)
    match = re.search(r"^\s*table\s+inet\s+pdg\b", source, re.M)
    if not match:
        raise MergeError("待合并文件中没有 `table inet pdg`", 4)
    source = source[match.start():]
    mode = _strict_mode(explicit_mode, "--mode") if explicit_mode else _persisted_mode(source)
    block = BANNER + "\n" + _render_mode(source, mode)
    current = _read(target_path)
    # A markerless table is replaceable only when it is byte-shape-equivalent
    # to the historical stock PDG schema.  This is a one-way migration gate;
    # --remove never gains ownership from that inference.
    removed, first_hit = _remove_owned(current, target_path, allow_legacy=True)
    keep = removed.split("\n")
    _check_flush(keep, target_path)
    if first_hit is None:
        while keep and not keep[-1].strip():
            keep.pop()
        merged = "\n".join(keep) + ("\n\n" if keep else "") + block
    else:
        head, tail = keep[:first_hit], keep[first_hit:]
        while head and not head[-1].strip():
            head.pop()
        while tail and not tail[0].strip():
            tail.pop(0)
        merged = "\n".join(
            head + ([""] if head else []) + block.split("\n")
            + ([""] if tail else []) + tail
        )
    _write(output_path, merged)


def _remove(target_path, output_path):
    current = _read(target_path)
    result, _first_hit = _remove_owned(current, target_path)
    _write(output_path, result.rstrip("\n"))


def main(argv):
    args = list(argv[1:])
    explicit_mode = ""
    if "--mode" in args:
        pos = args.index("--mode")
        if pos + 1 >= len(args):
            raise MergeError("--mode 缺少值")
        explicit_mode = args[pos + 1]
        del args[pos:pos + 2]
    if args and args[0] == "--remove":
        if explicit_mode or len(args) != 3:
            raise MergeError("用法: nftmerge.py --remove <target> <output>")
        _remove(args[1], args[2])
        return 0
    if len(args) != 3:
        raise MergeError(
            "用法: nftmerge.py [--mode managed|external] <block> <target> <output>")
    _replace(args[0], args[1], args[2], explicit_mode)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except MergeError as error:
        print(str(error), file=sys.stderr)
        sys.exit(error.code)
    except OSError as error:
        print("nftables 配置读写失败: %s" % error, file=sys.stderr)
        sys.exit(1)
