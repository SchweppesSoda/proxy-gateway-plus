#!/usr/bin/env python3
"""真实 pdgtx 服务 guard：锁内前置状态、零写入拒绝、CLI metadata round-trip。"""
import contextlib
import importlib.util
import io
import json
import os
import tempfile
from types import SimpleNamespace


def load_tx(root):
    os.environ["PDG_TX_FSROOT"] = root
    os.environ["PDG_TX_ROOT"] = root + "/var/lib/privdns-gateway/tx"
    os.environ["PDG_LOCKFILE"] = root + "/run/pdg.lock"
    path = os.path.join(os.path.dirname(__file__), "..", "deploy", "bot", "pdgtx.py")
    spec = importlib.util.spec_from_file_location("pdgtx_guard_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    with tempfile.TemporaryDirectory() as root:
        os.makedirs(root + "/etc/mosdns/rules", exist_ok=True)
        os.makedirs(root + "/run", exist_ok=True)
        tx = load_tx(root)
        runtime = {"state": "inactive", "query_ok": True}

        def prop(_unit, name):
            if name == "ActiveState":
                return (runtime["state"], runtime["query_ok"])
            if name == "UnitFileState":
                return ("disabled", True)
            if name == "NRestarts":
                return ("0", True)
            return ("", False)

        tx._svc_prop_ex = prop
        tx._svc_active = lambda _u: runtime["state"] == "active"
        tx.svc_stable = lambda _u: (
            runtime["state"] == "active", "service is not active")
        tx.health_snapshot = lambda services, relax_units=(): {
            "svc:" + u: runtime["state"] == "active"
            for u in services if u not in relax_units
        }

        # Direct API: exact inactive succeeds on a repair baseline and writes atomically.
        t = tx.Tx("installer", "guard-ok", mode="repair")
        t.stage("mosdns_rule:geosite_cn.txt", b"domain:cn.example\n")
        t.guard_service("mosdns", "inactive")
        result = t.commit()
        target = root + "/etc/mosdns/rules/geosite_cn.txt"
        assert result["state"] == tx.COMMITTED
        assert open(target, "rb").read() == b"domain:cn.example\n"

        # Active mismatch: terminal PRECONDITION_FAILED before production bytes move.
        before = open(target, "rb").read()
        runtime["state"] = "active"
        t = tx.Tx("installer", "guard-active", mode="repair")
        t.stage("mosdns_rule:geosite_cn.txt", b"domain:must-not-land.example\n")
        t.guard_service("mosdns", "inactive")
        try:
            t.commit()
            raise AssertionError("active guard mismatch unexpectedly committed")
        except tx.TxRefused:
            pass
        meta = tx.load_meta(t.dir)
        assert meta["state"] == tx.ABORTED
        assert meta["error_class"] == "PRECONDITION_FAILED"
        assert open(target, "rb").read() == before
        assert not tx.pending_recovery()

        # Query failure has the same fail-closed, zero-write semantics.
        runtime.update(state="inactive", query_ok=False)
        t = tx.Tx("installer", "guard-query-fail", mode="repair")
        t.stage("mosdns_rule:geosite_cn.txt", b"domain:query-fail.example\n")
        t.guard_service("mosdns", "inactive")
        try:
            t.commit()
            raise AssertionError("unprovable guard unexpectedly committed")
        except tx.TxRefused:
            pass
        meta = tx.load_meta(t.dir)
        assert meta["state"] == tx.ABORTED
        assert meta["error_class"] == "PRECONDITION_FAILED"
        assert open(target, "rb").read() == before
        assert not tx.pending_recovery()

        # CLI path persists staged_service_guards, reconstructs all Tx attributes and
        # really commits while the guard remains inactive.
        runtime.update(state="inactive", query_ok=True)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            assert tx._cli_new(SimpleNamespace(
                source="installer", op="cli-guard", mode="repair")) == 0
        txid = out.getvalue().strip()
        candidate = root + "/candidate.txt"
        cli_bytes = b"domain:cli-landed.example\n"
        with open(candidate, "wb") as f:
            f.write(cli_bytes)
        assert tx._cli_stage(SimpleNamespace(
            tx=txid, target="mosdns_rule:geosite_cn.txt", file=candidate,
            delete=False, expect=None)) == 0
        assert tx._cli_guard(SimpleNamespace(
            tx=txid, unit="mosdns", expect="inactive")) == 0
        staged = tx.load_meta(os.path.join(tx.TX_ROOT, txid))
        assert staged["staged_service_guards"]["mosdns"]["expect"] == "inactive"
        staged["watched"] = {
            "rs_meta": {"sha256": None, "absent": True, "optional": True}}
        tx.atomic_write(
            os.path.join(tx.TX_ROOT, txid, "meta.json"),
            json.dumps(staged).encode(), 0o600)
        assert tx._cli_apply(SimpleNamespace(
            tx=txid, allow_runner_drift=False)) == 0
        assert open(target, "rb").read() == cli_bytes
        meta = tx.load_meta(os.path.join(tx.TX_ROOT, txid))
        assert meta["state"] == tx.COMMITTED
        assert not tx.pending_recovery()

        # A second CLI transaction proves active mismatch still aborts before any write.
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            assert tx._cli_new(SimpleNamespace(
                source="installer", op="cli-guard-active", mode="repair")) == 0
        txid = out.getvalue().strip()
        with open(candidate, "wb") as f:
            f.write(b"domain:cli-must-not-land.example\n")
        assert tx._cli_stage(SimpleNamespace(
            tx=txid, target="mosdns_rule:geosite_cn.txt", file=candidate,
            delete=False, expect=None)) == 0
        assert tx._cli_guard(SimpleNamespace(
            tx=txid, unit="mosdns", expect="inactive")) == 0
        runtime["state"] = "active"
        assert tx._cli_apply(SimpleNamespace(
            tx=txid, allow_runner_drift=False)) == 5
        meta = tx.load_meta(os.path.join(tx.TX_ROOT, txid))
        assert meta["state"] == tx.ABORTED
        assert meta["error_class"] == "PRECONDITION_FAILED"
        assert open(target, "rb").read() == cli_bytes
        assert not tx.pending_recovery()

        # Old PREPARING metadata without guard/watch fields remains applicable. Also
        # cover current `watched` optional-absent reconstruction.
        runtime.update(state="inactive", query_ok=True)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            assert tx._cli_new(SimpleNamespace(
                source="legacy", op="cli-old-meta", mode="repair")) == 0
        txid = out.getvalue().strip()
        with open(candidate, "wb") as f:
            f.write(b"domain:old-meta-landed.example\n")
        assert tx._cli_stage(SimpleNamespace(
            tx=txid, target="mosdns_rule:geosite_cn.txt", file=candidate,
            delete=False, expect=None)) == 0
        old_meta_path = os.path.join(tx.TX_ROOT, txid, "meta.json")
        old_meta = tx.load_meta(os.path.join(tx.TX_ROOT, txid))
        old_meta.pop("staged_service_guards", None)
        old_meta.pop("service_guards", None)
        old_meta.pop("watched", None)
        old_meta.pop("staged_watches", None)
        tx.atomic_write(old_meta_path, json.dumps(old_meta).encode(), 0o600)
        assert tx._cli_apply(SimpleNamespace(
            tx=txid, allow_runner_drift=False)) == 0
        assert open(target, "rb").read() == b"domain:old-meta-landed.example\n"
        assert not tx.pending_recovery()

    print("[OK] pdgtx service guard real transaction and CLI round-trip")


if __name__ == "__main__":
    main()
