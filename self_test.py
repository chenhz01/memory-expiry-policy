# -*- coding: utf-8 -*-
"""self_test for memory-expiry-policy (scaffold v2, four defenses inherited).

D1: SystemExit/BaseException caught in run_cli (argparse exits never escape).
D2: Unicode-safe: fixtures contain CJK/accented ids; regexes are \\w-based, not ASCII.
D3: All fixtures written with newline="" (Windows CRLF double-write safe).
D4: Last line is always "SUMMARY: PASS n/n".
"""
import contextlib
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import time
import unittest

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")  # D3

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "core", os.path.join(_HERE, "memory_expiry_policy.py"))
core = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(core)
main = core.main
SpecError = core.SpecError


def run_cli(argv):
    """D1: capture SystemExit + Exception; return (code, stdout, stderr)."""
    buf_out, buf_err = io.StringIO(), io.StringIO()
    code = 0
    try:
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            ret = main(argv)
            code = 0 if ret is None else int(ret)
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    except Exception as e:
        code = 1
        buf_err.write(repr(e))
    return code, buf_out.getvalue(), buf_err.getvalue()


CASES = []


def case(category, name):
    def deco(fn):
        CASES.append((category, name, fn))
        return fn
    return deco


_TMP = tempfile.mkdtemp(prefix="mep_selftest_")


def write_fixture(name, text):
    p = os.path.join(_TMP, name)
    with open(p, "w", encoding="utf-8", newline="") as f:  # D3
        f.write(text)
    return p


def jdump(obj):
    return json.dumps(obj, ensure_ascii=False, indent=2)


GOOD_POLICY = {
    "version": 1, "default_ttl": "30d", "fallback_on_expiry": "soft_delete",
    "rules": [
        {"id": "r1", "match": {"kind": "secret"}, "ttl": "1h", "on_expiry": "hard_delete"},
        {"id": "r2", "match": {"kind": "summary"}, "ttl": "7d", "on_expiry": "demote"}],
    "audit": {"retention": "365d"}}
NOW = "2026-10-13T00:00:00Z"
OLD = "2026-09-01T00:00:00Z"      # ~42 days before NOW
RECENT = "2026-10-12T00:00:00Z"   # 1 day before NOW

# ---------- [A] functional ----------
for _s, _v in [("0s", 0), ("45m", 2700), ("12h", 43200), ("30d", 2592000),
               ("2w", 1209600), ("never", None)]:
    def _mk(_s=_s, _v=_v):
        def t():
            assert core.parse_duration(_s) == _v
        return t
    case("A", "parse_duration valid %s" % _s)(_mk())

def _t_min_policy():
    p = {"version": 1, "default_ttl": "30d", "fallback_on_expiry": "soft_delete", "rules": []}
    assert core.validate_policy(p) == []
case("A", "validate minimal good policy")(_t_min_policy)

def _t_full_policy():
    assert core.validate_policy(GOOD_POLICY) == []
case("A", "validate full good policy")(_t_full_policy)

def _t_first_match():
    rec = {"id": "x", "created_at": OLD, "kind": "secret", "namespace": "summary"}
    acts, _ = core.plan_expiry([rec], GOOD_POLICY, NOW)
    assert acts[0]["action"] == "hard_delete" and "r1" in acts[0]["source"]
case("A", "plan first-match-wins")(_t_first_match)

def _t_fallback():
    rec = {"id": "n1", "created_at": OLD, "kind": "note"}
    acts, _ = core.plan_expiry([rec], GOOD_POLICY, NOW)
    assert acts[0]["action"] == "soft_delete" and acts[0]["source"] == "default"
case("A", "plan fallback when no rule matches")(_t_fallback)

def _t_demote():
    rec = {"id": "s1", "created_at": OLD, "kind": "summary"}
    acts, _ = core.plan_expiry([rec], GOOD_POLICY, NOW)
    assert acts[0]["action"] == "demote"
case("A", "plan expired summary -> demote")(_t_demote)

def _t_keep():
    rec = {"id": "k1", "created_at": RECENT, "kind": "note"}
    acts, audit = core.plan_expiry([rec], GOOD_POLICY, NOW)
    assert acts[0]["action"] == "keep" and audit == []
case("A", "plan keep when not expired")(_t_keep)

def _t_zero_ttl():
    rec = {"id": "z", "created_at": NOW, "kind": "note"}
    p = dict(GOOD_POLICY, default_ttl="0s")
    acts, _ = core.plan_expiry([rec], p, NOW)
    assert acts[0]["action"] == "soft_delete"
case("A", "ttl 0s expires immediately")(_t_zero_ttl)

def _t_never():
    rec = {"id": "nv", "created_at": "1999-01-01T00:00:00Z", "kind": "note"}
    p = dict(GOOD_POLICY, default_ttl="never")
    acts, _ = core.plan_expiry([rec], p, NOW)
    assert acts[0]["action"] == "keep"
case("A", "ttl never keeps forever")(_t_never)

def _t_apply():
    store = [{"id": "a", "created_at": OLD, "kind": "secret"},
             {"id": "b", "created_at": OLD, "kind": "summary"},
             {"id": "c", "created_at": OLD, "kind": "note"},
             {"id": "d", "created_at": RECENT, "kind": "note"}]
    out, rep = core.apply_expiry(store, GOOD_POLICY, NOW)
    ids = [r["id"] for r in out]
    assert "a" not in ids and out[ids.index("b")]["demoted"] is True
    assert out[ids.index("c")]["expired"] is True and "d" in ids
case("A", "apply_expiry drop/flag/demote")(_t_apply)

def _t_no_mutation():
    store = [{"id": "a", "created_at": OLD, "kind": "summary"}]
    _ = core.apply_expiry(store, GOOD_POLICY, NOW)
    assert "demoted" not in store[0]
case("A", "apply_expiry does not mutate input")(_t_no_mutation)

def _t_audit_count():
    store = [{"id": "a", "created_at": OLD, "kind": "secret"},
             {"id": "b", "created_at": RECENT, "kind": "note"}]
    _, rep = core.apply_expiry(store, GOOD_POLICY, NOW)
    assert len(rep["audit"]) == 1 and rep["audit"][0]["id"] == "a"
case("A", "audit length equals expired count")(_t_audit_count)

def _t_audit_source():
    _, rep = core.apply_expiry([{"id": "a", "created_at": OLD, "kind": "summary"}],
                               GOOD_POLICY, NOW)
    assert rep["audit"][0]["source"] == "rule:id=r2"
case("A", "audit carries rule id source")(_t_audit_source)

def _t_unicode_match():
    p = {"version": 1, "default_ttl": "1d", "fallback_on_expiry": "soft_delete",
         "rules": [{"id": "u1", "match": {"namespace": "记忆"}, "ttl": "0s",
                    "on_expiry": "hard_delete"}]}
    rec = {"id": "u-记忆-α", "created_at": "2020-01-01T00:00:00Z", "namespace": "记忆"}
    acts, _ = core.plan_expiry([rec], p, NOW)
    assert acts[0]["action"] == "hard_delete"
case("A", "unicode namespace matching")(_t_unicode_match)

def _t_cli_validate_ok():
    p = write_fixture("good_policy.json", jdump(GOOD_POLICY))
    code, out, _ = run_cli(["validate", p])
    assert code == 0 and "OK" in out
case("A", "CLI validate good -> 0")(_t_cli_validate_ok)

def _t_cli_validate_json():
    p = write_fixture("good_policy.json", jdump(GOOD_POLICY))
    code, out, _ = run_cli(["validate", p, "--json"])
    assert code == 0 and json.loads(out)["errors"] == []
case("A", "CLI validate --json parses")(_t_cli_validate_json)

def _t_cli_validate_bad():
    p = write_fixture("bad_policy.json", jdump({"version": 2}))
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R2" in out
case("A", "CLI validate bad -> 1")(_t_cli_validate_bad)

def _t_cli_simulate():
    sp = write_fixture("s_policy.json", jdump(GOOD_POLICY))
    st = write_fixture("s_store.json", jdump([{"id": "a", "created_at": OLD, "kind": "secret"}]))
    code, out, _ = run_cli(["simulate", st, sp, "--now", NOW])
    assert code == 0 and "hard_delete" in out
case("A", "CLI simulate good -> 0")(_t_cli_simulate)

def _t_cli_simulate_json():
    sp = write_fixture("s_policy.json", jdump(GOOD_POLICY))
    st = write_fixture("s_store.json", jdump([{"id": "a", "created_at": OLD, "kind": "note"}]))
    code, out, _ = run_cli(["simulate", st, sp, "--now", NOW, "--json"])
    assert code == 0
    parsed = json.loads(out)
    assert parsed["report"]["actions"][0]["action"] == "soft_delete"
case("A", "CLI simulate --json round-trip")(_t_cli_simulate_json)

def _t_rule_source_noid():
    p = {"version": 1, "default_ttl": "0s", "fallback_on_expiry": "demote",
         "rules": [{"match": {"kind": "x"}, "ttl": "0s", "on_expiry": "demote"}]}
    acts, _ = core.plan_expiry([{"id": "a", "created_at": "2020-01-01", "kind": "x"}], p, NOW)
    assert acts[0]["source"] == "rule"
case("A", "rule without id -> source 'rule'")(_t_rule_source_noid)

# ---------- [B] exception paths ----------
for _s in ["", "d", "30x", "-5d", "1.5h", None]:
    def _mk(_s=_s):
        def t():
            try:
                core.parse_duration(_s)
            except SpecError:
                return
            raise AssertionError("expected SpecError for %r" % (_s,))
        return t
    case("B", "parse_duration rejects %r" % (_s,))(_mk())

for _s in ["not-a-date", "2026-13-40", ["x"]]:
    def _mk(_s=_s):
        def t():
            try:
                core.parse_ts(_s)
            except SpecError:
                return
            raise AssertionError("expected SpecError for %r" % (_s,))
        return t
    case("B", "parse_ts rejects %r" % (_s,))(_mk())

def _t_non_dict():
    assert core.validate_policy([1, 2])[0]["rule"] == "R1"
case("B", "validate non-dict -> R1")(_t_non_dict)

def _t_version():
    assert core.validate_policy({"version": 2})[0]["rule"] == "R2"
case("B", "wrong version -> R2")(_t_version)

def _t_bad_ttl():
    p = dict(GOOD_POLICY, default_ttl="abc")
    assert core.validate_policy(p)[0]["rule"] == "R3"
case("B", "bad default_ttl -> R3")(_t_bad_ttl)

def _t_bad_fallback():
    p = dict(GOOD_POLICY, fallback_on_expiry="explode")
    assert core.validate_policy(p)[0]["rule"] == "R4"
case("B", "bad fallback verb -> R4")(_t_bad_fallback)

def _t_rules_not_list():
    p = dict(GOOD_POLICY, rules="nope")
    assert core.validate_policy(p)[0]["rule"] == "R5"
case("B", "rules not a list -> R5")(_t_rules_not_list)

def _t_empty_match():
    p = dict(GOOD_POLICY, rules=[{"match": {}, "ttl": "1d", "on_expiry": "demote"}])
    assert any(e["rule"] == "R6" for e in core.validate_policy(p))
case("B", "empty match -> R6")(_t_empty_match)

def _t_rule_bad_ttl():
    p = dict(GOOD_POLICY, rules=[{"match": {"k": 1}, "ttl": "5q", "on_expiry": "demote"}])
    assert any(e["rule"] == "R7" for e in core.validate_policy(p))
case("B", "rule bad ttl -> R7")(_t_rule_bad_ttl)

def _t_rule_bad_verb():
    p = dict(GOOD_POLICY, rules=[{"match": {"k": 1}, "ttl": "1d", "on_expiry": "delete"}])
    assert any(e["rule"] == "R8" for e in core.validate_policy(p))
case("B", "rule bad on_expiry -> R8")(_t_rule_bad_verb)

def _t_dup_ids():
    p = dict(GOOD_POLICY, rules=[
        {"id": "d", "match": {"k": 1}, "ttl": "1d", "on_expiry": "demote"},
        {"id": "d", "match": {"k": 2}, "ttl": "1d", "on_expiry": "demote"}])
    assert any(e["rule"] == "R9" for e in core.validate_policy(p))
case("B", "duplicate rule ids -> R9")(_t_dup_ids)

def _t_bad_audit():
    p = dict(GOOD_POLICY, audit={"retention": "3z"})
    assert any(e["rule"] == "R10" for e in core.validate_policy(p))
case("B", "bad audit retention -> R10")(_t_bad_audit)

def _t_skip_no_created():
    acts, _ = core.plan_expiry([{"id": "x"}], GOOD_POLICY, NOW)
    assert acts[0]["action"] == "skip"
case("B", "record without created_at -> skip")(_t_skip_no_created)

def _t_no_args():
    code, _, err = run_cli([])
    assert code == 2, (code, err)
case("B", "CLI no args -> SystemExit 2 (D1)")(_t_no_args)

def _t_unknown_cmd():
    code, _, _ = run_cli(["frobnicate"])
    assert code == 2
case("B", "CLI unknown subcommand -> 2")(_t_unknown_cmd)

# ---------- [C] extreme edges ----------
def _t_empty_store():
    acts, audit = core.plan_expiry([], GOOD_POLICY, NOW)
    assert acts == [] and audit == []
case("C", "empty store -> zero actions")(_t_empty_store)

def _t_no_rules():
    p = {"version": 1, "default_ttl": "1d", "fallback_on_expiry": "demote"}
    acts, _ = core.plan_expiry([{"id": "a", "created_at": "2020-01-01", "kind": "?"}], p, NOW)
    assert acts[0]["action"] == "demote" and acts[0]["source"] == "default"
case("C", "empty rules -> all default")(_t_no_rules)

def _t_unicode_roundtrip():
    sp = write_fixture("u_policy.json", jdump(GOOD_POLICY))
    st = write_fixture("u_store.json",
                       jdump([{"id": "记忆-α-🏷", "created_at": OLD, "kind": "note"}]))
    code, out, _ = run_cli(["simulate", st, sp, "--now", NOW, "--json"])
    assert code == 0
    assert json.loads(out)["result"][0]["id"] == "记忆-α-🏷"
case("C", "unicode id round-trips through CLI --json")(_t_unicode_roundtrip)

def _t_crlf():
    sp = write_fixture("c_policy.json", jdump(GOOD_POLICY))
    st = write_fixture("c_store.json",
                       jdump([{"id": "crlf", "created_at": OLD, "kind": "note"}]) + "\r\n")
    code, _, _ = run_cli(["simulate", st, sp, "--now", NOW, "--json"])
    assert code == 0
case("C", "CRLF-terminated store fixture parses (D3)")(_t_crlf)

def _t_long_id():
    long_id = "id" * 5000
    rec = {"id": long_id, "created_at": OLD, "kind": "note"}
    acts, _ = core.plan_expiry([rec], GOOD_POLICY, NOW)
    assert acts[0]["id"] == long_id
case("C", "10k-char record id works")(_t_long_id)

def _t_huge_ttl():
    p = dict(GOOD_POLICY, default_ttl="999999w")
    acts, _ = core.plan_expiry([{"id": "h", "created_at": "1970-01-01", "kind": "note"}],
                               p, NOW)
    assert acts[0]["action"] == "keep"
case("C", "huge ttl keeps record")(_t_huge_ttl)

def _t_epoch_now():
    now_epoch = core.parse_ts(NOW)
    acts, _ = core.plan_expiry([{"id": "e", "created_at": OLD, "kind": "secret"}],
                               GOOD_POLICY, now_epoch)
    assert acts[0]["action"] == "hard_delete"
case("C", "now as epoch number")(_t_epoch_now)

def _t_epoch_created():
    rec = {"id": "e2", "created_at": 0, "kind": "secret"}
    acts, _ = core.plan_expiry([rec], GOOD_POLICY, NOW)
    assert acts[0]["action"] == "hard_delete"
case("C", "created_at as epoch number")(_t_epoch_created)

def _t_tz_offset():
    rec = {"id": "tz", "created_at": "2026-09-01T08:00:00+08:00", "kind": "secret"}
    acts, _ = core.plan_expiry([rec], GOOD_POLICY, NOW)
    assert acts[0]["action"] == "hard_delete"
case("C", "timestamp with +08:00 offset")(_t_tz_offset)

def _t_space_ts():
    rec = {"id": "sp", "created_at": "2026-09-01 00:00:00", "kind": "secret"}
    acts, _ = core.plan_expiry([rec], GOOD_POLICY, NOW)
    assert acts[0]["action"] == "hard_delete"
case("C", "timestamp with space separator")(_t_space_ts)

def _t_dup_ids_store():
    store = [{"id": "same", "created_at": OLD, "kind": "note"},
             {"id": "same", "created_at": RECENT, "kind": "note"}]
    out, _ = core.apply_expiry(store, GOOD_POLICY, NOW)
    assert len(out) == 2 and out[0]["expired"] is True and "expired" not in out[1]
case("C", "duplicate store ids processed independently")(_t_dup_ids_store)

def _t_missing_now():
    sp = write_fixture("n_policy.json", jdump(GOOD_POLICY))
    st = write_fixture("n_store.json", jdump([]))
    code, _, _ = run_cli(["simulate", st, sp])
    assert code == 2
case("C", "CLI simulate missing --now -> 2")(_t_missing_now)

def _t_unknown_keys():
    p = dict(GOOD_POLICY, future_hint="reserved-for-v2")
    assert core.validate_policy(p) == []
case("C", "unknown top-level keys tolerated")(_t_unknown_keys)

def _t_multikey_match():
    p = {"version": 1, "default_ttl": "1d", "fallback_on_expiry": "demote",
         "rules": [{"match": {"kind": "a", "namespace": "b"}, "ttl": "0s",
                    "on_expiry": "hard_delete"}]}
    acts, _ = core.plan_expiry(
        [{"id": "m1", "created_at": "2020-01-01", "kind": "a", "namespace": "x"},
         {"id": "m2", "created_at": "2020-01-01", "kind": "a", "namespace": "b"}], p, NOW)
    assert acts[0]["action"] == "demote" and acts[1]["action"] == "hard_delete"
case("C", "multi-key match requires all keys")(_t_multikey_match)

def _t_non_dict_entry():
    acts, _ = core.plan_expiry(["garbage", 42, None], GOOD_POLICY, NOW)
    assert all(a["action"] == "skip" for a in acts)
case("C", "non-dict store entries -> skip, no crash")(_t_non_dict_entry)

def _t_idempotent_flags():
    store = [{"id": "i", "created_at": OLD, "kind": "note"}]
    out1, _ = core.apply_expiry(store, GOOD_POLICY, NOW)
    out2, _ = core.apply_expiry(out1, GOOD_POLICY, NOW)
    assert out2[0]["expired"] is True and list(out2[0].keys()).count("expired") == 1
case("C", "double apply keeps flags idempotent")(_t_idempotent_flags)

def _t_perf_sane():
    recs = [{"id": "p%05d" % i, "created_at": "2020-01-01T00:00:00Z",
             "kind": "note"} for i in range(5000)]
    t0 = time.perf_counter()
    core.apply_expiry(recs, GOOD_POLICY, NOW)
    assert time.perf_counter() - t0 < 5.0
case("C", "5k-record simulate under 5s")(_t_perf_sane)

def _t_meta_count():
    assert len(CASES) >= 60
case("C", "meta: at least 60 cases defined")(_t_meta_count)


class T(unittest.TestCase):
    pass


def _add(i, cat, name, fn):
    def t(self, _f=fn):
        _f()
    t.__doc__ = "%s: %s" % (cat, name)
    setattr(T, "test_%s_%03d_%s" % (cat, i, re.sub(r"[^0-9A-Za-z_]", "_", name)), t)


for _i, (_c, _n, _f) in enumerate(CASES):
    _add(_i + 1, _c, _n, _f)

if __name__ == "__main__":
    r = unittest.TextTestRunner(verbosity=0).run(
        unittest.defaultTestLoader.loadTestsFromModule(sys.modules["__main__"]))
    total, fails = r.testsRun, len(r.failures) + len(r.errors)
    print("SUMMARY: PASS %d/%d" % (total - fails, total))  # D4
    sys.exit(0 if fails == 0 else 1)
