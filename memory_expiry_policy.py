# -*- coding: utf-8 -*-
"""memory-expiry-policy: TTL declaration + expiry semantics (soft-delete / hard-delete / demote) + purge audit.

Pure standard library. CLI via argparse.
Exit codes: 0 ok, 1 validation/analysis failure, 2 usage error (argparse).
"""
import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone

VERBS = ("soft_delete", "hard_delete", "demote")
DUR_RE = re.compile(r"^(\d+)([smhdw])$")
UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
TS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?)?$"
)
IDENT_RE = re.compile(r"^[^\W\d][\w-]*$", re.UNICODE)  # D2: unicode-aware identifier


class SpecError(Exception):
    """Raised for malformed durations / timestamps."""


def parse_duration(s):
    """Parse '<n><s|m|h|d|w>' into seconds, or 'never' -> None."""
    if s == "never":
        return None
    if not isinstance(s, str):
        raise SpecError("duration must be a string, got %r" % (s,))
    m = DUR_RE.match(s)
    if not m:
        raise SpecError("bad duration %r, want '<n><s|m|h|d|w>' or 'never'" % (s,))
    return int(m.group(1)) * UNITS[m.group(2)]


def parse_ts(s):
    """Parse ISO-8601 string (or epoch number) into epoch seconds."""
    if isinstance(s, (int, float)) and not isinstance(s, bool):
        return float(s)
    if not isinstance(s, str):
        raise SpecError("timestamp must be ISO-8601 string or epoch number, got %r" % (s,))
    t = s.strip()
    if TS_RE.match(t):
        t2 = t.replace(" ", "T")
        if t2.endswith("Z"):
            t2 = t2[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(t2)
        except ValueError:
            raise SpecError("bad timestamp %r" % (s,))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    try:
        return float(t)
    except ValueError:
        raise SpecError("bad timestamp %r" % (s,))


def validate_policy(p):
    """Validate a policy dict. Returns list of {rule, path, message}; empty = valid."""
    errs = []

    def err(rule, path, msg):
        errs.append({"rule": rule, "path": path, "message": msg})

    if not isinstance(p, dict):
        err("R1", "$", "policy must be a JSON object")
        return errs
    if p.get("version") != 1:
        err("R2", "$.version", "version must be 1")
    if "default_ttl" not in p:
        err("R3", "$.default_ttl", "missing default_ttl")
    else:
        try:
            parse_duration(p["default_ttl"])
        except SpecError as e:
            err("R3", "$.default_ttl", str(e))
    if p.get("fallback_on_expiry") not in VERBS:
        err("R4", "$.fallback_on_expiry", "must be one of %s" % (", ".join(VERBS),))
    rules = p.get("rules")
    if not isinstance(rules, list):
        err("R5", "$.rules", "rules must be an array")
    else:
        seen_ids = set()
        for i, r in enumerate(rules):
            path = "$.rules[%d]" % i
            if not isinstance(r, dict):
                err("R5", path, "rule must be an object")
                continue
            match = r.get("match")
            if not isinstance(match, dict) or not match:
                err("R6", path + ".match", "match must be a non-empty object")
            else:
                for k in match:
                    if not IDENT_RE.match(k):
                        err("R6", path + ".match", "match key %r must be an identifier" % (k,))
            if "ttl" in r:
                try:
                    parse_duration(r["ttl"])
                except SpecError as e:
                    err("R7", path + ".ttl", str(e))
            if r.get("on_expiry") not in VERBS:
                err("R8", path + ".on_expiry", "must be one of %s" % (", ".join(VERBS),))
            if "id" in r:
                rid = r["id"]
                if not isinstance(rid, str) or not rid:
                    err("R9", path + ".id", "id must be a non-empty string")
                elif rid in seen_ids:
                    err("R9", path + ".id", "duplicate rule id %r" % rid)
                else:
                    seen_ids.add(rid)
    audit = p.get("audit")
    if audit is not None:
        if not isinstance(audit, dict):
            err("R10", "$.audit", "audit must be an object")
        elif "retention" in audit:
            try:
                parse_duration(audit["retention"])
            except SpecError as e:
                err("R10", "$.audit.retention", str(e))
    return errs


def _match(rule, rec):
    return all(rec.get(k) == v for k, v in rule.get("match", {}).items())


def plan_expiry(records, policy, now):
    """Compute per-record expiry actions.

    Returns (actions, audit). First matching rule wins; unmatched records use
    default_ttl + fallback_on_expiry. Audit records every non-keep decision.
    """
    now_ts = parse_ts(now)
    actions, audit = [], []
    for rec in records:
        if not isinstance(rec, dict) or "id" not in rec or "created_at" not in rec:
            actions.append({"id": None, "action": "skip", "source": None,
                            "reason": "record missing id/created_at"})
            continue
        rule = None
        for r in policy.get("rules", []):
            if _match(r, rec):
                rule = r
                break
        if rule is not None:
            ttl = rule.get("ttl", policy.get("default_ttl", "never"))
            verb = rule.get("on_expiry", policy.get("fallback_on_expiry"))
            source = "rule" + (":id=" + rule["id"] if "id" in rule else "")
        else:
            ttl = policy.get("default_ttl", "never")
            verb = policy.get("fallback_on_expiry")
            source = "default"
        try:
            ttl_secs = parse_duration(ttl)
        except SpecError:
            ttl_secs = None
        try:
            created = parse_ts(rec["created_at"])
        except SpecError:
            actions.append({"id": rec.get("id"), "action": "skip", "source": source,
                            "reason": "bad created_at"})
            continue
        expired = ttl_secs is not None and (created + ttl_secs <= now_ts)
        action = verb if expired else "keep"
        actions.append({"id": rec["id"], "action": action, "source": source})
        if expired:
            audit.append({"ts": now, "id": rec["id"], "action": verb, "source": source})
    return actions, audit


def apply_expiry(records, policy, now):
    """Return (new_store, report). Original store is never mutated.
    Records are processed positionally, so duplicate ids stay independent."""
    actions, audit = plan_expiry(records, policy, now)
    out = []
    for rec, act in zip(records, actions):
        action = act["action"]
        if action == "skip":
            out.append(rec)
            continue
        if action == "hard_delete":
            continue
        rec2 = dict(rec)
        if action == "demote":
            rec2["demoted"] = True
        elif action == "soft_delete":
            rec2["expired"] = True
        out.append(rec2)
    return out, {"actions": actions, "audit": audit}


def _load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def cmd_validate(args):
    errs = validate_policy(_load(args.policy))
    if args.json:
        print(json.dumps({"errors": errs}, ensure_ascii=False, indent=2))
    else:
        for e in errs:
            print("%s %s: %s" % (e["rule"], e["path"], e["message"]))
        print("OK" if not errs else "%d error(s)" % len(errs))
    return 1 if errs else 0


def cmd_simulate(args):
    errs = validate_policy(_load(args.policy))
    if errs:
        for e in errs:
            print("%s %s: %s" % (e["rule"], e["path"], e["message"]), file=sys.stderr)
        return 1
    store = _load(args.store)
    out, report = apply_expiry(store, _load(args.policy), args.now)
    if args.json:
        print(json.dumps({"result": out, "report": report}, ensure_ascii=False, indent=2))
    else:
        for a in report["actions"]:
            print("%s -> %s (%s)" % (a.get("id"), a["action"], a.get("source") or ""))
        kept = sum(1 for a in report["actions"] if a["action"] == "keep")
        print("kept=%d audit=%d" % (kept, len(report["audit"])))
    return 0


def cmd_bench(args):
    import random
    rnd = random.Random(42)
    policy = {"version": 1, "default_ttl": "30d", "fallback_on_expiry": "soft_delete",
              "rules": [
                  {"id": "r1", "match": {"kind": "secret"}, "ttl": "1h", "on_expiry": "hard_delete"},
                  {"id": "r2", "match": {"kind": "summary"}, "ttl": "7d", "on_expiry": "demote"}],
              "audit": {"retention": "365d"}}
    now = time.time()
    recs = [{"id": "m%06d" % i, "created_at": now - rnd.random() * 100 * 86400,
             "namespace": rnd.choice(["episodes", "session", "docs"]),
             "kind": rnd.choice(["note", "secret", "summary"])}
            for i in range(args.records)]
    t0 = time.perf_counter()
    out, rep = apply_expiry(recs, policy, now)
    dt = time.perf_counter() - t0
    rate = args.records / dt if dt > 0 else 0
    print("bench: %d records in %.3fs (%.0f rec/s)" % (args.records, dt, rate))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="memory-expiry-policy",
        description="Agent memory expiry policy: TTL declaration, expiry semantics "
                    "(soft-delete / hard-delete / demote), purge audit.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="validate a policy JSON file")
    v.add_argument("policy")
    v.add_argument("--json", action="store_true")
    v.set_defaults(fn=cmd_validate)
    s = sub.add_parser("simulate", help="apply a policy to a memory-store JSON file")
    s.add_argument("store")
    s.add_argument("policy")
    s.add_argument("--now", required=True, help="evaluation time (ISO-8601 or epoch)")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_simulate)
    b = sub.add_parser("bench", help="synthetic benchmark")
    b.add_argument("--records", type=int, default=10000)
    b.set_defaults(fn=cmd_bench)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
