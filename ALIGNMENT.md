# ALIGNMENT — memory-expiry-policy

Round R14, rubric v4.0 (E/F graded). Local-only draft: no git remote, no push, no repo creation.
Date: 2026-10-13.

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 1 | Runnable Python, pure stdlib | PASS | memory_expiry_policy.py imports only argparse/json/re/sys/io/time/contextlib/datetime+importlib (self_test); `python memory_expiry_policy.py --help` runs |
| 2 | argparse CLI | PASS | subcommands per repo (validate/simulate|check|analyze|map/lint/bench) with `--json` where applicable; usage errors exit 2 |
| 3 | self_test inherits scaffold-v2 four defenses | PASS | D1 SystemExit caught in run_cli (tested); D2 unicode-aware regexes + CJK/emoji fixtures (tested); D3 fixtures written with newline="" (tested); D4 last line `SUMMARY: PASS n/n` |
| 4 | E gate >=60 cases, 3 categories | PASS | SUMMARY: PASS 65/65 — sections [A] functional / [B] exception / [C] extreme edge, incl. empty/oversized/unicode/CRLF inputs |
| 5 | SUMMARY last-line contract | PASS | `python self_test.py` prints `SUMMARY: PASS 65/65` as its final line; meta-case asserts len(CASES)>=60 |
| 6 | README English, <=60-word lead | PASS | README.md opening paragraph is 55-60 words, English |
| 7 | README Problem section | PASS | README.md '## Problem' |
| 8 | README How-it-works | PASS | README.md '## How it works' |
| 9 | README Quickstart with timing | PASS | README.md '## Quickstart' cites the [Measured] run time |
| 10 | why-not-X >=3 alternatives | PASS | README.md '## Why not X' lists 4 adjacent solutions; sim=none per _r14_design.json: WebSearch + 194 gh queries on 2026-10-12/13 surfaced only adjacent tooling (listed in README 'Why not X'); no direct equivalent found as of 2026-10-13. |
| 11 | Performance [Measured] + repro command | PASS | README.md '## Performance' table: 10,000-record store: 0.030s (332k rec/s) — `python memory_expiry_policy.py bench --records 10000` |
| 12 | Minimal Fallback | PASS | README.md '## Minimal Fallback' (grep/spreadsheet/manual equivalents) |
| 13 | Design Trade-offs | PASS | README.md '## Design Trade-offs' (4 entries) |
| 14 | Limits & Second-order Effects | PASS | README.md '## Limits & Second-order Effects' (4 entries) |
| 15 | FAQ incl When NOT to use | PASS | README.md '## FAQ' first item is 'When NOT to use this?' |
| 16 | Core Assumptions >=3 + confidence + as-of + hygiene | PASS | README.md '[Core Assumptions]' lists 4 assumptions with confidence line and 'As of 2026-10-13'; MIT LICENSE (zhengming contributors); CHANGELOG.md v0.1.0 -> v0.1.1; no secrets, no real names, contact limited to hcac4735@agent.qq.com |

Round-2 iterations (all repos): fixed run_cli to capture main() return codes (template gap);
rule-logic repairs per failing self-tests (see CHANGELOG v0.1.1); case counts raised to the
60-85 band; all suites re-run green before hand-off.
