# SDD ledger — plan: docs/superpowers/plans/2026-11-25-plan-1-foundation-core.md

Spec: docs/superpowers/specs/2026-11-25-soc-audidashboard-design.md
Branch: feat/plan-1-core (created from main @ aaaa8c3; same checkout, no worktree — fresh repo, nothing else in flight)
Env: uv 0.12.0, Python 3.14.7 local, pwsh NOT installed, Windows 11.

## Pre-flight scan

| Pair / task | Produces ↔ consumes | Finding / ruling |
|---|---|---|
| T1 self | .gitignore | Ruling: .gitignore must include `.superpowers/` (SDD workspace) — else scratch gets committed — cost: noise in repo |
| T2→T3 | Finding (frozen) → sanitize_finding returns new Finding | consistent (model_copy) |
| T2→T5 | Severity/Category/FindingStatus → ScoredFinding | consistent |
| T4→T6 | load_manifest/verify_integrity/compute_hashes, Execution | consistent |
| T6↔T7 | interpreter_argv python `-I entry` (T6) → bootstrap `-I -c BOOTSTRAP entry` (T7) | T7 explicitly amends T6; Ruling: T7 owns change and updates T6 test expectations if any |
| T6 self | RunInput.credentials SecretStr → stdin JSON | Ruling: `dict[str, SecretStr]`; runner serializes with get_secret_value only into stdin payload |
| T7 self | runner must locate SDK src while SDK must not import core | Ruling: audidash-core declares dependency on audidash-sdk (workspace); runner locates SDK dir via importlib.util.find_spec("audidash_sdk") — cost: small coupling |
| T4/T8→T9 | T9 says hashes via `audidash plugins hash` (T10, later) | Ruling: T9 uses compute_hashes directly; T10 later verifies with `plugins validate` |
| T8→T10 | load_catalog, Trust | consistent |
| T5→T10 | asset_score, band | consistent |
| T11 self | CI python version | Ruling: CI matrix python 3.12 + 3.13 on ubuntu/windows; local is 3.14 — cost: none |
| T6 self | PowerShell/bash interpreters | pwsh absent locally; tests use python plugins only; bash argv tested by interpreter_argv unit test only |
| T3,T5,T9,T10 self | tests vs code | consistent |

## Progress
Task 1: dispatched (base aaaa8c3, implementer a92db1fbf9840ae27, sonnet)
Task 1: complete (commits aaaa8c3..e3bde28, review clean)
Parked minors T1: mypy_path must add audidash-sdk src (Task 7); add !.env.example to .gitignore (Plan 2); README clone dir placeholder (Task 11)
Task 2: dispatched (base e3bde28, implementer a1f9f9a2063bda5f2, sonnet)
Parked: add .gitattributes eol=lf (Task 11)
Task 2: complete (commits e3bde28..6de5f6b, review clean; controller re-ran pytest+mypy for missing evidence)
Task 3: dispatched (base 6de5f6b, implementer ae6b593b667be630a, sonnet)
Task 3: review → Important: email regex quadratic (ReDoS) on large evidence
Task 3: Ruling: promote minor 'unterminated private key not redacted' to Important — spec anti-goal: secrets must never reach server — cost if wrong: tiny extra fix
Task 3: minor (deferred): password value stops at whitespace (document); \d matches Unicode digits (use [0-9]); weak shared loop in test_sanitizer.py:30; duplicate ip test
Task 3: Ruling: recommendation truncation to 2000 chars accepted — bounds work, no spec conflict — cost: long recommendations cut
Task 3: fix round 1/5 (2 addressed, 0 open; commits 7e69ef7..c72326d)
Task 3: complete (commits 6de5f6b..c72326d, review clean after 1 fix round)
Task 3: minor (deferred): public redact() unbounded on its own (JWT rule ~1.2s/MB) — Task 6 must cap stderr_tail to 4 KiB BEFORE redact
Task 4: dispatched (base c72326d, implementer acf2f280c66a4144c, sonnet)
Task 4: Ruling: tmp_path-built fixtures instead of static fixtures accepted — avoids CRLF hash drift — cost: none
Ruling: .gitattributes (* text=auto eol=lf; plugins/** -text or eol=lf) moves to Task 9 (before hashed plugins are committed) — CRLF checkout would break plugin hashes
Task 4: review → Important: load_manifest leaks UnicodeDecodeError/RecursionError; verify_integrity leaks raw OSError (TOCTOU)
Task 4: minor (deferred): path segment edge cases (a//b, ., CON); missing tests (inside-dir symlink, bad semver, empty yaml); unrelated test names; chunked hashing
Carry to Task 6: runner should copy verified bytes to temp dir and execute the copy (closes verify→execute TOCTOU; unlisted sibling files not available)
Task 4: fix round 1/5 (2 addressed, 0 open; commits 7272570..f2e8020)
Task 4: complete (commits c72326d..f2e8020, review clean after 1 fix round)
Task 4: minor (deferred): compute_hashes raises raw OSError (authoring helper)
Task 5: dispatched (base f2e8020, implementer ad1d5415d0064c0d8, sonnet)
Task 5: complete (commits f2e8020..83d9625, review clean)
Task 5: minor (deferred): pin band(24.999)==low; info weight 0 test; NaN guard in global_score
Task 6: dispatched (base 83d9625, implementer a1a853771706ecd1b, opus — security-critical integration)
Task 6: review → spec ❌/Important: run_local raises on crafted manifest (nested path FileExistsError, NUL ValueError); Important: leftover processes after normal exit (no killpg/Job object)
Task 6: Ruling: promote minor 'known credential values not scrubbed from output' to Important — spec anti-goal (secrets never leave) — cost: small
Task 6: Ruling: promote minor 'no kill on exception after spawn + unclosed pipes' into Important #2 (same code)
Task 6: Ruling: Windows Job object (ctypes, KILL_ON_JOB_CLOSE) required in this round — timeout bypass is a security gap — cost if wrong: extra ctypes code
Task 6: minor (deferred): weak env allowlist test; _payload RecursionError; venv site-packages visible to plugins (Task 7 bootstrap)
Task 6: Ruling: accept residual risks (Win Popen→job-assign window; POSIX setsid escape) — document as known limitations in SECURITY.md/docs in Task 11 — cost: rare escape of a malicious plugin child
Task 6: fix round 1/5 (3 addressed, 0 open; commits c48f92e..eae0560)
Task 6: complete (commits 83d9625..eae0560, review clean after 1 fix round)
Task 6: minor (deferred): stderr_tail should pre-scrub (scrub(redact(scrub))); credential with whitespace at tail cut; fallback path no warning when job object fails; POSIX killpg after reap PID reuse; target/references/item_key not credential-scrubbed
Task 7: dispatched (base eae0560, implementer a23db98187712dd71, sonnet)
Task 7: review → Important: sdk_parent_dir = site-packages under non-editable install (isolation broken)
Task 7: minor (deferred): _run_script lacks -S; sdk tests import core without dev dep note; missing SDK RuntimeError (covered by run_local safety net)
Task 7: fix round 1/5 (2 addressed, 0 open; commits f1c1fd0..ec75c5e)
Task 7: complete (commits eae0560..ec75c5e, review clean after 1 fix round)
Task 7: minor (deferred): interpreter_argv without sdk_dir inserts '' (cwd)
Task 8: Ruling: no real project key/index.sig/catalog.pub committed — maintainer (user) runs keygen offline before first release; until then plugins load as community — cost: confirmation prompts for own plugins in v0.1-alpha
Task 8: dispatched (base ec75c5e, implementer ab3f7f4eac817c7f1, sonnet)
Task 8: review → Important: non-ASCII index.sig raises ValueError from load_catalog; Important (plan-mandated): plugin.yaml not covered by signature
Task 8: Ruling: index entries add 'manifest' sha256 of plugin.yaml bytes, checked in official test; build_index rejects duplicate ids — spec: official = maintainer endorsement incl. permissions/runtime — cost: index shape differs from plan text
Task 8: Ruling: promote minors into round: sign tool fails loudly on integrity mismatch/skipped manifest; private key written O_EXCL 0o600; missing plugins dir → []
Task 8: minor (deferred): bad key path traceback in tool; set(verified_hashes) per plugin; redundant gitignore lines
Task 8: fix round 1/5 (3 addressed, 0 open; commits c67b796..2173a68)
Task 8: complete (commits ec75c5e..2173a68, review clean after 1 fix round)
Task 8: minor (deferred): keygen leaves private key if public write races; load_public_key raises on malformed catalog.pub — carry to Task 10: CLI treats missing/malformed catalog.pub as no key (warn)
Task 9: dispatched (base 2173a68, implementer aec1a01f1f6f65842, sonnet)
Task 9: Rulings: 4 HTTP findings over plain http accepted (HSTS https-only, matches brief); risky ports emit both IDs accepted (brief 'any open port'); tls run.py 210 lines accepted
Task 9: review → Important: ports [] default rejected; TLS hostname mismatch missed for unknown-CA leaf; port-scan unbounded time budget (loses results at runner timeout)
Task 9: minor (deferred): vacuous default-ports test; untested all-silent warning; TLS legacy probe unavailable gives silent clean; https://host:8443 port ignored; url host not tied to target; nginx/1 banner regex; conftest 6379 socket leak on bind fail
Task 9: fix round 1/5 (3 addressed, 0 open; commits 3a17a3a..237d01c)
Task 9: complete (commits 2173a68..237d01c, review clean after 1 fix round)
Task 9: minor (deferred): budget/silent tests depend on 10.255.255.1 black-holing (CI flake risk); budget_s allows >295 (runner kills at 300); untrusted-issuer now only a warning; double warning when budget exhausted + all silent
Task 10: dispatched (base 237d01c, implementer ae9a426411cb708ea, sonnet)
Task 10: Rulings: accepted implementer decisions (target-type default first target; control-char escaping; notice before prompt; --json prompt to stderr; hash skips __pycache__/symlinks; cli_format split)
Task 10: review → Important: escaping gaps (param names, dir names, error text); newline forgery in single-line fields; no escape tests; OSError in source_text; trust key auto-loaded from untrusted plugins dir (controller-mandated)
Task 10: Ruling: reverse earlier ruling — trusted public key NEVER auto-loaded from plugins_dir; default = package resource audidash_core/keys/catalog.pub (absent until maintainer keygen → no key); --public-key explicit override only — spec anti-goal: unverified plugin must not run without review — cost: maintainer must place key in package
Task 10: Ruling: promote minors: duplicate ids → exit 2 ambiguous; stdout/stderr reconfigure errors=replace; non-interactive decline test asserts nothing ran; docs wording
Task 10: minor (deferred): bidi chars not neutralized; loose error test; --param int oddities / repeated param; plugins hash ignores new unlisted files when manifest exists
Task 10: fix round 1/5 (5 addressed, 0 open; commits 3db8c8a..6f2d25d)
Task 10: complete (commits 237d01c..6f2d25d, review clean after 1 fix round)
Task 10: minor (deferred): --json may contain U+0085/2028; bidi chars in community source; reconfigure untested; non-community unreadable file goes to runner integrity check
Task 11: dispatched (base 6f2d25d, implementer ad0963eef70c31a0e, sonnet)
Task 11: complete (commits 6f2d25d..0c99d37, review clean)
Task 11: minor (deferred): gitleaks path allowlist file-wide; ISO doc 8.25/8.32 enforcement manual wording; 5.36 mapping approximate; codeql v3→v4; gitleaks license note for orgs; issue labels + OWNER placeholders
Final review: With fixes — Important: (1) run_local re-reads disk after review/signature (TOCTOU across CLI→runner); (2) bidi/invisible chars in source viewer; (3) permissions not shown before run; (4) sanitizer misses URI userinfo, key=value tokens, quoted/spaced passwords; (5) target/references/item_key unsanitized/unbounded; (6) verified tier hashes only entrypoint
Final review: Ruling: one fix wave covers all 6 Importants + minors (docs --public-key placement, RunResult manifest_sha256+trust, stderr pre-scrub, _SEMVER [0-9], macOS CI job, shutil.which for pwsh/bash) — spec anti-goals; interfaces Plans 2-4 inherit — cost: larger fix wave
Final review: Ruling: local tag v0.1.0-alpha.1 (unpushed) moved to the post-fix commit — cost: none (never published)
Final review: Ruling: mild over-redaction by new rules accepted (fail-safe for LGPD) — cost: occasional redacted benign text
Final review: fix wave re-review — all 6 Important + minors ADDRESSED (commits 0c99d37..bd80aa4)
Final review: parked — password regex ~4s/MB on whitespace — Ruling: real, unreachable today (all callers cap input ≤4KB); fix in Plan 2 opening task
Final review: parked — redacted fields can exceed schema limits; RunInput.target unbounded — Ruling: real, load-bearing for Plan 2 storage; carry to Plan 2 opening 'data-leaving-the-client' task
