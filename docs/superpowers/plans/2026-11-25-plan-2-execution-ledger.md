# SDD ledger — plan: docs/superpowers/plans/2026-11-25-plan-2-server-dashboard.md

Spec: docs/superpowers/specs/2026-11-25-soc-audidashboard-design.md (§14 addendum). Branch feat/plan-2-server from main @ e9d86e8.
Env: uv 0.12, Python 3.14 local, Docker CLI present (daemon may not be running locally — compose verified in CI).

## Pre-flight scan
| Pair / task | Finding / ruling |
|---|---|
| T6↔T14 | T14 needs POST /api/v1/assets. Ruling: Task 6 implements POST /api/v1/assets (analyst/admin bearer, audit asset.create) — cost: slightly bigger T6 |
| T6↔T8 | Trend needs events for creation. Ruling: T6 records FindingEvent(from_status=None, to_status=open) when a finding is first created and on every auto status change |
| T7 self | Client must be testable in-process. Ruling: client/api.py functions accept an optional httpx transport/client factory; tests use ASGI transport that injects proxy headers; mTLS wiring tested separately |
| T4 self | `__Host-` cookie requires Secure. Ruling: tests use TestClient(base_url="https://testserver") |
| T8 self | HTMX default inserts an inline <style> (violates CSP). Ruling: `<meta name="htmx-config" content='{"includeIndicatorStyles":false}'>` and indicator CSS in app.css; Chart.js sizing via element.style is CSP-compatible |
| T13 self | Caddy `{http.request.tls.client.fingerprint}` format must equal app's lowercase hex sha256(DER). Ruling: app normalizes (lowercase, strip colons) and T13 test documents the format |
| T4↔T14 | create-admin non-interactive flags (--password-stdin, --totp-secret-out) added in T14 as planned; T4 keeps interactive only |
| T2 | needs pydantic-settings dependency — allowed |
| T15 | ISO 8.32 row: branch protection now enabled on GitHub (2026-11-25) → mark implemented |

## Progress
Task 1: dispatched (base e9d86e8, implementer a5b36e1f3e19b7be8, sonnet)
Task 1: complete (commits e9d86e8..ccec1a0, review clean)
Task 1: minor (deferred): duplicate title limit constant; no leak assertion in redacted-fields test; uncaught ValidationError in _Scrubber.finding (unreachable); long spaced password >257 partially leaks (pre-existing)
Task 2: dispatched (base ccec1a0, implementer a235873b8b67c07dc, sonnet)
Task 2: Ruling: keep httpx with targeted filterwarnings for the TestClient deprecation (no httpx2 install; implementer's attempt was blocked by permission classifier — not retried by controller) — cost: revisit when Starlette drops httpx
Task 2: review → Important: security headers missing on unhandled 500; _is_dev parsing mismatch fail-open (empty secrets with DEV_MODE=on)
Task 2: Ruling: promote minors: create_app calls validate_for_production when not dev_mode; coverage source adds audidash_server
Task 2: minor (deferred): uvicorn server_header=False needed at serve time (Task 13); TEMPLATES_DIR unused; test typing noise; no HEAD/static-served test
Task 2: fix round 1/5 (3 addressed, 0 open; commits fd6b571..a078ac2)
Task 2: complete (commits ccec1a0..a078ac2, review clean after 1 fix round)
Task 3: dispatched (base a078ac2, implementer a2fddcd2436676650, sonnet)
Task 3: Rulings: accepted FK choices (device owner RESTRICT; run/event/verified/changer SET NULL; audit actor no FK); two alembic.ini accepted
Carry to Task 4: Ruling: session cookie value = 32-byte random token; DB stores only sha256 (add Session.token_sha256 unique via new Alembic revision) — UUID id alone is not a secret-grade token
Task 3: review → Important: Run.trust/status untyped; get_session commits in teardown (maybe after response)
Task 3: Ruling: promote minors cheap before data exists: FK indexes for PG; AuditEntry.seq BigInteger(+Integer variant SQLite); naive-datetime rejection + round-trip tests
Task 3: minor (deferred): JSON columns not Mutable (reassign whole value); env.py FK pragma during migrations; engine dispose on shutdown; two alembic.ini drift; downgrade/SET NULL tests
Task 3: Ruling: explicit-commit sessions (get_session never commits; handlers call db.commit()) — carry to every route task — cost: a route forgetting commit silently drops writes (tests must assert persistence)
Task 3: fix round 1/5 (3 addressed, 0 open; commits 3ae26be..d819d44)
Task 3: complete (commits a078ac2..d819d44, review clean after 1 fix round)
Task 3: minor (deferred): unindexed SET NULL FKs enrollment_tokens.device_id, findings.status_changed_by, verified_plugins.approved_by
Task 4: dispatched (base d819d44, implementer aa54a7d1d06ec62f8, opus — security-critical; rulings: session token sha256 + 0002, login CSRF double-submit, TOTP replay guard, compact common-password list)
Task 4: Rulings: accepted Session.mfa_pending + encrypted setup_token, extra auth files, 246-entry common list substitute, atomic TOTP replay update
Carry to Task 8: replace placeholder GET / in auth/routes.py with overview
Carry to Task 13 (and Task 6 deps): client IP = X-Forwarded-For from Caddy ONLY when X-Audidash-Proxy-Secret valid; else request.client.host
Task 4: review → Important: lockout counter non-atomic (concurrent bypass)
Task 4: Ruling: promote cheap minors into round: timing oracle no-op write; TOTP ±60s boundary tests; tests for pending cap / foreign setup_token / pending rejected by csrf route; enrolment double-submit 500; explicit Depends in home; RBAC 403 detail assertion
Task 4: minor (deferred): login CSRF token never rotates; pending session cannot log out (UX)
Task 4: fix round 1/5 (2 addressed, 0 open; commits 20a17e3..a679dc1)
Task 4: complete (commits d819d44..a679dc1, review clean after 1 fix round)
Task 4: minor (deferred): burst window — increment counted after Argon2 check (reserve-attempt-first hardening); SQLite dev concurrency 'database is locked' (WAL/BEGIN IMMEDIATE)
Task 5: dispatched (base a679dc1, implementer ae07eb3095fa66f5e, sonnet)
Task 5: review → Important: concurrent-lockout and TOTP-claim-race failure paths skip login.failure audit
Task 5: Ruling: promote minors: strip control chars from audited username; round-trip µs/non-UTC test; long/control-char username test; CLI audit verify friendly error on DB failure
Task 5: minor (deferred): 'code' substring over-broad in key guard; failed logins append rows under global advisory lock (bounded by rate limit)
Task 5: fix round 1/5 (2 addressed, 0 open; commits de10fb1..f951f4a)
Task 5: complete (commits a679dc1..f951f4a, review clean after 1 fix round)
Task 5: minor (deferred): username sanitizer misses U+2028/2029/bidi; make_engine outside try in audit verify
Task 6: dispatched (base f951f4a, implementer a45f7be6c5ee0cd9c, opus; rulings: POST assets, creation events, shared auth/service.py, client_ip helper, target match, run_id idempotency per device, 5 MiB limit)
Task 6: Ruling: any user may obtain an API token on any enrolled device — spec §12.6 (several users can share a machine; cert = machine, login = person) — cost: none
Task 6: Rulings: accepted runs.ingest_summary (0003), auto-resolve only open/ack, result.target must match, viewers 403 on upload, 201/200 replay; dev-mode CA needs AUDIDASH_CA_PASSPHRASE for persistence (document in Task 15)
Task 6: complete (commits f951f4a..79c6b85, review clean)
Task 6: carried minors → Ruling: Task 10 makes ALL status transitions guarded SQL UPDATEs (manual + auto-resolve in services/ingest) to stop PG lost updates; Task 11 validates plugin_id against manifest id pattern + manifest_sha256 hex + strips control chars in run metadata at ingest; Task 12 makes CA creation atomic (temp+rename) and adds 'init-ca' command
Task 6: minor (deferred): untested race branches (enroll claim loss, run_id IntegrityError replay, fingerprint 409); duplicate token hashing helper; DB session held during slow upload; dev-mode CA passphrase restart
Task 7: dispatched (base 79c6b85, implementer a741d5b3e5cc07058, sonnet; rulings: ApiClient w/ injectable transport, TOFU via --ca-fingerprint check on returned ca_pem, perms, target=asset.address)
Task 7: Rulings: accepted enroll --force, client/identity.py, non-ok runs not uploaded (exit 1), duplicated server test setup in core tests
Task 7: complete (commits 79c6b85..ae67e07, review clean)
Carry → Ruling: Task 12 adds CA.issue_server_cert(hosts: list[str]) (SERVER_AUTH EKU, DNS/IP SANs) + 'audidash-server issue-server-cert --host …'; Task 13 Caddy :9443 serves that cert (tls cert key) and client_auth trusts the internal CA; e2e checks API TLS with pinned CA
Task 7: minor (deferred): enroll partial-failure state / --force keeps token.json / OSError traceback; --insecure-first-contact saves before showing fingerprint; .tmp name collisions + fsync; vacuous enrol assertion; unclosed ApiClient in TLS tests; no wrong-SAN test
User decision (2026-11-26): vendor only htmx 2.0.4 (downloaded+verified by controller, commit 24b4e60); charts as server-rendered SVG, no Chart.js — Task 8 must not add chart.umd.min.js
Task 8: dispatched (base 24b4e60, implementer a791e512f8852976a, sonnet)
Task 8: Rulings: accepted extra htmx-config hardening keys; narrowed login/TOTP script assertions to inline-only
Task 8: complete (commits 24b4e60..acc1d66, review clean)
Task 8: minor (deferred): trend boundary/stale/XSS regression tests; event tie ordering (add SQL ORDER BY at + secondary); last trend point vs gauge; double findings load + 30xN trend cost; theme flash; UTC label on suspicious dates; unused fixtures
Task 9: dispatched (base acc1d66, implementer af04067c3d78e69b9, sonnet)
Carry to final verification: exercise HTMX 409/422 swaps + inline edit in the built-in browser against a dev server
Task 9: complete (commits acc1d66..f63a263, review clean)
Task 9: minor (deferred): refused-delete IndexError branch; untested delete race; no UI feedback on 403/404/5xx htmx (→ Task 10 adds htmx:responseError toast in app.js); duplicate field ids; loose unauth test; rename-vs-ingestion hint
Task 10: dispatched (base f63a263, implementer ab60edbf4478c16b2, sonnet; rulings: transitions table, services/lifecycle guarded UPDATE used by ingest too, audit w/o justification text, safe reference links, responseError toast)
Task 10: Ruling: justification may contain newline/tab (multi-line text; rendered escaped) — cost: none
Flake watch: packages/audidash-core/tests/test_client.py intermittently failing under full-suite load (enroll assertion + fixture error) — investigate before final review
Task 10: review Approved w/ Important: severity-order test passes under alphabetical sort
Task 10: Ruling: same round: reject Cf/Zl/Zp in justification; add reference edge-case + page clamp tests
Task 10: minor (deferred): rowcount race branch untested; fq re-exports; history same-instant ordering
Task 10: fix round 1/5 (2 addressed, 0 open; commits 7e59d03..2970baf)
Task 10: complete (commits f63a263..2970baf, review clean after 1 fix round)
Flake: dispatching Task 7 implementer to diagnose test_client.py intermittent failure (base 2970baf)
Flake root cause: token_urlsafe tokens starting with '-' broke argparse --token; fixed in 4182ed1 (--token=VALUE, prompt if omitted)
Carry to Task 11/12: every displayed CLI enroll command uses --token=VALUE form
Flake fix reviewed: clean (commit 4182ed1)
Carry to Task 14: catch EOFError/KeyboardInterrupt at getpass prompts (token + password) → clean ServerCliError exit; tests
Task 11: dispatched (base 4182ed1, implementer aedfee38cbb888c23, sonnet)
Task 11: controller verified full suite 650 passed/5 skipped; rulings accepted: verify only hashes seen in runs; last-admin guard tested directly; test plugin ids renamed
Task 11: complete (commits 4182ed1..7a4f974, review clean)
Task 11: Ruling: carry into Task 12: last-admin guard row lock (with_for_update); verified.json fetched_at + 24h expiry warning; fix vacuous tamper test (run --json trust==community); tests for disabled/demoted existing sessions; validate Host netloc in default_urls; load CA before creating token
Task 11: minor (deferred): list/show vs run trust inconsistency (documented); plugins page wording
Task 12: dispatched (base 7a4f974, implementer af8b1a4bfd5a92231, sonnet; Part A ops + issue-server-cert + atomic CA; Part B carry-overs)
Task 12: Rulings accepted: split tamper test; load_verified (hashes, stale); default_urls 3-tuple + warning; orphan CA key regenerated under lock
Task 12: review → Important: orphan-key regeneration silently destroys a real CA key
Task 12: Ruling: reverse accepted orphan-regeneration: load_or_create_ca refuses ('incomplete CA: ca.key present without ca.crt — restore ca.crt or run init-ca --force') ; init-ca --force moves key aside to ca.key.orphan-<UTC ts> then creates new CA. Promote cheap minors: real TLS handshake test; --days cap 398; IPv6 CN brackets; LDH-only DNS SAN; timedelta(hours); CLI token refuses without CA; --created-by required msg with several admins; port ≤65535
Task 12: minor (deferred): stale-lock race in _creation_lock; thin CLI audit row; purge needs CA passphrase in dev; issue-server-cert prod-config test; server key fsync/half pair; future fetched_at; zsh IPv6 quoting
Task 12: fix round 1/5 (2 addressed, 0 open; commits bdda50d..6f98fc2)
Task 12: complete (commits 7a4f974..6f98fc2, review clean after 1 fix round)
Task 12: minor (deferred): orphan CAError → generic 500 on /enroll (fail-closed, no handler/test); _write_key --force unlink+create not atomic
Task 13: dispatched (base 6f98fc2, implementer a875fbe4bd1817ecc, opus; Docker daemon not running locally → compose config + YAML tests locally, real build/up in CI compose-smoke job)
Task 13: Rulings accepted: lab listens 8080/8443 internally (non-root); 8443/9443 bound to 127.0.0.1 by default via AUDIDASH_BIND_ADDRESS; :8443 host-bound AUDIDASH_DASHBOARD_HOST; redis stock image. Compose untested until CI compose-smoke runs (needs branch push)
Task 13: review → Important: CI pipelines with pipefail (s_client|grep, curl|grep) can fail falsely
Task 13: Ruling: promote minors: pg_isready -h 127.0.0.1; prove expiry in tls-expired check; document secret charset; entrypoint reissues api cert when not chaining to current ca.crt or <30d to expiry or hosts changed; /api* exact split on :8443
Task 13: fix round 1/5 (2 addressed, 0 open; commits d78065a..25f316b)
Task 13: complete (commits 6f98fc2..25f316b, review clean after 1 fix round; real compose untested until CI)
Task 13: minor (deferred): entrypoint doesn't distinguish check-server-cert exit 2 from 1
Task 14: dispatched (base 25f316b, implementer ab821b06759344e5c, sonnet). Ruling: e2e asserts NET-OPEN-PORT on lab-redis + TLS-EXPIRED critical on lab-tls + HTTP-NO-CSP on lab-web (NET-RISKY-PORT only fires on canonical 6379, lab uses 16379; plugin semantics unchanged)
Task 14: Rulings accepted: e2e reads findings via docker compose exec (no findings API); login --username added; TOTP secret in /data removed by down -v; F811 per-file ignore
Task 14: review → Important: demo swallows plugin warnings / reports success with 0 findings; Ctrl-C at community confirmation + main() unhandled
Task 14: Ruling: promote minors: e2e assertion diagnostics; Windows APPDATA/LOCALAPPDATA isolation; unit demo test must not hit real lab ports (use fake plugins dir or skip unless lab reachable); 409-with-different-address hint
Task 14: minor (deferred): TOTP step-boundary in e2e; PT/EN mix in create-admin messages
Task 14: fix round 1/5 (3 addressed, 0 open; commits 87bbd65..d11dbbf)
Task 14: complete (commits 25f316b..d11dbbf, review clean after 1 fix round; e2e first real run in CI)
Task 14: minor (deferred): ensure_assets conflict check doesn't paginate
Task 15: dispatched (base d11dbbf, implementer a3e932d2f3ff73b9e, sonnet; incl. server-postgres CI job + AUDIDASH_TEST_DATABASE_URL fixture support; no tag)
Task 15: Rulings accepted: ISO 8.10 retention row added; # nosec markers for 4 bandit lows
Task 15: complete (commits d11dbbf..3488f9b, review clean; branch protection claim verified — controller enabled it 2026-11-25)
Task 15: minor (deferred): PG fixture DROP SCHEMA guard; TRUNCATE lock risk; B107 nosec rationale
Browser verification (controller, 2026-11-26): dev server + test admin; login w/ TOTP OK, overview renders (SVG gauge), asset create via HTMX OK, duplicate name 422 swapped inline with PT message, no CSP console errors. Found: at narrow width (~500px) tables overflow and cause horizontal page scroll → add to final fix wave (wrap tables in overflow-x:auto container)
Final review: With fixes — Important: NUL bytes 500 on PG (incl. unauthenticated login); enrollment token over unverified TLS + SECURITY.md understated; must-fix PG fixture DROP guard
Final review: Ruling: ONE fix wave = final-fix-findings.md (Important 1-2 with option (a): :8443 served by internal-CA cert + /ca.pem + verify-before-send; items 3-10 incl. browser-found table overflow, versions bump to 0.2.0a1, async→def, retention on received_at, ORDER BY)
Final fix wave: implementer done (165cdf4); rulings accepted: retention on received_at (supersedes constraint wording); AUDIDASH_DASHBOARD_HOST → AUDIDASH_DASHBOARD_HOSTS
Final fix wave re-review: items 1,3-10 addressed; NEW Important: multi-PEM /ca.pem and result.ca_pem trusted wholesale → MITM bypasses --ca-fingerprint
Ruling: residual is security-critical and load-bearing (Plan 3 inherits enrolment) — dispatch ONE narrowly scoped follow-up fix (single-cert parse + re-serialize for /ca.pem and ca_pem, streamed 16 KiB cap) with a scoped re-review, instead of surfacing unfixed — cost: one extra small round beyond the single fix wave
Follow-up fix: ADDRESSED (commits 165cdf4..0378616); minor (deferred): iter_bytes after Content-Encoding decode (use iter_raw/identity)
Final review: complete — all Important findings fixed and re-reviewed
Browser check 375px (controller): no horizontal page scroll (scrollWidth 375), table scrolls inside .table-wrap. Minor cosmetic: empty band under the nav on mobile (deferred)
