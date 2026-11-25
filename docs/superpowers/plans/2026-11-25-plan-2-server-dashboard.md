# Plan 2 — Server, Dashboard, Secure Upload & Demo Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A central server (FastAPI API + HTMX dashboard on PostgreSQL) that receives sanitized findings from enrolled devices over mTLS, keeps a shared asset registry, finding lifecycle and tamper-evident audit log, shows the threat dashboard, and a one-command demo (`docker compose up` + `audidash demo`) that populates it from intentionally insecure lab targets.

**Architecture:** New workspace package `audidash-server` (FastAPI, SQLAlchemy 2, Alembic, Jinja2 + vendored HTMX/Chart.js). Caddy terminates TLS: `:8443` dashboard + enrollment, `:9443` ingestion API with required client certificates signed by the server's internal CA; the proxy forwards the client-cert fingerprint plus a shared secret header to the app, which listens only on the internal compose network. `audidash-core` gains a client (`audidash enroll`, `audidash login`, `audidash run --upload`, `audidash demo`). Scoring reuses `audidash_core.scoring`.

**Tech Stack:** FastAPI, Uvicorn, SQLAlchemy 2 (sync), Alembic, psycopg 3, argon2-cffi, pyotp, segno (QR as SVG), Jinja2, HTMX 2 and Chart.js 4 (vendored, no CDN), cryptography (CA), httpx (client), Caddy 2, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-11-25-soc-audidashboard-design.md` (sections 5, 7, 8, 11, 12, 14). Deferred findings from Plan 1: `docs/superpowers/plans/2026-11-25-plan-1-execution-ledger.md`.

## Global Constraints

- Python `>=3.12`; workspace members `packages/*`; new import name `audidash_server`; console script `audidash-server`.
- Code/commits/docstrings in English; user-facing dashboard text in PT-BR (single locale for now, strings kept in templates).
- Severity, category, status enums and the scoring formula come from `audidash_core` — never redefined in the server.
- Finding lifecycle states (spec §7): `open → acknowledged → resolved | false_positive | accepted_risk` plus `auto_resolved`; `accepted_risk` and `false_positive` require a non-empty justification; only `open` and `acknowledged` count in the score.
- Auto-resolve (spec §12.3): when a later run of the same plugin on the same asset does not report a fingerprint, that finding becomes `auto_resolved`; manual states are never changed automatically. Findings not seen for more than 90 days show as stale but still count.
- Fingerprint = `audidash_core.findings.fingerprint(plugin_id, finding.id, asset_id, item_key)`.
- Passwords: Argon2id (argon2-cffi defaults). TOTP mandatory for every account (RFC 6238, 30 s, 6 digits, ±1 step). Login lockout: 5 failures → 15 min lock per account; plus per-IP rate limit 20 attempts / 15 min.
- Dashboard sessions: cookie `__Host-audidash_session`, `HttpOnly; Secure; SameSite=Strict; Path=/`, server-side session rows, idle timeout 30 min, absolute 12 h; CSRF token on every state-changing form/HTMX request.
- CSP: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'` — no inline scripts/styles anywhere. Also HSTS (max-age=31536000), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
- RBAC roles: `admin` (users, devices, enrollment tokens, verified allowlist, assets), `analyst` (assets, finding lifecycle, runs), `viewer` (read-only).
- Device certificates: EC P-256 key generated on the client; CSR signed by the internal CA; validity 90 days; subject CN = device UUID; revocation is by device row (checked on every ingestion request).
- Enrollment tokens: 32 random bytes urlsafe, stored only as SHA-256, single use, expire in 24 h.
- API access tokens (CLI login): 32 random bytes, stored as SHA-256, bound to the device id, expire in 15 min.
- Audit log: append-only, each row stores `prev_hash` and `row_hash = sha256(prev_hash || canonical_json(row))`; no update/delete API.
- Retention: findings and runs older than 365 days (by `last_seen` / `finished_at`) purged by `audidash-server purge`.
- No external network calls from the server; no CDN assets; static files vendored with recorded sha256 in `static/VENDORED.md`.
- Secrets only from environment / Docker secrets (`AUDIDASH_SECRET_KEY`, `AUDIDASH_PROXY_SECRET`, `AUDIDASH_DATABASE_URL`, `AUDIDASH_CA_PASSPHRASE`); the app refuses to start in non-dev mode if any is missing or shorter than 32 chars.
- Every subprocess call uses argument lists; the path contains a space.

## Review Focus

1. Ingestion request whose proxy header is present but secret header wrong/missing (direct access bypassing Caddy) → 401, nothing stored. (Task 6 test `test_ingest_rejects_forged_proxy_headers`.)
2. Upload referencing an asset name that doesn't exist, or a run for a plugin not in the allowlist/catalog → 422 with a clear message; never auto-creates assets. (Task 6 `test_ingest_unknown_asset`.)
3. Same run uploaded twice (client retry) → idempotent via `run_id` (UUID chosen by the client): second call returns 200 with the existing run, no duplicate findings. (Task 6 `test_ingest_idempotent`.)
4. HTMX lifecycle action posted without CSRF token or by a `viewer` → 403, state unchanged. (Task 10 `test_lifecycle_requires_csrf_and_role`.)
5. Audit-log chain broken by a direct DB edit → `audidash-server audit verify` exits 1 and names the first bad row. (Task 5 `test_verify_detects_tampering`.)

---

### Task 1: Client-side data hardening (Plan 1 carry-over)

**Files:**
- Modify: `packages/audidash-core/src/audidash_core/sanitizer.py`, `runner.py`, `findings.py`
- Test: `packages/audidash-core/tests/test_sanitizer.py`, `test_runner.py`, `test_findings.py`

**Interfaces:**
- Produces: `RunInput.target` bounded `min_length=1, max_length=255`; after redaction the runner truncates `title` to 200, each reference to 200, `item_key` to 255 (re-validating via `Finding.model_validate`) so every emitted `Finding` satisfies the schema.

- [ ] **Step 1: Failing tests** — `test_password_rule_fast_on_whitespace` (`"password=" + " " * 1_000_000` redacts in < 1.0 s); `test_redacted_fields_respect_limits` (item_key of 255 chars containing `token=abc…` → result ≤ 255 and valid); `test_runinput_target_bounded` (256-char target → ValidationError).
- [ ] **Step 2: Run** `uv run pytest packages/audidash-core -q` → FAIL.
- [ ] **Step 3: Implement** — password branch starts with a non-space char (`[^;\s"'][^;\r\n"']{0,255}(?=;)`); truncate-then-validate in `_Scrubber.finding`.
- [ ] **Step 4: Run** full gate → PASS.
- [ ] **Step 5: Commit** `fix(core): bound redacted finding fields and password rule cost`

### Task 2: Server package, settings and app factory

**Files:**
- Create: `packages/audidash-server/pyproject.toml`, `src/audidash_server/{__init__.py,settings.py,app.py,security_headers.py}`
- Test: `packages/audidash-server/tests/{conftest.py,test_settings.py,test_headers.py}`

**Interfaces:**
- Produces: `Settings` (pydantic-settings; env prefix `AUDIDASH_`): `database_url: str`, `secret_key: SecretStr`, `proxy_secret: SecretStr`, `ca_passphrase: SecretStr`, `dev_mode: bool = False`, `data_dir: Path`, `session_idle_minutes: int = 30`, `session_absolute_hours: int = 12`, `retention_days: int = 365`; `Settings.validate_for_production()` raises `ValueError` naming missing/short secrets when `dev_mode` is False.
- `create_app(settings: Settings) -> FastAPI` mounting `/static`, installing the security-headers middleware, and routers added by later tasks.
- conftest fixture `app_client` (TestClient over SQLite in a tmp dir, `dev_mode=True`).

- [ ] **Step 1: Failing tests** — `test_production_requires_secrets` (missing `proxy_secret` → ValueError mentioning it; 31-char secret → error); `test_security_headers` (GET `/healthz` → exact CSP string from Global Constraints, HSTS, nosniff, no-referrer, `frame-ancestors 'none'`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** (`/healthz` returns `{"status": "ok"}`). **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(server): add server package, settings and security headers`

### Task 3: Data model and migrations

**Files:**
- Create: `src/audidash_server/db.py`, `models.py`, `alembic.ini`, `migrations/` (env.py + first revision)
- Test: `tests/test_models.py`

**Interfaces:**
- Produces SQLAlchemy models (UUID primary keys, timezone-aware timestamps):
  - `User(id, username unique, password_hash, totp_secret_enc, role, failed_logins, locked_until, created_at, disabled)`
  - `Session(id, user_id, created_at, last_seen_at, csrf_token, ip)`
  - `Device(id, name, owner_user_id, cert_fingerprint unique, cert_not_after, revoked_at, created_at)`
  - `EnrollmentToken(id, token_sha256 unique, created_by, expires_at, used_at, device_id)`
  - `ApiToken(id, token_sha256 unique, user_id, device_id, expires_at)`
  - `Asset(id, name unique, address, asset_type: TargetType, criticality: Criticality, tags: JSON list, created_at)`
  - `Run(id = client run_id, device_id, user_id, asset_id, plugin_id, plugin_version, manifest_sha256, trust, status, reason, started_at, finished_at, warnings JSON, received_at)`
  - `FindingRecord(id, fingerprint unique, asset_id, plugin_id, finding_id, item_key, title, severity, category, evidence, recommendation, references JSON, status: FindingStatus, justification, first_seen, last_seen, last_run_id, status_changed_at, status_changed_by)`
  - `FindingEvent(id, finding_id, run_id nullable, user_id nullable, from_status, to_status, justification, at)`
  - `VerifiedPlugin(id, manifest_sha256 unique, plugin_id, version, approved_by, approved_at)`
  - `AuditEntry(seq autoincrement, at, actor_user_id, actor_device_id, action, target, details JSON, prev_hash, row_hash)`
- `get_session()` dependency; `init_db(engine)` for tests (create_all) while production uses Alembic.

- [ ] **Step 1: Failing tests** — `test_asset_name_unique`, `test_fingerprint_unique`, `test_migration_matches_models` (run `alembic upgrade head` on a temp SQLite file, then compare `MetaData` reflected tables/columns with models — no diff).
- [ ] **Step 2–4:** implement, run → PASS.
- [ ] **Step 5: Commit** `feat(server): add data model and initial migration`

### Task 4: Accounts — Argon2id, TOTP, lockout, sessions, CSRF, RBAC

**Files:**
- Create: `src/audidash_server/auth/{passwords.py,totp.py,sessions.py,rbac.py,routes.py}`, `templates/{base.html,login.html,totp_setup.html}`, `static/css/app.css`
- Create: `src/audidash_server/cli.py` (`audidash-server create-admin --username U` prompting password twice via getpass and printing the TOTP provisioning URI + QR in terminal ASCII via segno)
- Test: `tests/test_auth.py`, `tests/test_rbac.py`

**Interfaces:**
- `hash_password(pw: str) -> str`, `verify_password(hash: str, pw: str) -> bool` (+ rehash-if-needed).
- `totp_secret_new() -> str`, `totp_verify(secret: str, code: str, at: datetime | None = None) -> bool`; TOTP secrets encrypted at rest with Fernet derived (HKDF-SHA256) from `secret_key`.
- `require_role(*roles: Role) -> Depends` raising 403; `current_user` dependency (session cookie) redirecting to `/login` for HTML and 401 for HTMX/JSON.
- `csrf_protect` dependency comparing form field `csrf_token` or header `HX-CSRF-Token` with the session's token (constant-time).
- Password policy: min 12 chars, rejected if in a bundled list of 10k common passwords (`auth/common_passwords.txt`, SecLists top-10k, license noted).

- [ ] **Step 1: Failing tests** — login happy path (password + TOTP) sets cookie with exact attributes; wrong TOTP → 401 and failed counter++; 5 failures → locked 15 min even with right creds; idle timeout 30 min and absolute 12 h (freeze time); logout deletes session row; CSRF missing → 403; viewer POST admin route → 403; weak/common password rejected by `create-admin`.
- [ ] **Step 2–4.** **Step 5: Commit** `feat(server): add accounts with Argon2id, mandatory TOTP, sessions, CSRF and RBAC`

### Task 5: Audit log with hash chain

**Files:**
- Create: `src/audidash_server/audit.py`; extend `cli.py` with `audit verify`
- Test: `tests/test_audit.py`

**Interfaces:**
- `record(db, *, action: str, actor_user_id: UUID | None, actor_device_id: UUID | None, target: str, details: dict) -> AuditEntry` — computes chain under a DB lock (`SELECT … FOR UPDATE` on PostgreSQL; serialized on SQLite).
- `verify_chain(db) -> int | None` — returns first bad `seq` or None.
- Actions recorded (exact strings): `login.success`, `login.failure`, `user.create`, `user.disable`, `device.enroll`, `device.revoke`, `enrollment_token.create`, `run.ingest`, `finding.status_change`, `asset.create`, `asset.update`, `asset.delete`, `plugin.verify`, `plugin.unverify`, `retention.purge`.
- `details` never contains secrets, tokens, passwords or evidence text.

- [ ] **Step 1: Failing tests** — chain of 3 verifies; editing row 2's details directly → `audit verify` exit 1 naming seq 2; deleting a row → detected; `details` for `login.failure` contains username but not password.
- [ ] **Step 2–4.** **Step 5: Commit** `feat(server): add tamper-evident audit log`

### Task 6: Internal CA, enrollment and mTLS ingestion API

**Files:**
- Create: `src/audidash_server/ca.py`, `api/{enroll.py,auth_token.py,ingest.py,deps.py}`
- Test: `tests/test_ca.py`, `tests/test_enroll.py`, `tests/test_ingest.py`

**Interfaces:**
- CA: `load_or_create_ca(data_dir: Path, passphrase: SecretStr) -> CA` (EC P-256 root, 10-year validity, key encrypted with `BestAvailableEncryption`); `CA.sign_csr(csr_pem: bytes, device_id: UUID) -> x509.Certificate` (rejects non-P-256 keys and CSRs with extra extensions; sets CN=device_id, 90-day validity, clientAuth EKU); `CA.cert_pem`.
- `POST /enroll` (port 8443, no client cert): body `{token, device_name, csr_pem}` → 201 `{device_id, cert_pem, ca_pem}`; token single-use/expiry/sha256 checks; audit `device.enroll`.
- Proxy trust (`deps.client_device`): requires header `X-Audidash-Proxy-Secret` equal (constant-time) to settings and `X-Client-Cert-Fingerprint` (lowercase hex sha256 of DER) matching a non-revoked, unexpired `Device`; else 401.
- `POST /api/v1/auth/token` (mTLS): `{username, password, totp}` → `{access_token, expires_at}` bound to device; same lockout rules as dashboard login.
- `GET /api/v1/assets` (mTLS + bearer) → list `{id, name, address, asset_type, criticality}`.
- `POST /api/v1/runs` (mTLS + bearer): body `{run_id: UUID, asset: str (name), result: RunResult JSON}`; validates with `audidash_core.runner.RunResult`; rejects findings whose `target` != the asset's `address` or `name`; upserts findings by fingerprint (`last_seen`, `last_run_id`, re-open `auto_resolved` → `open` with event); auto-resolves missing fingerprints for same `(asset, plugin_id)` only when `status == ok`; idempotent on `run_id`; audit `run.ingest`; response `{run_id, new, updated, auto_resolved, asset_score}`.

- [ ] **Step 1: Failing tests** — CSR signing (wrong curve rejected; CN = device id; EKU clientAuth); enrollment token reuse → 410, expired → 410; forged proxy headers (no/wrong secret) → 401 (Review Focus 1); revoked device → 401; bearer from another device → 401; unknown asset → 422 (Review Focus 2); idempotent re-upload (Review Focus 3); auto-resolve + re-open flow over three uploads; manual `accepted_risk` untouched by auto-resolve; error-status run does not auto-resolve.
- [ ] **Step 2–4.** **Step 5: Commit** `feat(server): add internal CA, device enrollment and mTLS ingestion API`

### Task 7: CLI client — enroll, login, upload

**Files:**
- Create: `packages/audidash-core/src/audidash_core/client/{config.py,api.py}`; modify `cli.py` (new subcommands) — keep `cli.py` under ~450 lines by putting handlers in `cli_server.py`
- Modify: `packages/audidash-core/pyproject.toml` (add `httpx`)
- Test: `packages/audidash-core/tests/test_client.py` (against the server app via an in-process ASGI transport that injects the proxy headers, plus a pure TLS test using a local `ssl` server for the pinning logic)

**Interfaces:**
- Config dir: `platformdirs.user_config_dir("audidash")` (add `platformdirs`); files `device.key` (PEM, created with 0600 on POSIX; on Windows inherits the user-profile ACL), `device.crt`, `ca.crt`, `server.json` (`{dashboard_url, api_url, device_id}`), `token.json` (`{access_token, expires_at}`, 0600).
- `audidash enroll --server https://host:8443 --api https://host:9443 --token T --name NAME [--ca-fingerprint SHA256]` — generates key + CSR locally, posts to `/enroll`; the dashboard URL's TLS certificate is verified against `--ca-fingerprint` (printed by the server CLI) on first contact (TOFU only with explicit fingerprint; without it, refuse unless `--insecure-first-contact` with a loud warning).
- `audidash login` — prompts username, password (getpass), TOTP; stores token.
- `audidash run … --upload --asset NAME` — after a successful local run, uploads with a fresh `run_id`; prints the server response line `Uploaded: <new> new, <updated> updated, <auto_resolved> auto-resolved — asset score <score> (<band>)`.
- `audidash assets` — lists assets from the server.
- All requests use mTLS with the device cert and verify the server against the pinned `ca.crt`.

- [ ] **Step 1: Failing tests** — enroll writes the 4 files with restrictive perms (POSIX check, skip on Windows); login stores token and never writes the password anywhere (scan config dir); upload succeeds and prints the summary line; expired token → message "run `audidash login`" exit 1; server cert not signed by pinned CA → refuse.
- [ ] **Step 2–4.** **Step 5: Commit** `feat(cli): add enroll, login, assets and run --upload`

### Task 8: Dashboard — layout, overview page

**Files:**
- Create: `src/audidash_server/web/{routes_overview.py,queries.py}`, `templates/{overview.html,partials/_score_gauge.html,_severity_cards.html,_suspicious.html,_top_assets.html}`, `static/js/{htmx.min.js,chart.umd.min.js,app.js}`, `static/VENDORED.md`
- Test: `tests/test_overview.py`

**Interfaces:**
- Overview (`GET /`): global score (criticality-weighted via `audidash_core.scoring.global_score`) with band label PT-BR (`Baixo`, `Moderado`, `Alto`, `Crítico`), counts by severity of counted findings, suspicious list (category `suspicious`, counted states, newest first, max 10), top 5 assets by score, 30-day trend (daily snapshot computed on the fly from `FindingEvent`), stale count (>90 days).
- Charts rendered by `app.js` reading `data-*` JSON attributes (no inline scripts). Dark theme default with a light toggle stored in `localStorage` (try/catch).
- Layout: left nav — Visão geral, Ativos, Achados, Execuções, Plugins, Dispositivos, Usuários (admin), Auditoria (admin).

- [ ] **Step 1: Failing tests** — overview numbers for a seeded DB (2 assets, mixed findings) match `audidash_core.scoring` exactly; no `<script>` without `src` and no `style=` attributes in rendered HTML; viewer can view.
- [ ] **Step 2–4.** **Step 5: Commit** `feat(server): add dashboard layout and overview`

### Task 9: Dashboard — assets

**Files:** `web/routes_assets.py`, `templates/assets/*.html`; Test: `tests/test_assets_web.py`

**Interfaces:** list with score/band/open counts; create/edit/delete (admin, analyst) with fields name, address, asset_type, criticality, tags; delete refused if findings exist (offer "arquivar" = not in scope; just refuse with message). HTMX inline edit. Audit events.

- [ ] Steps 1–5 (tests: CRUD per role, CSRF, unique name error shown, score column equals `asset_score`). Commit `feat(server): add asset registry pages`

### Task 10: Dashboard — findings and lifecycle

**Files:** `web/routes_findings.py`, `templates/findings/*.html`; Test: `tests/test_findings_web.py`

**Interfaces:** list with filters (asset, severity, category, status, plugin, stale) + pagination 50; detail page with evidence (escaped), recommendation, references, history (`FindingEvent`); actions via HTMX POST: acknowledge, resolve, false_positive (justification required), accepted_risk (justification required), reopen; each records `FindingEvent` + audit `finding.status_change`.

- [ ] Steps 1–5 (tests include Review Focus 4; justification required; XSS payload in evidence rendered escaped). Commit `feat(server): add findings list, detail and lifecycle actions`

### Task 11: Dashboard — runs, plugins (verified allowlist), devices, users, audit

**Files:** `web/routes_{runs,plugins,devices,users,audit}.py`, templates; Test: `tests/test_admin_web.py`

**Interfaces:**
- Runs: list (asset, plugin, trust, status, counts, device, user, time).
- Plugins: shows plugins seen in runs (id, version, manifest_sha256, trust reported); admin can mark a `manifest_sha256` as verified (VerifiedPlugin) or remove it; `GET /api/v1/verified` (mTLS) returns the allowlist; CLI `audidash plugins list --sync-verified` fetches it into the catalog's `verified_hashes` (extend Task 7 client).
- Devices: list, create enrollment token (shown once + copyable CLI command incl. CA fingerprint), revoke.
- Users: admin creates users (temporary password + forced TOTP setup on first login), changes role, disables.
- Audit: paginated chain view + "verificar integridade" button.

- [ ] Steps 1–5. Commit `feat(server): add runs, plugin allowlist, devices, users and audit pages`

### Task 12: Retention and operations commands

**Files:** extend `cli.py` (`purge`, `show-ca-fingerprint`, `create-enrollment-token`); Test: `tests/test_ops.py`

**Interfaces:** `purge [--dry-run]` deletes runs/findings beyond `retention_days` and records `retention.purge` with counts; `show-ca-fingerprint` prints the CA cert SHA-256; `create-enrollment-token --hours 24` prints token once.

- [ ] Steps 1–5. Commit `feat(server): add retention purge and ops commands`

### Task 13: Docker Compose, Caddy mTLS and demo lab

**Files:**
- Create: `deploy/Dockerfile.server` (python:3.12-slim, non-root user, `uv sync --frozen --no-dev --package audidash-server`), `deploy/Caddyfile`, `deploy/docker-compose.yml`, `deploy/.env.example`, `deploy/entrypoint.sh` (alembic upgrade, start uvicorn on 0.0.0.0:8000 internal only)
- Create: `lab/web-noheaders/` (nginx serving a page with no security headers and `Server: nginx/1.x` banner), `lab/tls-expired/` (nginx with an expired self-signed cert generated at build time), `lab/redis-open/` (redis bound inside lab network — port 6379 exposed only to the lab network)
- Modify: `.gitignore` add `!deploy/.env.example`
- Test: `deploy/tests/test_compose_config.py` (parses compose YAML: app not published to host; only Caddy publishes 8443/9443; lab services on `lab` network; secrets from env; containers run as non-root where supported)

**Interfaces:**
- Caddy: `:8443` → app (server TLS with Caddy internal cert or provided cert); `:9443` with `client_auth { mode require_and_verify; trust_pool file /data/ca/ca.crt }` → app, setting headers `X-Client-Cert-Fingerprint {http.request.tls.client.fingerprint}` and `X-Audidash-Proxy-Secret {$AUDIDASH_PROXY_SECRET}`, and stripping any client-supplied copies of both headers on both ports.
- `make`-free instructions in `deploy/README.md` (PT/EN): `cp .env.example .env`, generate secrets with `python -c "import secrets;print(secrets.token_urlsafe(48))"`, `docker compose up -d`, `docker compose exec server audidash-server create-admin --username admin`.

- [ ] Steps 1–5 (plus CI job `compose-smoke` on ubuntu: `docker compose up -d --wait`, `curl -k https://localhost:8443/healthz`, `curl -k https://localhost:9443/api/v1/assets` without client cert must fail TLS handshake). Commit `feat(deploy): add compose stack with Caddy mTLS and demo lab targets`

### Task 14: `audidash demo` and end-to-end test

**Files:** `packages/audidash-core/src/audidash_core/demo.py`, CLI wiring; `deploy/tests/test_e2e_demo.py` (marked `e2e`, run only in the CI compose job)

**Interfaces:** `audidash demo --server https://localhost:8443 --api https://localhost:9443` — requires a prior `enroll` + `login`; ensures the three lab assets exist via the API (`POST /api/v1/assets` allowed for analyst/admin — add to Task 6's API if missing, with audit `asset.create`), runs `http-security-headers` against `web-noheaders`, `tls-certificate-check` against `tls-expired`, `network-port-scan` against `redis-open` (ports list `[6379, 80, 443]`), uploads each, prints a summary and the dashboard URL.
- The e2e test drives: create admin (non-interactive flags for CI only: `--password-stdin`, `--totp-secret-out FILE`), create enrollment token, `audidash enroll`, `audidash login` (TOTP computed from the secret file), `audidash demo`, then asserts via API that ≥1 critical (`TLS-EXPIRED`) and ≥1 high (`NET-RISKY-PORT`) findings exist.

- [ ] Steps 1–5. Commit `feat(cli): add demo command and end-to-end compose test`

### Task 15: Docs, compliance update, CI wiring, release notes

**Files:** README.md/README.en.md (architecture now real; "Demo em 5 minutos" section with screenshots placeholders `docs/img/`), `docs/compliance/*.md` (8.15 logging, 8.5 secure authentication, 8.24 CA, 5.15/8.2 access control/RBAC, LGPD art. 37/46/48 move to implemented where true), SECURITY.md (threat model of the server: proxy-secret header trust, CA key at rest, dashboard session model), CHANGELOG `[0.2.0-alpha.1]`, CI: server tests on SQLite matrix + a `postgres` service job running server tests with `AUDIDASH_DATABASE_URL`, bandit/mypy include the server package.

- [ ] Steps: full gate green locally; YAML validated; commit `docs: document server, demo and security model for 0.2.0-alpha.1`; local tag `v0.2.0-alpha.1` (push only when the user asks).
