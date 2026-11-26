# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0-alpha.1] - 2026-11-26

Second alpha: the server and web dashboard (Plan 2), plus the CLI client features that talk to it.

### Added
- `audidash-server` (FastAPI + SQLAlchemy + Alembic; PostgreSQL in production, SQLite for
  development): ingestion API (`/api/v1`) with finding deduplication, status lifecycle and
  auto-resolution.
- HTMX dashboard: overview (SVG gauge and trend), assets, findings, runs, plugin allow-list,
  devices and enrolment tokens, users and audit-log viewer. htmx is vendored; no third-party
  JavaScript.
- Authentication: Argon2id, mandatory TOTP, account lockout, per-IP rate limit, server-side
  sessions with CSRF, role-based access control.
- Hash-chained audit log with `audidash-server audit verify`.
- Internal CA (EC P-256), single-use enrolment tokens and device enrolment; mTLS via Caddy.
- Ops CLI: `create-admin`, `create-enrollment-token`, `show-ca-fingerprint`, `init-ca`,
  `issue-server-cert`, `check-server-cert`, `audit verify`, `purge` (retention, 365 days default).
- `deploy/`: Dockerfile, Caddyfile, Docker Compose stack (PostgreSQL, server, Caddy) and three
  intentionally vulnerable lab targets.
- `audidash` client commands: `enroll`, `login`, `assets`, `run --upload`, `demo` and
  `plugins list --sync-verified`.
- CI: `server-postgres` job (server tests against PostgreSQL 16) and a `compose-smoke` job
  (Caddy mTLS, lab targets, end-to-end demo).
- Server threat model in `SECURITY.md`; ISO 27001 and LGPD mappings updated (alignment, not
  certification); Portuguese and English "5-minute demo" in the READMEs.

### Changed
- READMEs describe the architecture that actually exists; roadmap: Plan 3 desktop app, Plan 4
  remote execution and Linux/Windows plugins.
- Server test fixtures honour `AUDIDASH_TEST_DATABASE_URL` (schema migrated once per session,
  tables truncated between tests); the default remains SQLite.

### Security
- Proxy headers (client IP, certificate fingerprint) are trusted only with the proxy secret;
  Caddy strips client-supplied copies; the app sits on an internal network.
- CA key encrypted at rest with `AUDIDASH_CA_PASSPHRASE` and never overwritten; the proxy API
  certificate is re-validated on every start.
- Known limitations documented in `SECURITY.md` (per-process rate limiter, SQLite is
  development-only, Caddy loads the API certificate at start, `verified.json` cache trust,
  TOFU enrolment).

## [0.1.0-alpha.1] - 2026-11-25

First alpha: the foundation and core of the platform (Plan 1). CLI only.

### Added
- uv workspace monorepo (`audidash-core`, `audidash-sdk`), Apache-2.0 license and community files.
- Finding model and scoring (`findings`, `scoring`).
- Client-side sanitizer that redacts secrets and personal data (LGPD) from findings.
- Plugin manifest (`plugin.yaml`) with strict validation and SHA-256 integrity verification.
- Plugin runner with isolated subprocess execution, minimal environment, timeout and output caps,
  and whole-process-tree termination (Windows Job Objects, POSIX `killpg`).
- Ed25519-signed plugin catalog with trust tiers (`official`, `verified`, `community`)
  and `tools/sign_catalog.py`.
- `audidash` CLI: list, inspect, hash, validate and run plugins.
- Plugin SDK for Python plugins and plugin-authoring docs (PT-BR and EN).
- Three official plugins: `http-security-headers`, `tls-certificate-check`, `network-port-scan`.
- CI matrix (Ubuntu and Windows, Python 3.12 and 3.13; macOS, Python 3.12) with ruff, mypy, pytest coverage
  (>= 85 %), bandit and pip-audit; CodeQL, gitleaks and Dependabot.
- Issue and pull request templates, CODEOWNERS.
- ISO/IEC 27001/27002 and LGPD alignment documents (alignment, not certification).
- "Known limitations" section in `SECURITY.md`.

### Security
- `run_local` pins the reviewed manifest (`expected_manifest`, `expected_manifest_sha256`);
  the CLI passes the catalog pin and shows source only from bytes matching the pinned hashes,
  so code swapped after review is blocked (`integrity`).
- `verified` tier requires the `plugin.yaml` sha256 in the allow-list plus full file integrity.
- CLI escapes bidirectional/invisible Unicode (Trojan Source, CVE-2021-42574) and warns before
  the prompt; the manifest summary (permissions, connection, parameters) is shown before every run.
- Sanitizer also redacts URI userinfo passwords, `token`/`secret`/`api_key`-style values,
  quoted and `;`-terminated passwords, and GitHub/Slack/Stripe token formats.
- Findings: `target` forced to the run's target; `references` (max 50 x 200 chars) and
  `item_key` (max 255) are bounded and redacted; `RunResult` gains `manifest_sha256` and `trust`.
- Non-Python interpreters are resolved on the plugin's PATH (`interpreter_not_found:<name>`).

### Notes
- The catalog public key ships in `keys/catalog.pub`; the three bundled plugins are signed and
  load as `official`.
