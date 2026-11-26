# SOC AudiDashboard

![CI](https://github.com/n4nd00o/soc-audidashboard/actions/workflows/ci.yml/badge.svg)

> **Student project** · *Projeto estudantil* · [Versão em português](README.md)
>
> This is an open-source **student** project built for a portfolio. It is not a certified
> product and comes with no warranty of any kind.

> **ETHICAL AND AUTHORIZED USE NOTICE.** Use this tool **only** on systems you own or have
> **explicit written authorization** to audit. Running audits against targets without
> permission may be illegal. The authors are not responsible for misuse.

## What it is

IT/security teams keep dozens of audit scripts (Bash, PowerShell, Python) scattered around and
run by hand. SOC AudiDashboard gathers them as **plugins** in a single app: the analyst runs
audits from their own machine, findings are standardized, ranked by severity and sent securely
to a central server, and a **web dashboard** shows threat level, suspected compromise, trends
and recommendations.

## Architecture

```
┌──── Analyst machine ─────────┐            ┌──────────── Server (docker compose) ──────────────────────┐
│ `audidash` CLI (today)       │            │ Caddy                                                      │
│  ├ signed catalog / plugins  │  mTLS      │  ├ :9443  device API (mutual TLS required)                 │
│  ├ runner (subprocess,       │ ─────────► │  └ :8443  dashboard + /enroll (TLS, no /api)   ◄── browser │
│  │  timeout, no shell)       │  :9443     │        │ internal network + proxy secret                   │
│  ├ sanitizer (secrets/PII)   │            │ FastAPI + HTMX app (API /api/v1, dashboard, session + TOTP)│
│  └ device certificate (CA)   │            │        │                                                   │
└──────────────────────────────┘            │ PostgreSQL (assets, findings, runs, users, audit log)      │
        │ network                           │ Internal CA (EC P-256, issues device certificates)         │
        ▼                                   └────────────────────────────────────────────────────────────┘
   Audited targets (web, TLS, ports, ...)
```

What exists today (`0.2.0-alpha.1`):

- **Server** (`packages/audidash-server`): ingestion API (`/api/v1`, with deduplication and
  auto-resolution of findings) and a FastAPI + HTMX **dashboard**: overview (SVG gauge and
  trend), assets, findings with a lifecycle, runs, plugin allow-list, devices/enrolment tokens,
  users and an audit-log viewer.
- **Authentication**: Argon2id, mandatory TOTP, account lockout, rate limiting, sessions with
  CSRF and roles (RBAC); hash-chained audit log (`audit verify`).
- **Devices**: internal CA, enrolment with a single-use token + CA fingerprint check, mTLS
  terminated at Caddy (`deploy/`).
- **Client** (`packages/audidash-core`): `audidash enroll | login | assets | run --upload | demo
  | plugins list --sync-verified`.
- **Not there yet**: desktop app and remote execution (see the Roadmap).

## Trust root

A plugin's trust tier (`official`, `verified`, `community`) comes from the signed catalog (Ed25519),
never from the plugin's own manifest. The bundled plugins are signed with the project key
(`packages/audidash-core/src/audidash_core/keys/catalog.pub`) and show as `official`; anything
else is `community` and asks for confirmation. See [docs/plugins.en.md](docs/plugins.en.md#trust-tiers).

## ISO 27001/27002 and LGPD alignment

The project *aligns with* ISO/IEC 27001/27002 controls and LGPD principles (minimization,
sanitization at the source, security by design). This is **not** a certification or legal
advice; it is a design reference only.

## 5-minute demo

Requires **Docker** (Compose v2), Python 3.12+ and [uv](https://docs.astral.sh/uv/). Everything
runs on `localhost`; the lab targets are **intentionally vulnerable** and bound to `127.0.0.1`.
Details and ports in [`deploy/README.md`](deploy/README.md).

```bash
git clone https://github.com/n4nd00o/soc-audidashboard.git
cd soc-audidashboard
uv sync

# 1. secrets (URL-safe, >= 32 characters): replace every CHANGE_ME with a value from
#    python -c "import secrets;print(secrets.token_urlsafe(48))"
cp deploy/.env.example deploy/.env

# 2. start the stack (PostgreSQL + server + Caddy + 3 lab targets)
docker compose -f deploy/docker-compose.yml up -d --build

# 3. admin account (asks for a password and shows the TOTP secret)
docker compose -f deploy/docker-compose.yml exec server audidash-server create-admin --username admin

# 4. internal CA fingerprint and enrolment token (shown only once)
docker compose -f deploy/docker-compose.yml exec server audidash-server show-ca-fingerprint
docker compose -f deploy/docker-compose.yml exec server audidash-server create-enrollment-token --created-by admin

# 5. on the host: enrol this machine, log in and run the demo against the lab targets
uv run audidash enroll --server https://localhost:8443 --api https://localhost:9443 \
    --name my-laptop --token=<TOKEN> --ca-fingerprint <SHA-256>
uv run audidash login
uv run audidash demo
```

Open <https://localhost:8443> (browsers warn about Caddy's internal CA), sign in with the admin
account and TOTP code, and browse assets, findings and runs. To wipe everything:
`docker compose -f deploy/docker-compose.yml down -v`.

> Planned screenshots (not added yet): see [`docs/img/README.md`](docs/img/README.md).

## Local development

```bash
uv sync
uv run pytest -q
uv run audidash plugins list
uv run audidash plugins show http-security-headers
uv run audidash run http-security-headers --target example.com --target-type web \
    --param url=https://example.com --yes
```

Credentials are **not** accepted on the command line (they would leak into shell history and
argv). The server test suite uses SQLite by default; CI also runs it against PostgreSQL
(`AUDIDASH_TEST_DATABASE_URL`). Beware: the fixtures **drop that database's `public` schema**, so
they only accept a disposable database whose name ends with `_test` (or contains `test` on
`localhost`); any other name aborts the run.

## How to write a plugin

Plugins are scripts in any language with a manifest and JSON output. See the guide at
[`docs/plugins.en.md`](docs/plugins.en.md).

## Roadmap

- **Plan 1** (`0.1.0-alpha.1`): foundation and core (schemas, runner, sanitizer, scoring, SDK, CLI).
- **Plan 2** (`0.2.0-alpha.1`): server and dashboard (API, PostgreSQL, internal CA and mTLS, MFA,
  audit log, Docker Compose demo).
- **Plan 3**: desktop app (PySide6) reusing the CLI client.
- **Plan 4**: remote execution (SSH/WinRM) and Linux/Windows plugins.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and
[SECURITY.md](SECURITY.md). Vulnerabilities: use GitHub private reporting, never public issues.

## License

Apache-2.0. Copyright 2026 SOC AudiDashboard contributors. See [LICENSE](LICENSE).
