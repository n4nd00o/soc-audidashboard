# SOC AudiDashboard

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
┌──────────── Analyst machine ────────────────┐          ┌──────── Central server (docker compose) ──────────┐
│ Desktop app (PySide6)                       │  mTLS    │ Reverse proxy (TLS 1.3 + cert verification)       │
│  ├ plugin catalog / view source code        │ ───────► │ FastAPI API  /api/v1  (ingestion, catalog)       │
│  ├ targets (synced from the server)         │  HTTPS   │ FastAPI+HTMX dashboard (session + MFA) ◄── browser
│  ├ runner (isolated subprocess, timeout)    │          │ PostgreSQL (findings, assets, users, audit log)   │
│  ├ sanitizer (strips secrets/PII)           │          │ Internal CA (issues device certificates)          │
│  └ credentials → OS keyring (never uploaded)│          └───────────────────────────────────────────────────┘
└─────────────────────────────────────────────┘
        │ SSH / WinRM / cloud APIs / network
        ▼
   Targets: Linux, Windows, AWS, Azure, GCP, M365, network, web
```

## ISO 27001/27002 and LGPD alignment

The project *aligns with* ISO/IEC 27001/27002 controls and LGPD principles (minimization,
sanitization at the source, security by design). This is **not** a certification or legal
advice; it is a design reference only.

## Quickstart (CLI only for now)

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone <repository-url>
cd <repository-directory>
uv sync
uv run pytest -q

# CLI
uv run audidash plugins list
uv run audidash plugins show http-security-headers
uv run audidash run http-security-headers --target example.com --target-type web \
    --param url=https://example.com --yes
```

Credentials are **not** accepted on the command line (they would leak into shell history and argv);
credential input arrives with the desktop app (OS keyring).

## How to write a plugin

Plugins are scripts in any language with a manifest and JSON output. See the guide at
[`docs/plugins.md`](docs/plugins.md) (to be created in Plan 1, Task 7).

## Roadmap

- **Plan 1** — foundation and core (`audidash-core`: schemas, runner, sanitizer, scoring, SDK).
- **Plan 2** — server (FastAPI API, database, mTLS).
- **Plan 3** — web dashboard (FastAPI + HTMX, MFA login).
- **Plan 4** — desktop app (PySide6) and demo environment.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and
[SECURITY.md](SECURITY.md). Vulnerabilities: use GitHub private reporting, never public issues.

## License

Apache-2.0. Copyright 2026 SOC AudiDashboard contributors. See [LICENSE](LICENSE).
